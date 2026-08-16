"""RelayFabric LXMF plugin: bridges Reticulum/LXMF channels over Plugin Protocol v1.

Module top level is stdlib-only (json/mimetypes/os/socket/sys/threading/
time/concurrent.futures) plus media (itself stdlib-only at import time; see
media.py) so the config/channel/command/attachment helpers above stay
importable without rns, lxmf, or even cbor2 installed. relay_ipc and
RNS/LXMF are imported lazily inside the functions/methods that need
them (see Bridge and main()).
"""

import json
import mimetypes
import os
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import media


def load_config(raw):
    cfg = dict(raw)
    if not cfg.get("storage"):
        raise ValueError("config requires 'storage'")
    cfg.setdefault("display_name", "RelayFabric Gateway")
    cfg.setdefault("rns_configdir", None)
    cfg.setdefault("announce_interval", 3600)
    cfg.setdefault("stamp_cost", None)
    cfg.setdefault("propagation_node", None)
    cfg.setdefault("max_attachment_bytes", 1_000_000)
    cfg.setdefault("image_max_bytes", None)
    cfg.setdefault("voice_to_codec2", None)
    cfg.setdefault("lxmf_delivery_limit_kb", 8192)
    cfg["channels"] = [dict(ch) for ch in cfg.get("channels", [])]
    for ch in cfg["channels"]:
        if not ch.get("name"):
            raise ValueError("every channel requires a 'name'")
        ch["members"] = [m.lower() for m in ch.get("members", [])]
        ch.setdefault("open", False)
    return cfg


def channel_by_name(cfg, name):
    return next((c for c in cfg["channels"] if c["name"] == name), None)


def channel_for_member(cfg, sender_hex, dynamic):
    for ch in cfg["channels"]:
        if sender_hex in ch["members"] or sender_hex in dynamic.get(ch["name"], []):
            return ch
    return None


def channel_members(channel, dynamic):
    joined = dynamic.get(channel["name"], [])
    return channel["members"] + [m for m in joined if m not in channel["members"]]


KNOWN_COMMANDS = {"/join", "/leave", "/channels"}


def command_reply(cfg, dynamic, sender, text):
    parts = text.split()
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else None

    if cmd == "/join" and arg:
        ch = channel_by_name(cfg, arg)
        if ch is None:
            return f"No such channel: {arg}", False
        if sender in ch["members"] or sender in dynamic.get(arg, []):
            return f"Already a member of {arg}", False
        if not ch["open"]:
            return f"Channel {arg} is closed; ask the operator", False
        dynamic.setdefault(arg, []).append(sender)
        return f"Joined {arg}", True

    if cmd == "/leave" and arg:
        joined = dynamic.get(arg, [])
        if sender in joined:
            joined.remove(sender)
            return f"Left {arg}", True
        ch = channel_by_name(cfg, arg)
        if ch is not None and sender in ch["members"]:
            return (f"You are in {arg} via the gateway config; "
                    f"ask the operator to remove you"), False
        return f"Not a member of {arg}", False

    if cmd == "/channels":
        lines = []
        for ch in cfg["channels"]:
            if sender in ch["members"] or sender in dynamic.get(ch["name"], []):
                status = "member"
            else:
                status = "open" if ch["open"] else "closed"
            lines.append(f"{ch['name']} ({status})")
        return "\n".join(lines) or "No channels configured", False

    return "Commands: /join <channel>, /leave <channel>, /channels", False


def save_members_atomic(path, dynamic):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(dynamic, f, indent=2)
    os.replace(tmp, path)


# ---------- attachment helpers (ported from rns-signal-gateway's
# attachment_fields/lxmf_attachments; use media.py for the FIELD_*/AM_*
# literals and the shrink_image/audio_to_codec2/codec2_to_wav transforms
# so these stay importable without lxmf) ----------

def attachment_fields(loaded, max_bytes, voice_codec2_bitrate=None,
                       image_max_bytes=None):
    """Build LXMF fields from [(filename, content_type, bytes), ...].

    Returns (fields, notes). The first image becomes FIELD_IMAGE (rendered
    inline by Sideband), downscaled to image_max_bytes (or max_bytes) when
    it doesn't already fit. When voice_codec2_bitrate is set, the first
    audio attachment is transcoded to a codec2 FIELD_AUDIO (tiny, plays in
    Sideband's voice UI, LoRa-friendly). Everything else becomes
    FIELD_FILE_ATTACHMENTS; anything still over max_bytes is dropped with
    a note.
    """
    fields = {}
    files = []
    notes = []
    for name, ctype, data in loaded:
        ext = os.path.splitext(name)[1].lstrip(".").lower()
        if ctype.startswith("image/") and media.FIELD_IMAGE not in fields:
            budget = image_max_bytes or max_bytes
            if len(data) > budget:
                shrunk = media.shrink_image(data, budget)
                if shrunk is not None:
                    data, ext = shrunk, "webp"
            if len(data) > max_bytes:
                notes.append(f"[dropped {name}: {len(data)} B over "
                             f"{max_bytes} B limit]")
                continue
            fields[media.FIELD_IMAGE] = [ext or ctype.split("/", 1)[1], data]
            continue
        if (ctype.startswith("audio/") and voice_codec2_bitrate
                and media.FIELD_AUDIO not in fields):
            c2 = media.audio_to_codec2(data, voice_codec2_bitrate)
            if c2 is not None:
                fields[media.FIELD_AUDIO] = [
                    media.AM_FOR_BITRATE[voice_codec2_bitrate], c2]
                continue
        if len(data) > max_bytes:
            notes.append(f"[dropped {name}: {len(data)} B over "
                         f"{max_bytes} B limit]")
            continue
        files.append([os.path.basename(name), data])
    if files:
        fields[media.FIELD_FILE_ATTACHMENTS] = files
    return fields, notes


def lxmf_attachments(message_fields, max_bytes):
    """Extract [(filename, bytes), ...] plus drop notes from LXMF fields."""
    out, notes = [], []
    fields = message_fields or {}
    image = fields.get(media.FIELD_IMAGE)
    if isinstance(image, (list, tuple)) and len(image) >= 2 and image[1]:
        name, data = f"image.{image[0]}", image[1]
        if len(data) > max_bytes:
            shrunk = media.shrink_image(data, max_bytes)
            if shrunk is not None:
                name, data = "image.webp", shrunk
        out.append((name, data))
    audio = fields.get(media.FIELD_AUDIO)
    if isinstance(audio, (list, tuple)) and len(audio) >= 2 and audio[1]:
        if audio[0] >= media.AM_OPUS_OGG:
            # opus modes are ogg containers, played natively downstream
            out.append(("voice.ogg", audio[1]))
        else:
            # codec2: raw low-bitrate radio audio; transcode to WAV if
            # pycodec2 is installed, else forward raw
            decoded = media.codec2_to_wav(audio[0], audio[1])
            if decoded is not None:
                out.append(("voice.wav", decoded))
            else:
                out.append(("voice.c2", audio[1]))
    for att in fields.get(media.FIELD_FILE_ATTACHMENTS) or []:
        if isinstance(att, (list, tuple)) and len(att) >= 2 and att[1]:
            out.append((str(att[0]) or "file", att[1]))
    kept = []
    for name, data in out:
        if len(data) > max_bytes:
            notes.append(f"[dropped {os.path.basename(name)}: "
                         f"{len(data)} B over {max_bytes} B limit]")
        else:
            kept.append((os.path.basename(name), data))
    return kept, notes


def _harden_storage(storage, identity_path):
    """Tighten perms on the storage dir and identity (private key) file.

    `os.makedirs(..., mode=0o700)` only applies the mode on creation, and
    RNS.Identity.to_file writes the raw private key with umask perms, so
    both need an explicit chmod regardless of whether they pre-existed.
    """
    os.chmod(storage, 0o700)
    if os.path.isfile(identity_path):
        os.chmod(identity_path, 0o600)


PLUGIN_VERSION = "0.1.0"


class FanoutTracker:
    """Tracks per-`corr` fan-out delivery outcomes across channel members.

    Thread-safe (internal lock). `member_done()` returns the
    `delivery_result` dict exactly once, when the last member reaches a
    terminal state; every other call returns None.

    # ponytail: at-least-one delivery semantics — the whole send counts as
    # delivered as soon as *any* member received it (or a propagation node
    # took custody). Per-member delivery rows are the upgrade path if
    # finer-grained observability is ever needed.
    """

    def __init__(self, corr, members):
        self.corr = corr
        self.total = len(members)
        self._lock = threading.Lock()
        self._done = 0
        self._delivered = 0
        self._failed = []
        self._reported = False

    def member_done(self, member, success):
        import relay_ipc

        with self._lock:
            self._done += 1
            if success:
                self._delivered += 1
            else:
                self._failed.append(member)
            if self._done < self.total or self._reported:
                return None
            self._reported = True
            detail = "failed: " + ",".join(self._failed) if self._failed else None
            return relay_ipc.delivery_result(self.corr, self._delivered > 0, detail)


class _PropagationNodePicker:
    """Announce handler that selects the closest active propagation node.

    RNS.Transport calls `received_announce` on a background thread whenever
    a matching announce (aspect_filter) is seen; `on_pick` is invoked with
    the destination hash of the nearest node seen so far that announces
    itself as active.
    """

    aspect_filter = "lxmf.propagation"

    def __init__(self, on_pick):
        self.on_pick = on_pick
        self.best = None

    def received_announce(self, destination_hash, announced_identity, app_data):
        import RNS
        import RNS.vendor.umsgpack as msgpack

        try:
            if not msgpack.unpackb(app_data)[0]:
                return  # node announces itself as inactive
        except Exception:  # noqa: BLE001 - unparseable announce data
            return
        if (self.best is None
                or RNS.Transport.hops_to(destination_hash) < RNS.Transport.hops_to(self.best)):
            self.best = destination_hash
            self.on_pick(destination_hash)


class Bridge:
    """Owns the RNS/LXMF stack and bridges it to the daemon over relay_ipc.

    All rns/lxmf imports are local to __init__/methods so this class (and
    the module it lives in) stays importable without those packages.
    """

    def __init__(self, cfg, wfile):
        import LXMF
        import RNS

        self.cfg = cfg
        self.wfile = wfile
        self.write_lock = threading.Lock()

        storage = cfg["storage"]
        identity_path = os.path.join(storage, "identity")
        os.makedirs(storage, mode=0o700, exist_ok=True)
        _harden_storage(storage, identity_path)  # tighten pre-existing dir/legacy key
        self.reticulum = RNS.Reticulum(cfg["rns_configdir"])

        if os.path.isfile(identity_path):
            self.identity = RNS.Identity.from_file(identity_path)
        else:
            self.identity = RNS.Identity()
            self.identity.to_file(identity_path)
        _harden_storage(storage, identity_path)  # to_file writes with umask perms

        self.router = LXMF.LXMRouter(
            storagepath=os.path.join(storage, "lxmf"),
            delivery_limit=cfg["lxmf_delivery_limit_kb"])
        self.stamp_cost = cfg["stamp_cost"]
        self.dest = self.router.register_delivery_identity(
            self.identity,
            display_name=cfg["display_name"],
            stamp_cost=self.stamp_cost,
        )

        self.members_lock = threading.Lock()
        self.members_path = os.path.join(storage, "members.json")
        self.dynamic_members = {}
        if os.path.isfile(self.members_path):
            with open(self.members_path) as f:
                self.dynamic_members = json.load(f)

        self.has_propagation_node = False
        self.propagation_state_path = os.path.join(storage, "propagation_node")
        prop_cfg = cfg["propagation_node"]
        if prop_cfg == "auto":
            if os.path.isfile(self.propagation_state_path):
                with open(self.propagation_state_path) as f:
                    remembered = f.read().strip()
                if remembered:
                    self.router.set_outbound_propagation_node(bytes.fromhex(remembered))
                    self.has_propagation_node = True
            RNS.Transport.register_announce_handler(
                _PropagationNodePicker(self._use_propagation_node))
        elif prop_cfg:
            self.router.set_outbound_propagation_node(bytes.fromhex(prop_cfg))
            self.has_propagation_node = True

        self.pool = ThreadPoolExecutor(max_workers=8)
        self.router.register_delivery_callback(self._on_lxmf)

        RNS.log(f"Gateway LXMF address: {RNS.prettyhexrep(self.dest.hash)}",
                RNS.LOG_NOTICE)

    def _use_propagation_node(self, dest_hash):
        import RNS

        self.router.set_outbound_propagation_node(dest_hash)
        self.has_propagation_node = True
        with open(self.propagation_state_path, "w") as f:
            f.write(dest_hash.hex())
        RNS.log(f"Using propagation node {RNS.prettyhexrep(dest_hash)}",
                RNS.LOG_NOTICE)

    def _send_frame(self, obj):
        import relay_ipc

        with self.write_lock:
            relay_ipc.write_frame(self.wfile, obj)

    # ----- inbound (LXMF -> daemon) -----

    def _on_lxmf(self, message):
        import RNS

        try:
            self._handle_lxmf(message)
        except Exception as e:  # noqa: BLE001 - one bad message must not kill the plugin
            RNS.log(f"LXMF handler error: {e}", RNS.LOG_ERROR)

    def _handle_lxmf(self, message):
        import RNS

        sender = message.source_hash.hex()
        # message bodies are never logged, only lengths/prefixes
        text = message.content.decode("utf-8", "replace").strip()

        if not message.signature_validated:
            RNS.log(f"Dropping LXMF message from {sender} without a validated "
                     f"signature (no announce seen yet?); requesting path",
                     RNS.LOG_WARNING)
            # the path response carries the sender's announce, so the next
            # delivery attempt from them will validate
            RNS.Transport.request_path(message.source_hash)
            return

        if text.startswith("/"):
            with self.members_lock:
                reply, changed = command_reply(self.cfg, self.dynamic_members, sender, text)
                if changed:
                    save_members_atomic(self.members_path, self.dynamic_members)
            # only log the verb for known commands; anything else may be
            # arbitrary user text (e.g. "/etc/hosts is broken") and must
            # not be logged
            verb = text.split()[0].lower() if text.split() else ""
            logged = verb if verb in KNOWN_COMMANDS else "unknown command"
            RNS.log(f"Command from {sender}: {logged}", RNS.LOG_INFO)
            self.pool.submit(self.send_lxmf, sender, reply)
            return

        channel = channel_for_member(self.cfg, sender, self.dynamic_members)
        if channel is None:  # deny by default
            RNS.log(f"Dropping LXMF message from non-member {sender}",
                     RNS.LOG_VERBOSE)
            return

        # attachment bytes are never logged, only counts/sizes via notes
        kept, notes = lxmf_attachments(message.fields, self.cfg["max_attachment_bytes"])
        if not text and not kept and not notes:
            return  # truly empty message (no text, no attachments, nothing dropped)
        body = "\n".join(p for p in [text, *notes] if p)

        import relay_ipc
        attachments = [
            relay_ipc.attachment(
                name, mimetypes.guess_type(name)[0] or "application/octet-stream", data)
            for name, data in kept
        ]
        self._send_frame(relay_ipc.inbound(
            channel["name"], sender, body, message.timestamp, attachments=attachments))

    # ----- egress (daemon -> LXMF) -----

    def handle_send(self, corr, endpoint, body, attachments=None):
        import relay_ipc

        channel = channel_by_name(self.cfg, endpoint)
        if channel is None:
            self._send_frame(relay_ipc.delivery_result(corr, False, "unknown channel"))
            return
        members = channel_members(channel, self.dynamic_members)
        if not members:
            self._send_frame(relay_ipc.delivery_result(corr, False, "no members"))
            return

        # attachment bytes are never logged, only counts/sizes via notes
        loaded = [(a["filename"], a["mime"], a["data"]) for a in (attachments or [])]
        fields, notes = attachment_fields(
            loaded, self.cfg["max_attachment_bytes"],
            self.cfg["voice_to_codec2"], self.cfg["image_max_bytes"])
        text = "\n".join(p for p in [body, *notes] if p)

        tracker = FanoutTracker(corr, members)
        for member in members:
            self.pool.submit(
                self.send_lxmf, member, text,
                lambda success, m=member: self._fanout_done(tracker, m, success),
                fields=fields or None)

    def _fanout_done(self, tracker, member, success):
        result = tracker.member_done(member[:8], success)
        if result is not None:
            self._send_frame(result)

    def send_lxmf(self, dest_hex, text, on_result=None, method=None, fields=None):
        import LXMF
        import RNS

        try:
            method = method or LXMF.LXMessage.DIRECT
            dest_hash = bytes.fromhex(dest_hex)
            # PROPAGATED sends go to the propagation node, whose path is
            # already known (this is a resubmit after a failed DIRECT
            # attempt); only Identity.recall below is needed, so skip the
            # path wait entirely for this method.
            if method != LXMF.LXMessage.PROPAGATED and not RNS.Transport.has_path(dest_hash):
                RNS.Transport.request_path(dest_hash)
                # 15s, not 30s: keeps a single stalled fan-out member's
                # DIRECT attempt inside the daemon's 60s reclaim window for
                # the overall send.
                deadline = time.time() + 15
                while (not RNS.Transport.has_path(dest_hash)
                       and time.time() < deadline):
                    time.sleep(0.25)
            identity = RNS.Identity.recall(dest_hash)
            if identity is None:
                RNS.log(f"No identity known for {dest_hex}, dropping",
                         RNS.LOG_WARNING)
                if on_result:
                    on_result(False)
                return
            destination = RNS.Destination(
                identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                "lxmf", "delivery")
            lxm = LXMF.LXMessage(
                destination, self.dest, text,
                fields=fields,
                desired_method=method,
                include_ticket=self.stamp_cost is not None)
            lxm.register_delivery_callback(
                lambda m, d=dest_hex, r=on_result: self._on_delivered(d, r))
            lxm.register_failed_callback(
                lambda m, d=dest_hex, t=text, meth=method, r=on_result, f=fields:
                    self._on_failed(d, t, meth, r, f))
            self.router.handle_outbound(lxm)
        except Exception as e:  # noqa: BLE001 - daemon must survive bad sends
            RNS.log(f"LXMF send to {dest_hex} failed: {e}", RNS.LOG_ERROR)
            if on_result:
                on_result(False)

    def _on_delivered(self, dest_hex, on_result):
        import RNS

        RNS.log(f"LXMF delivered to {dest_hex}", RNS.LOG_INFO)
        if on_result:
            on_result(True)

    def _on_failed(self, dest_hex, text, method, on_result, fields=None):
        import LXMF
        import RNS

        if method == LXMF.LXMessage.DIRECT and self.has_propagation_node:
            RNS.log(f"Direct delivery to {dest_hex} failed, handing to "
                     f"propagation node", RNS.LOG_INFO)
            # ponytail: a resubmitted PROPAGATED message's own delivery
            # callback fires once the propagation node accepts custody, not
            # once the recipient fetches it. We treat that handoff as
            # delivered=True for this member since store-and-forward
            # custody is the strongest guarantee available here.
            self.pool.submit(self.send_lxmf, dest_hex, text, on_result,
                              LXMF.LXMessage.PROPAGATED, fields)
        else:
            RNS.log(f"LXMF delivery FAILED to {dest_hex}", RNS.LOG_WARNING)
            if on_result:
                on_result(False)

    # ----- announce loop -----

    def announce_loop(self):
        import RNS

        interval = self.cfg["announce_interval"]
        while True:
            try:
                self.router.announce(self.dest.hash)
                if self.has_propagation_node:
                    self.router.request_messages_from_propagation_node(self.identity)
            except Exception as e:  # noqa: BLE001 - a bad round must not kill the loop
                RNS.log(f"Announce loop error: {e}", RNS.LOG_ERROR)
            time.sleep(interval)


def main():
    sock_path = os.environ["RELAYFABRIC_SOCKET"]
    plugin_name = os.environ.get("RELAYFABRIC_PLUGIN_NAME", "lxmf")
    raw_cfg = json.loads(os.environ.get("RELAYFABRIC_PLUGIN_CONFIG", "{}"))
    cfg = load_config(raw_cfg)

    import relay_ipc

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    rfile = sock.makefile("rb")
    wfile = sock.makefile("wb")

    caps = relay_ipc.capabilities(direct_messages=True, groups=True, attachments=True)
    relay_ipc.write_frame(wfile, relay_ipc.hello(plugin_name, PLUGIN_VERSION, caps))
    ack = relay_ipc.read_frame(rfile)
    if ack.get("t") != "hello_ack" or ack.get("error"):
        print(f"relayfabric-lxmf: hello rejected: {ack.get('error')}", file=sys.stderr)
        sys.exit(1)

    bridge = Bridge(cfg, wfile)
    threading.Thread(target=bridge.announce_loop, daemon=True).start()

    import RNS

    while True:
        try:
            frame = relay_ipc.read_frame(rfile)
        except (EOFError, OSError) as e:
            RNS.log(f"Daemon connection lost, exiting: {e}", RNS.LOG_ERROR)
            sys.exit(1)
        kind = frame.get("t")
        if kind == "send":
            bridge.handle_send(frame["corr"], frame["endpoint"], frame["body"],
                               frame.get("attachments"))
        elif kind == "shutdown":
            sys.exit(0)
