"""RelayFabric LXMF plugin: bridges Reticulum/LXMF channels over Plugin Protocol v1.

Module top level is stdlib-only (json/os/socket/sys/threading/time/
concurrent.futures) so the config/channel/command helpers above stay
importable without rns, lxmf, or even cbor2 installed. relay_ipc and
RNS/LXMF are imported lazily inside the functions/methods that need
them (see Bridge and main()).
"""

import json
import os
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor


def load_config(raw):
    cfg = dict(raw)
    if not cfg.get("storage"):
        raise ValueError("config requires 'storage'")
    cfg.setdefault("display_name", "RelayFabric Gateway")
    cfg.setdefault("rns_configdir", None)
    cfg.setdefault("announce_interval", 3600)
    cfg.setdefault("stamp_cost", None)
    cfg.setdefault("propagation_node", None)
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

    def member_done(self, member, success):
        import relay_ipc

        with self._lock:
            self._done += 1
            if success:
                self._delivered += 1
            else:
                self._failed.append(member)
            if self._done < self.total:
                return None
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
        os.makedirs(storage, mode=0o700, exist_ok=True)
        self.reticulum = RNS.Reticulum(cfg["rns_configdir"])

        identity_path = os.path.join(storage, "identity")
        if os.path.isfile(identity_path):
            self.identity = RNS.Identity.from_file(identity_path)
        else:
            self.identity = RNS.Identity()
            self.identity.to_file(identity_path)

        self.router = LXMF.LXMRouter(storagepath=os.path.join(storage, "lxmf"))
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
            RNS.log(f"Command from {sender}: {text.split()[0]}", RNS.LOG_INFO)
            self.pool.submit(self.send_lxmf, sender, reply)
            return

        channel = channel_for_member(self.cfg, sender, self.dynamic_members)
        if channel is None:  # deny by default
            RNS.log(f"Dropping LXMF message from non-member {sender}",
                     RNS.LOG_VERBOSE)
            return

        import relay_ipc
        self._send_frame(relay_ipc.inbound(channel["name"], sender, text, message.timestamp))

    # ----- egress (daemon -> LXMF) -----

    def handle_send(self, corr, endpoint, body):
        import relay_ipc

        channel = channel_by_name(self.cfg, endpoint)
        if channel is None:
            self._send_frame(relay_ipc.delivery_result(corr, False, "unknown channel"))
            return
        members = channel_members(channel, self.dynamic_members)
        if not members:
            self._send_frame(relay_ipc.delivery_result(corr, False, "no members"))
            return
        tracker = FanoutTracker(corr, members)
        for member in members:
            self.pool.submit(
                self.send_lxmf, member, body,
                lambda success, m=member: self._fanout_done(tracker, m, success))

    def _fanout_done(self, tracker, member, success):
        result = tracker.member_done(member[:8], success)
        if result is not None:
            self._send_frame(result)

    def send_lxmf(self, dest_hex, text, on_result=None, method=None):
        import LXMF
        import RNS

        try:
            method = method or LXMF.LXMessage.DIRECT
            dest_hash = bytes.fromhex(dest_hex)
            if not RNS.Transport.has_path(dest_hash):
                RNS.Transport.request_path(dest_hash)
                deadline = time.time() + 30
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
                desired_method=method,
                include_ticket=self.stamp_cost is not None)
            lxm.register_delivery_callback(
                lambda m, d=dest_hex, r=on_result: self._on_delivered(d, r))
            lxm.register_failed_callback(
                lambda m, d=dest_hex, t=text, meth=method, r=on_result:
                    self._on_failed(d, t, meth, r))
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

    def _on_failed(self, dest_hex, text, method, on_result):
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
                              LXMF.LXMessage.PROPAGATED)
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

    caps = relay_ipc.capabilities(direct_messages=True, groups=True)
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
            bridge.handle_send(frame["corr"], frame["endpoint"], frame["body"])
        elif kind == "shutdown":
            sys.exit(0)
