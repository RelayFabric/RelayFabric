"""RelayFabric Signal plugin: bridges Signal groups over Plugin Protocol v1
via a signal-cli JSON-RPC/SSE daemon.

Module top level is stdlib-only (json/logging/os/shutil/socket/sys/
tempfile/threading/time/urllib.request) so the config/parser/backend
helpers stay importable without cbor2 or rns. relayfabric_sdk (ipc and
SentCache) is imported lazily inside the methods/functions that need it
(see Bridge and main()). Attachment bytes are never logged, only
names/sizes/counts.
"""

import json
import logging
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.request

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"

# Sanity cap on reading an attachment file into memory; ported from
# rns-signal-gateway's Gateway.ATTACHMENT_LOAD_CAP (gateway.py:509). The
# actual pass-through decision (drop with a note vs. forward) is made
# separately by cap_attachments() against the smaller, configurable
# max_attachment_bytes.
ATTACHMENT_LOAD_CAP = 32_000_000


def load_config(raw):
    cfg = dict(raw)
    if not cfg.get("account"):
        raise ValueError("config requires 'account'")
    if not cfg.get("groups"):
        raise ValueError("config requires a non-empty 'groups' mapping")
    cfg["groups"] = dict(cfg["groups"])
    cfg.setdefault("rpc_url", "http://127.0.0.1:7583")
    cfg.setdefault("allowed_users", None)
    cfg.setdefault("attachment_dir", "~/.local/share/signal-cli/attachments")
    cfg.setdefault("max_attachment_bytes", 8_000_000)
    return cfg


def parse_signal_event(event, own_account):
    envelope = event.get("envelope") or {}
    data = envelope.get("dataMessage")
    sync = data is None
    if sync:
        data = (envelope.get("syncMessage") or {}).get("sentMessage") or {}
    text = data.get("message") or ""
    attachments_raw = data.get("attachments") or []
    if not text and not attachments_raw:
        return None
    source = (envelope.get("sourceUuid")
              or envelope.get("sourceNumber")
              or envelope.get("source"))
    if source is None:
        return None
    if not sync and (envelope.get("sourceNumber") == own_account
                     or envelope.get("source") == own_account):
        return None
    group_id = (data.get("groupInfo") or {}).get("groupId")
    return source, group_id, text, envelope.get("timestamp"), attachments_raw


def load_signal_attachments(attachment_dir, attachments):
    """Read attachment files signal-cli stored; returns (loaded, notes).

    Ported from rns-signal-gateway's Gateway.load_signal_attachments
    (gateway.py:511-529). `attachment_dir` is expanduser'd here (at use),
    not at config-load time. Each descriptor's `id` is basename-sanitized
    before joining, so an upstream-supplied id (e.g. "../../etc/passwd")
    can never escape attachment_dir.
    """
    attachment_dir = os.path.expanduser(attachment_dir)
    loaded, notes = [], []
    for att in attachments:
        aid = att.get("id")
        name = att.get("filename") or aid or "file"
        path = (os.path.join(attachment_dir, os.path.basename(aid))
                if aid else None)
        if not path or not os.path.isfile(path):
            notes.append(f"[attachment {name} unavailable]")
            continue
        if os.path.getsize(path) > ATTACHMENT_LOAD_CAP:
            notes.append(f"[dropped {name}: exceeds {ATTACHMENT_LOAD_CAP} B]")
            continue
        with open(path, "rb") as f:
            loaded.append((name, att.get("contentType") or "", f.read()))
    return loaded, notes


def cap_attachments(loaded, max_bytes):
    """Split [(name, content_type, data), ...] into (kept, notes) by size.

    Anything over max_bytes is dropped with a note instead of being
    forwarded; mirrors the drop-note format used by plugins/lxmf's
    attachment_fields/lxmf_attachments.
    """
    kept, notes = [], []
    for name, ctype, data in loaded:
        if len(data) > max_bytes:
            notes.append(f"[dropped {name}: {len(data)} B over "
                         f"{max_bytes} B limit]")
        else:
            kept.append((name, ctype, data))
    return kept, notes


def cap_frame_budget(kept, budget):
    """Drop attachments from the tail once cumulative size exceeds budget.

    Applied after cap_attachments()'s per-attachment cap: several
    individually-under-cap attachments (e.g. three 6MB photos) can still
    sum past relay_ipc.MAX_FRAME, which would make write_frame() raise and
    silently drop the entire message (text included). Notes use the same
    drop-note wording as cap_attachments, but against the frame budget
    rather than the per-attachment limit.
    """
    kept_out, notes = [], []
    total = 0
    for name, ctype, data in kept:
        total += len(data)
        if total > budget:
            notes.append(f"[dropped {name}: {len(data)} B over frame budget]")
        else:
            kept_out.append((name, ctype, data))
    return kept_out, notes


class SignalCliBackend:
    """signal-cli JSON-RPC/SSE transport — the backend seam Bridge depends on.

    Swappable per spec Sec8 (FakeBackend stands in for tests); shapes ported
    from rns-signal-gateway's signal_rpc/sse_loop.
    """

    def __init__(self, rpc_url, account):
        self.rpc_url = rpc_url.rstrip("/")
        self.account = account

    def send_group(self, group_id, text, attachment_paths=None):
        params = {"account": self.account, "groupId": group_id,
                  "message": text}
        if attachment_paths:
            params["attachments"] = attachment_paths
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "send",
            "params": params,
        }).encode()
        req = urllib.request.Request(
            self.rpc_url + "/api/v1/rpc", data=body,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                reply = json.load(resp)
        except Exception as e:
            raise RuntimeError(f"signal-cli send failed: {e}") from e
        if "error" in reply:
            raise RuntimeError(f"signal-cli error: {reply['error']}")

    def events(self):
        """Yield parsed SSE events from signal-cli forever.

        Reconnects after any error (connection refused, stream teardown,
        malformed line) with a 5s backoff; never raises. Only `data:` lines
        are parsed; a line that isn't valid JSON is skipped in place rather
        than tearing down the connection.
        """
        url = self.rpc_url + "/api/v1/events"
        while True:
            try:
                req = urllib.request.Request(
                    url, headers={"Accept": "text/event-stream"})
                # Generous timeout: a wedged-but-still-open connection would
                # otherwise deafen inbound forever while egress keeps working.
                # Reconnecting drops any event that arrives during the gap, so
                # the timeout trades a bounded blind spot for eventually
                # recovering a wedged signal-cli within 10 minutes.
                with urllib.request.urlopen(req, timeout=600) as resp:
                    log.info("Connected to signal-cli event stream")
                    for raw in resp:
                        line = raw.decode("utf-8", "replace").strip()
                        if not line.startswith("data:"):
                            continue
                        try:
                            yield json.loads(line[len("data:"):])
                        except ValueError:
                            continue
            except Exception as e:  # noqa: BLE001 - daemon must survive and reconnect;
                # this also catches socket.timeout/TimeoutError from the
                # urlopen timeout above (TimeoutError is an OSError subclass,
                # and socket.timeout is an alias for it on Python 3.10+).
                log.warning(f"Signal SSE stream error, reconnecting in 5s: {e}")
                time.sleep(5)


class Bridge:
    """Bridges parsed Signal events <-> Plugin Protocol frames.

    group_ids_to_names is the reverse of cfg["groups"], built once.
    handle_event runs on the SSE thread; handle_send runs on the main
    thread; all daemon-socket writes go through _send_frame, serialized by
    one lock (mirrors plugins/lxmf's Bridge).
    """

    def __init__(self, cfg, backend, sock_file):
        from relayfabric_sdk import SentCache

        self.cfg = cfg
        self.backend = backend
        self.sock_file = sock_file
        self.write_lock = threading.Lock()
        self.sent_cache = SentCache()
        self.group_ids_to_names = {
            group_id: name for name, group_id in cfg["groups"].items()}

    def _send_frame(self, obj):
        from relayfabric_sdk import ipc as relay_ipc

        with self.write_lock:
            relay_ipc.write_frame(self.sock_file, obj)

    # ----- inbound (Signal -> daemon); called from the SSE thread -----

    def handle_event(self, event):
        parsed = parse_signal_event(event, self.cfg["account"])
        if parsed is None:
            return
        source, group_id, text, ts, attachments_raw = parsed

        envelope = event.get("envelope") or {}
        if "syncMessage" in envelope and self.sent_cache.match(group_id, text):
            return  # loop guard: sync echo of our own bridged post

        name = self.group_ids_to_names.get(group_id)
        if name is None:  # deny by default: unmapped groups and DMs
            log.debug(f"Dropping Signal event for unmapped group {group_id!r}")
            return

        allowed = self.cfg["allowed_users"]
        if allowed is not None and source not in allowed:
            log.warning(f"Dropping Signal message from unlisted user {source}")
            return

        from relayfabric_sdk import ipc as relay_ipc

        # attachment bytes are never logged, only counts/sizes via notes
        loaded, load_notes = load_signal_attachments(
            self.cfg["attachment_dir"], attachments_raw)
        kept, cap_notes = cap_attachments(loaded, self.cfg["max_attachment_bytes"])
        budget = relay_ipc.MAX_FRAME - 64 * 1024
        kept, budget_notes = cap_frame_budget(kept, budget)
        notes = load_notes + cap_notes + budget_notes
        body = "\n".join(p for p in [text, *notes] if p)

        atts = [
            relay_ipc.attachment(
                os.path.basename(fname), ctype or "application/octet-stream", data)
            for fname, ctype, data in kept
        ]
        created = ts / 1000 if ts is not None else None
        self._send_frame(relay_ipc.inbound(
            name, source, body, created, attachments=atts))
        log.info(f"Bridged Signal message from {source} to '{name}' "
                 f"({len(text)} chars, {len(atts)} attachment(s))")

    # ----- egress (daemon -> Signal); called from the main thread -----

    def handle_send(self, frame):
        from relayfabric_sdk import ipc as relay_ipc

        corr = frame["corr"]
        endpoint = frame["endpoint"]
        body = frame["body"]
        group_id = self.cfg["groups"].get(endpoint)
        if group_id is None:
            log.warning(f"Signal send to unknown endpoint {endpoint!r}")
            self._send_frame(relay_ipc.delivery_result(corr, False, "unknown group"))
            return

        # attachment bytes are never logged, only counts/sizes via notes
        max_bytes = self.cfg["max_attachment_bytes"]
        kept, notes = [], []
        for att in frame.get("attachments") or []:
            data = att["data"]
            if len(data) > max_bytes:
                notes.append(f"[dropped {att['filename']}: {len(data)} B over "
                             f"{max_bytes} B limit]")
            else:
                kept.append(att)
        text = "\n".join(p for p in [body, *notes] if p)

        tmpdir = None
        try:
            paths = []
            if kept:
                tmpdir = tempfile.mkdtemp(prefix="relayfabric-signal-att-")
                # same-basename attachments overwrite; prefix an
                # index if that ever matters
                for att in kept:
                    path = os.path.join(tmpdir, os.path.basename(att["filename"]))
                    with open(path, "wb") as f:
                        f.write(att["data"])
                    paths.append(path)
            self.backend.send_group(group_id, text, paths)
        except Exception as e:  # noqa: BLE001 - report the failure, don't crash
            log.warning(f"Signal send to '{endpoint}' failed: {e}")
            self._send_frame(relay_ipc.delivery_result(corr, False, str(e)))
            return
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)
        self.sent_cache.record(group_id, text)
        self._send_frame(relay_ipc.delivery_result(corr, True))
        log.info(f"Sent Signal message to '{endpoint}' "
                 f"({len(text)} chars, {len(paths)} attachment(s))")


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    sock_path = os.environ["RELAYFABRIC_SOCKET"]
    plugin_name = os.environ.get("RELAYFABRIC_PLUGIN_NAME", "signal")
    raw_cfg = json.loads(os.environ.get("RELAYFABRIC_PLUGIN_CONFIG", "{}"))
    cfg = load_config(raw_cfg)

    from relayfabric_sdk import ipc as relay_ipc

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    rfile = sock.makefile("rb")
    wfile = sock.makefile("wb")

    caps = relay_ipc.capabilities(groups=True, attachments=True)
    relay_ipc.write_frame(wfile, relay_ipc.hello(plugin_name, PLUGIN_VERSION, caps))
    ack = relay_ipc.read_frame(rfile)
    if ack.get("t") != "hello_ack" or ack.get("error"):
        print(f"relayfabric-signal: hello rejected: {ack.get('error')}",
             file=sys.stderr)
        sys.exit(1)

    backend = SignalCliBackend(cfg["rpc_url"], cfg["account"])
    bridge = Bridge(cfg, backend, wfile)

    def sse_loop():
        for ev in backend.events():
            try:
                bridge.handle_event(ev)
            except Exception as e:  # noqa: BLE001 - one bad event must not kill the reader
                log.error(f"Signal event handler error: {e}")

    threading.Thread(target=sse_loop, daemon=True).start()

    while True:
        try:
            frame = relay_ipc.read_frame(rfile)
        except (EOFError, OSError, ValueError) as e:
            # ValueError: oversize/corrupt frame (relay_ipc.read_frame's own
            # MAX_FRAME check). The stream is desynced at that point, so exit
            # rather than continue -- there is no way to resume mid-frame.
            log.error(f"Daemon connection lost, exiting: {e}")
            sys.exit(1)
        kind = frame.get("t")
        if kind == "send":
            bridge.handle_send(frame)
        elif kind == "shutdown":
            sys.exit(0)
