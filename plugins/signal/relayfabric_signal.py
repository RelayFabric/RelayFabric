"""RelayFabric Signal plugin: bridges Signal groups over Plugin Protocol v1
via a signal-cli JSON-RPC/SSE daemon.

Module top level is stdlib-only (json/logging/os/socket/sys/threading/
time/urllib.request) so the config/parser/backend helpers stay importable
without cbor2 or rns. relay_ipc is imported lazily inside the methods/
functions that need it (see Bridge and main()).
"""

import json
import logging
import os
import socket
import sys
import threading
import time
import urllib.request

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"


def load_config(raw):
    cfg = dict(raw)
    if not cfg.get("account"):
        raise ValueError("config requires 'account'")
    if not cfg.get("groups"):
        raise ValueError("config requires a non-empty 'groups' mapping")
    cfg["groups"] = dict(cfg["groups"])
    cfg.setdefault("rpc_url", "http://127.0.0.1:7583")
    cfg.setdefault("allowed_users", None)
    return cfg


def parse_signal_event(event, own_account):
    envelope = event.get("envelope") or {}
    data = envelope.get("dataMessage")
    sync = data is None
    if sync:
        data = (envelope.get("syncMessage") or {}).get("sentMessage") or {}
    text = data.get("message") or ""
    if not text:
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
    return source, group_id, text, envelope.get("timestamp")


class SentCache:
    """Loop guard for linked-device sync echoes of our own bridged posts."""

    def __init__(self, ttl_secs=86400):
        self.ttl = ttl_secs
        self._entries = {}
        self._lock = threading.Lock()

    def record(self, group_id, text, now=None):
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            self._entries[(group_id, text)] = now

    def match(self, group_id, text, now=None):
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            return self._entries.pop((group_id, text), None) is not None

    def _prune(self, now):
        # ponytail: O(n) prune per call, fine at gateway volumes
        for key in [k for k, t in self._entries.items() if now - t > self.ttl]:
            del self._entries[key]


class SignalCliBackend:
    """signal-cli JSON-RPC/SSE transport — the backend seam Bridge depends on.

    Swappable per spec Sec8 (FakeBackend stands in for tests); shapes ported
    from rns-signal-gateway's signal_rpc/sse_loop.
    """

    def __init__(self, rpc_url, account):
        self.rpc_url = rpc_url.rstrip("/")
        self.account = account

    def send_group(self, group_id, text):
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "send",
            "params": {"account": self.account, "groupId": group_id,
                       "message": text},
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
                with urllib.request.urlopen(req) as resp:
                    log.info("Connected to signal-cli event stream")
                    for raw in resp:
                        line = raw.decode("utf-8", "replace").strip()
                        if not line.startswith("data:"):
                            continue
                        try:
                            yield json.loads(line[len("data:"):])
                        except ValueError:
                            continue
            except Exception as e:  # noqa: BLE001 - daemon must survive and reconnect
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
        self.cfg = cfg
        self.backend = backend
        self.sock_file = sock_file
        self.write_lock = threading.Lock()
        self.sent_cache = SentCache()
        self.group_ids_to_names = {
            group_id: name for name, group_id in cfg["groups"].items()}

    def _send_frame(self, obj):
        import relay_ipc

        with self.write_lock:
            relay_ipc.write_frame(self.sock_file, obj)

    # ----- inbound (Signal -> daemon); called from the SSE thread -----

    def handle_event(self, event):
        parsed = parse_signal_event(event, self.cfg["account"])
        if parsed is None:
            return
        source, group_id, text, ts = parsed

        envelope = event.get("envelope") or {}
        if "syncMessage" in envelope and self.sent_cache.match(group_id, text):
            return  # loop guard: sync echo of our own bridged post

        name = self.group_ids_to_names.get(group_id)
        if name is None:  # deny by default: unmapped groups and DMs
            log.debug(f"Dropping Signal event for unmapped group {group_id!r}")
            return

        allowed = self.cfg["allowed_users"]
        if allowed and source not in allowed:
            log.warning(f"Dropping Signal message from unlisted user {source}")
            return

        import relay_ipc
        created = ts / 1000 if ts is not None else None
        self._send_frame(relay_ipc.inbound(name, source, text, created))
        log.info(f"Bridged Signal message from {source} to '{name}' "
                 f"({len(text)} chars)")

    # ----- egress (daemon -> Signal); called from the main thread -----

    def handle_send(self, frame):
        import relay_ipc

        corr = frame["corr"]
        endpoint = frame["endpoint"]
        body = frame["body"]
        group_id = self.cfg["groups"].get(endpoint)
        if group_id is None:
            log.warning(f"Signal send to unknown endpoint {endpoint!r}")
            self._send_frame(relay_ipc.delivery_result(corr, False, "unknown group"))
            return
        try:
            self.backend.send_group(group_id, body)
        except Exception as e:  # noqa: BLE001 - report the failure, don't crash
            log.warning(f"Signal send to '{endpoint}' failed: {e}")
            self._send_frame(relay_ipc.delivery_result(corr, False, str(e)))
            return
        self.sent_cache.record(group_id, body)
        self._send_frame(relay_ipc.delivery_result(corr, True))
        log.info(f"Sent Signal message to '{endpoint}' ({len(body)} chars)")


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    sock_path = os.environ["RELAYFABRIC_SOCKET"]
    plugin_name = os.environ.get("RELAYFABRIC_PLUGIN_NAME", "signal")
    raw_cfg = json.loads(os.environ.get("RELAYFABRIC_PLUGIN_CONFIG", "{}"))
    cfg = load_config(raw_cfg)

    import relay_ipc

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    rfile = sock.makefile("rb")
    wfile = sock.makefile("wb")

    caps = relay_ipc.capabilities(groups=True)
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
        except (EOFError, OSError) as e:
            log.error(f"Daemon connection lost, exiting: {e}")
            sys.exit(1)
        kind = frame.get("t")
        if kind == "send":
            bridge.handle_send(frame)
        elif kind == "shutdown":
            sys.exit(0)
