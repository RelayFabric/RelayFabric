"""RelayFabric MeshCore plugin: bridges MeshCore text events over Plugin Protocol v1.

Module top level is stdlib-only (asyncio/json/logging/os/queue/socket/sys/
threading/urllib.parse) so config/parser/event helpers stay importable
without the meshcore or cbor2 packages. meshcore and relayfabric_sdk (ipc
and SentCache) are imported lazily inside the methods that need them (see
MeshCoreBackend.start() and main()). Text bytes are never logged, only
names/types.
"""

import asyncio
import json
import logging
import os
import queue
import socket
import sys
import threading
import time
import urllib.parse

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"

# design §3 (cycle D): plugin-side rate limit on Gauges frame emission -- at
# most one per this many seconds, regardless of how many events arrive.
GAUGES_INTERVAL_SECS = 30

# Hard ceiling on advertised Hello capabilities.max_payload, independent of
# cfg["max_text_bytes"]: a practical cap for MeshCore text payloads regardless
# of how an operator configures max_text_bytes.
MESHCORE_MAX_PAYLOAD = 160


def load_config(raw):
    """Load and validate MeshCore plugin configuration.

    Required fields: connection (string), channels (non-empty dict).
    Each channel value must be a dict with required int 'index'.

    Defaults: max_text_bytes 160.

    Returns a copy of the config dict with channels deep-copied.
    Raises ValueError if validation fails.
    Raises TypeError if type checks fail.
    """
    cfg = dict(raw)

    if not cfg.get("connection"):
        raise ValueError("config requires 'connection'")
    if not isinstance(cfg.get("connection"), str):
        raise TypeError("connection must be str")
    if not cfg.get("channels"):
        raise ValueError("config requires a non-empty 'channels' mapping")
    if not isinstance(cfg.get("channels"), dict):
        raise TypeError("channels must be a dict")

    # Validate and copy channels
    channels_copy = {}
    for name, channel_spec in cfg["channels"].items():
        if not isinstance(channel_spec, dict):
            raise TypeError(f"channel '{name}' must be a dict")
        if "index" not in channel_spec:
            raise ValueError(f"channel '{name}' requires 'index'")
        idx = channel_spec["index"]
        if not isinstance(idx, int):
            raise TypeError(
                f"channel '{name}' index must be int, got {type(idx).__name__}"
            )

        # Deep copy each channel spec
        channels_copy[name] = dict(channel_spec)

    cfg["channels"] = channels_copy
    cfg.setdefault("max_text_bytes", 160)
    if not isinstance(cfg["max_text_bytes"], int):
        raise TypeError(
            f"max_text_bytes must be int, got {type(cfg['max_text_bytes']).__name__}"
        )

    return cfg


def parse_connection(url):
    """Parse a MeshCore connection URL into (kind, target, dict).

    Supported schemes:
    - serial://<path>[?baud=N] → ("serial", path, {"baud": N or 115200})
    - tcp://host:port → ("tcp", (host, port), {})
    - ble://<addr> → ("ble", addr, {})

    Raises ValueError for unsupported schemes or malformed URLs.
    """
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme

    if scheme == "serial":
        path = parsed.netloc + parsed.path
        if not path:
            raise ValueError("serial:// requires a path")
        query_params = urllib.parse.parse_qs(parsed.query)
        baud = 115200
        if "baud" in query_params:
            try:
                baud = int(query_params["baud"][0])
            except (ValueError, IndexError):
                raise ValueError("serial:// baud must be an integer")
        return "serial", path, {"baud": baud}

    elif scheme == "tcp":
        if not parsed.hostname or parsed.port is None:
            raise ValueError("tcp:// requires host:port")
        return "tcp", (parsed.hostname, parsed.port), {}

    elif scheme == "ble":
        addr = parsed.netloc + parsed.path
        if not addr:
            raise ValueError("ble:// requires an address")
        return "ble", addr, {}

    else:
        raise ValueError(
            f"unsupported connection scheme: {scheme!r}; "
            "supported: serial://, tcp://, ble://"
        )


def channels_by_index(cfg):
    """Build reverse mapping from channel index to channel name.

    Returns dict[int, str] mapping channel index to name.
    """
    return {
        channel_spec["index"]: name
        for name, channel_spec in cfg["channels"].items()
    }


def normalize_event(ev, by_index):
    """Parse a MeshCore event dict into (name, sender, text, ts) or None.

    Args:
        ev: dict with keys kind, channel_idx, sender, text, ts (optional).
        by_index: dict[int, str] mapping channel index to channel name.

    Returns:
        (name, sender, text, ts) tuple if valid channel_msg event, else None.

    Filters:
    - kind != "channel_msg" → None
    - missing or empty text → None
    - unmapped channel_idx → None
    - missing sender → None

    Timestamp: ev.get("ts") (may be None).
    """
    # Type filter
    if ev.get("kind") != "channel_msg":
        return None

    # Text validation
    text = ev.get("text")
    if not text or not isinstance(text, str):
        return None

    # Sender validation (required, presented as given)
    sender = ev.get("sender")
    if sender is None:
        return None

    # Channel mapping
    channel_idx = ev.get("channel_idx")
    if channel_idx is None:
        return None
    if channel_idx not in by_index:
        return None
    name = by_index[channel_idx]

    ts = ev.get("ts")

    return name, sender, text, ts


def channel_event_to_dict(payload):
    """Normalize a meshcore CHANNEL_MSG_RECV Event.payload into the Task-1
    event dict shape {kind, channel_idx, sender, text, ts}.

    payload keys, per the installed meshcore 2.3.8 library's
    meshcore/reader.py (PacketType.CHANNEL_MSG_RECV / _V3 branches):
    channel_idx (int), sender_timestamp (int, seconds, sender-controlled),
    text (str). Unlike CONTACT_MSG_RECV, a MeshCore channel packet carries
    NO pubkey_prefix / per-node sender identity at the protocol level --
    channels are pre-shared-key group broadcasts, confirmed by reading the
    reader.py packet parser.

    `sender` is therefore the CHANNEL, not a per-node identity: a stable
    "mc:channel:<idx>" keyed on channel_idx (not name -- stable across
    config renames), so every message on a given channel maps to the same
    sender. This means the daemon's per-sender rate limits and alias
    stability operate at CHANNEL granularity for this plugin -- the same
    trade-off the mqtt plugin already makes with its topic-as-sender
    (there, too, the transport has no per-node identity to key on). A
    per-message value (e.g. hashing sender_timestamp) would look like a
    per-node id but isn't one, and would silently defeat per-sender rate
    limiting (fresh key every message => limits never trigger) and alias
    stability (a new alias every message). `sender_timestamp` is a
    timestamp, not an identity, so it flows into `ts` only, never `sender`.
    """
    return {
        "kind": "channel_msg",
        "channel_idx": payload.get("channel_idx"),
        "sender": f"mc:channel:{payload.get('channel_idx')}",
        "text": payload.get("text"),
        "ts": payload.get("sender_timestamp"),
    }


class MeshCoreBackend:
    """meshcore-library transport (native Companion Radio Protocol) -- the
    backend seam Bridge depends on (swappable for FakeBackend in tests, per
    the fleet's MqttJsonBackend/SignalCliBackend precedent).

    The meshcore library (2.3.8, MIT) is asyncio-native throughout:
    MeshCore.create_serial/create_tcp/create_ble are async classmethods,
    CommandHandler.send_chan_msg() is an async coroutine, and inbound events
    are delivered through an EventDispatcher whose internal asyncio.Queue is
    bound to a running loop (dispatcher.start() creates it lazily inside the
    loop). None of that composes with the synchronous Bridge/main() thread,
    so this backend owns a private event loop on a dedicated daemon thread
    (asyncio.new_event_loop() + run_forever()) and crosses threads two ways:
      - inbound: the meshcore.subscribe() callback (invoked on the loop
        thread) normalizes the event via channel_event_to_dict() and
        queue.Queue.put_nowait()s it, dropping (with a debug log) on Full
        rather than blocking the loop thread; events() (called from the
        bridge's reader thread) blocks on queue.get().
      - outbound: send_channel() (called from main()'s read loop, i.e. the
        main thread) uses asyncio.run_coroutine_threadsafe(coro, loop)
        .result(timeout=30) to run the library's send coroutine on the loop
        thread and get the result back synchronously, raising RuntimeError
        on timeout or failure.
    """

    def __init__(self, connection_url):
        # parse_connection is a pure stdlib-only helper: validating the URL
        # here (like meshtastic's MqttJsonBackend.__init__ -> parse_broker_url)
        # surfaces a malformed connection string immediately at construction,
        # not deferred into the background asyncio thread.
        self.connection_url = connection_url
        self._kind, self._target, self._opts = parse_connection(connection_url)
        self._queue = queue.Queue(maxsize=256)
        self._loop = None
        self._mc = None

    def start(self):
        import meshcore  # lazy: keeps module import stdlib-only (see module docstring)

        self._loop = asyncio.new_event_loop()
        ready = threading.Event()
        self._start_error = None

        def _run():
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(self._connect(meshcore))
            except Exception as e:  # noqa: BLE001 - surfaced to start() via _start_error
                self._start_error = e
            finally:
                ready.set()
            if self._start_error is None:
                self._loop.run_forever()

        threading.Thread(target=_run, daemon=True).start()
        if not ready.wait(timeout=30):
            # BLE scans (create_ble with no address) can legitimately take a
            # while; a silent timeout here would leave self._mc None forever
            # -- a distinct "dead plugin" failure mode from a raised connect
            # error (same end state, but previously invisible), so surface
            # it the same way instead of returning as if start() succeeded.
            raise RuntimeError("meshcore connect timed out after 30s")
        if self._start_error is not None:
            raise RuntimeError(f"meshcore connect failed: {self._start_error}") from self._start_error

    async def _connect(self, meshcore_mod):
        if self._kind == "serial":
            mc = await meshcore_mod.MeshCore.create_serial(
                self._target, baudrate=self._opts["baud"])
        elif self._kind == "tcp":
            host, port = self._target
            mc = await meshcore_mod.MeshCore.create_tcp(host, port)
        elif self._kind == "ble":
            mc = await meshcore_mod.MeshCore.create_ble(address=self._target)
        else:
            raise ValueError(f"unsupported connection kind: {self._kind!r}")
        if mc is None:
            raise RuntimeError("meshcore: no response from node")
        mc.subscribe(meshcore_mod.EventType.CHANNEL_MSG_RECV, self._on_channel_msg)
        # auto_reconnect defaults False (and we never opt in), so a dropped
        # radio connection is permanent -- without this subscription the
        # plugin would sit silently doing nothing forever, with the daemon
        # never finding out. See _on_disconnected for why the reaction is
        # os._exit(1) rather than a normal exit.
        mc.subscribe(meshcore_mod.EventType.DISCONNECTED, self._on_disconnected)
        # The Companion Radio Protocol is PULL-based: the radio only ever
        # pushes MESSAGES_WAITING notifications on its own; CHANNEL_MSG_RECV
        # (and CONTACT_MSG_RECV) frames are replies to CMD_SYNC_NEXT_MESSAGE,
        # which MeshCore.connect() does NOT issue. start_auto_message_fetching()
        # (meshcore/meshcore.py) is what subscribes MESSAGES_WAITING and drives
        # the get_msg() drain loop that actually produces CHANNEL_MSG_RECV
        # events -- without calling it, the subscription above never fires
        # against real hardware (it only ever fired in this module's own
        # fakes/stubs, which invoke the callback directly).
        await mc.start_auto_message_fetching()
        self._mc = mc

    def _on_channel_msg(self, event):
        ev = channel_event_to_dict(event.payload)
        try:
            self._queue.put_nowait(ev)
        except queue.Full:
            log.debug("Dropping meshcore channel event: event queue full")

    def _on_disconnected(self, event):
        # This callback runs on the backend's private asyncio loop thread,
        # not the main thread -- main() is blocked in relay_ipc.read_frame()
        # on the daemon socket, so a plain sys.exit()/raise here would only
        # kill the loop thread and leave the process running with a
        # permanently dead radio link (auto_reconnect is off, see above).
        # os._exit(1) terminates the whole process immediately from any
        # thread, which the daemon's plugin supervisor is expected to detect
        # and restart, matching the rest of the fleet's supervisor-restart
        # lifecycle for unrecoverable backend failures.
        payload = getattr(event, "payload", None) or {}
        reason = payload.get("reason")
        log.error(f"meshcore: radio disconnected ({reason}), exiting for supervisor restart")
        os._exit(1)

    def events(self):
        """Yield normalized event dicts from the queue forever."""
        while True:
            yield self._queue.get()

    def queue_depth(self):
        """Current backlog of not-yet-bridged inbound events -- the gauges
        fallback (design §3) for a channel packet that carries no RSSI/SNR
        (MeshCore CHANNEL_MSG_RECV never does; see channel_event_to_dict)."""
        return self._queue.qsize()

    def send_channel(self, idx, text):
        if self._loop is None or self._mc is None:
            raise RuntimeError("meshcore backend not started")
        fut = asyncio.run_coroutine_threadsafe(
            self._mc.commands.send_chan_msg(idx, text), self._loop)
        try:
            result = fut.result(timeout=30)
        except Exception as e:
            # normalize timeout/failure to RuntimeError per the backend contract
            raise RuntimeError(f"meshcore channel send failed: {e}") from e
        if result is None or result.is_error():
            detail = getattr(result, "payload", None)
            raise RuntimeError(f"meshcore channel send failed: {detail}")


class Bridge:
    """Bridges parsed MeshCore channel events <-> Plugin Protocol frames.

    Mirrors plugins/meshtastic's Bridge exactly (write lock, _send_frame,
    SentCache loop guard, deny-by-default, oversize defensive drop).
    handle_event runs on the backend's reader thread; handle_send runs on
    the main thread; all daemon-socket writes go through _send_frame,
    serialized by one lock.
    """

    def __init__(self, cfg, backend, sock_file):
        from relayfabric_sdk import SentCache

        self.cfg = cfg
        self.backend = backend
        self.sock_file = sock_file
        self.write_lock = threading.Lock()
        # 1h, not SentCache's 86400s default: mirrors meshtastic's radio-echo
        # loop guard window -- bounds how long a lost echo can leave a stale
        # entry able to swallow one genuine identical-text message (see
        # README's one-swallow caveat).
        self.sent_cache = SentCache(ttl_secs=3600)
        self.by_index = channels_by_index(cfg)
        # baseline to "now", not 0/never: a fresh Bridge must not emit a
        # gauges frame on its very first handled event (see
        # _maybe_emit_gauges), only after GAUGES_INTERVAL_SECS has elapsed.
        self._last_gauges_at = time.monotonic()

    def _send_frame(self, obj):
        from relayfabric_sdk import ipc as relay_ipc

        with self.write_lock:
            relay_ipc.write_frame(self.sock_file, obj)

    def _maybe_emit_gauges(self):
        """Best-effort gauge snapshot (design §3), rate-limited to at most
        once every GAUGES_INTERVAL_SECS. MeshCore CHANNEL_MSG_RECV events
        carry no RSSI/SNR at the protocol level (see channel_event_to_dict's
        docstring) -- the only data "already flowing" here is the backend's
        inbound queue depth.
        """
        now = time.monotonic()
        if now - self._last_gauges_at < GAUGES_INTERVAL_SECS:
            return
        self._last_gauges_at = now
        from relayfabric_sdk import ipc as relay_ipc

        self._send_frame(relay_ipc.gauges({"queue_depth": self.backend.queue_depth()}))

    # ----- inbound (MeshCore -> daemon); called from the backend's reader thread -----

    def handle_event(self, ev):
        self._maybe_emit_gauges()
        parsed = normalize_event(ev, self.by_index)
        if parsed is None:
            return
        name, sender, text, ts = parsed

        if self.sent_cache.match(name, text):
            return  # loop guard: radio/firmware echoed our own downlink

        from relayfabric_sdk import ipc as relay_ipc

        # ts (from sender_timestamp) is remote-sender-controlled, same trust
        # posture as meshtastic's uplink timestamp; the daemon is responsible
        # for guarding against bogus/out-of-range values.
        self._send_frame(relay_ipc.inbound(name, sender, text, ts))
        log.info(f"Bridged MeshCore message from {sender} to '{name}' "
                 f"({len(text)} chars)")

    # ----- egress (daemon -> MeshCore); called from the main thread -----

    def handle_send(self, frame):
        from relayfabric_sdk import ipc as relay_ipc

        corr = frame["corr"]
        endpoint = frame["endpoint"]
        body = frame["body"]
        channel_spec = self.cfg["channels"].get(endpoint)
        if channel_spec is None:
            log.warning(f"MeshCore send to unknown endpoint {endpoint!r}")
            self._send_frame(relay_ipc.delivery_result(corr, False, "unknown endpoint"))
            return

        body_bytes = len(body.encode("utf-8"))
        max_bytes = self.cfg["max_text_bytes"]
        if body_bytes > max_bytes:
            # defensive: the daemon should have already truncated to our
            # advertised capabilities.max_payload before it ever sends us
            # this frame.
            detail = f"body {body_bytes} B exceeds max_text_bytes {max_bytes} B"
            log.warning(f"MeshCore send to '{endpoint}' dropped: {detail}")
            self._send_frame(relay_ipc.delivery_result(corr, False, detail))
            return

        try:
            self.backend.send_channel(channel_spec["index"], body)
        except Exception as e:  # noqa: BLE001 - report the failure, don't crash
            log.warning(f"MeshCore send to '{endpoint}' failed: {e}")
            self._send_frame(relay_ipc.delivery_result(corr, False, str(e)))
            return
        # delivered = send accepted by the backend (spec Sec70), not a
        # radio-level delivery ACK.
        self.sent_cache.record(endpoint, body)
        self._send_frame(relay_ipc.delivery_result(corr, True))
        log.info(f"Sent MeshCore message to '{endpoint}' ({body_bytes} B)")


def hello_max_payload(cfg):
    """Advertised Hello capabilities.max_payload for this config.

    160 is the hard MeshCore-practical ceiling regardless of config: it
    keeps the advertised cap (which the daemon min()s against its own
    policy caps to decide truncation) independent of the local defensive
    check in Bridge.handle_send (cfg["max_text_bytes"]), so one
    misconfigured max_text_bytes can't disable both safety layers at once.
    A lower operator max_text_bytes tightens the advertised cap; a higher
    one can never loosen it past 160.
    """
    return min(MESHCORE_MAX_PAYLOAD, cfg["max_text_bytes"])


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    sock_path = os.environ["RELAYFABRIC_SOCKET"]
    plugin_name = os.environ.get("RELAYFABRIC_PLUGIN_NAME", "meshcore")
    raw_cfg = json.loads(os.environ.get("RELAYFABRIC_PLUGIN_CONFIG", "{}"))
    # Scrub the resolved config (may carry secrets substituted by the daemon
    # from a ${env:}/${file:} reference) out of our own environment so any
    # child process this plugin spawns doesn't inherit it.
    os.environ.pop("RELAYFABRIC_PLUGIN_CONFIG", None)
    try:
        cfg = load_config(raw_cfg)
    except (ValueError, TypeError) as e:
        print(f"relayfabric-meshcore: invalid config: {e}", file=sys.stderr)
        sys.exit(1)

    from relayfabric_sdk import ipc as relay_ipc

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    rfile = sock.makefile("rb")
    wfile = sock.makefile("wb")

    caps = relay_ipc.capabilities(groups=True, max_payload=hello_max_payload(cfg))
    relay_ipc.write_frame(wfile, relay_ipc.hello(plugin_name, PLUGIN_VERSION, caps))
    ack = relay_ipc.read_frame(rfile)
    if ack.get("t") != "hello_ack" or ack.get("error"):
        print(f"relayfabric-meshcore: hello rejected: {ack.get('error')}",
             file=sys.stderr)
        sys.exit(1)

    backend = MeshCoreBackend(cfg["connection"])
    bridge = Bridge(cfg, backend, wfile)
    backend.start()

    def reader_loop():
        for ev in backend.events():
            try:
                bridge.handle_event(ev)
            except Exception as e:  # noqa: BLE001 - one bad event must not kill the reader
                log.error(f"MeshCore event handler error: {e}")

    threading.Thread(target=reader_loop, daemon=True).start()

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
