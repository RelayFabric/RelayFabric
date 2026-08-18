"""RelayFabric Meshtastic plugin: bridges Meshtastic MQTT text uplinks over Plugin Protocol v1.

Module top level imports only stdlib plus the stdlib-only
relayfabric_sdk.bridge, so config/parser/loop-guard helpers stay importable
without cbor2, paho-mqtt, or meshtastic/protobuf packages (GPL). The rest of
relayfabric_sdk (ipc and SentCache) and paho.mqtt.client are imported lazily
inside the methods that need them (see MqttJsonBackend.__init__ and
_make_bridge). Text bytes are never logged, only names/types.
"""

import json
import logging
import math
import os
import queue
import threading
import time
import urllib.parse

from relayfabric_sdk.bridge import FrameWriter, capped_text_send

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"

# design §3 (cycle D): plugin-side rate limit on Gauges frame emission -- at
# most one per this many seconds, regardless of how many events arrive.
GAUGES_INTERVAL_SECS = 30

# Hard ceiling on advertised Hello capabilities.max_payload, independent of
# cfg["max_text_bytes"] (see main()'s use of it): a practical cap for
# Meshtastic text payloads regardless of how an operator configures
# max_text_bytes.
MESHTASTIC_MAX_PAYLOAD = 200


def load_config(raw):
    """Load and validate Meshtastic plugin configuration.

    Required fields: broker, topic_root, channels (non-empty dict).
    Each channel value must be a dict with required int 'index' and str 'topic_channel'.

    Defaults: gateway_id None, max_text_bytes 200.

    Returns a copy of the config dict with channels deep-copied.
    Raises ValueError if validation fails.
    """
    cfg = dict(raw)

    if not cfg.get("broker"):
        raise ValueError("config requires 'broker'")
    if not cfg.get("topic_root"):
        raise ValueError("config requires 'topic_root'")
    if not cfg.get("channels"):
        raise ValueError("config requires a non-empty 'channels' mapping")

    # Validate and copy channels
    channels_copy = {}
    for name, channel_spec in cfg["channels"].items():
        if not isinstance(channel_spec, dict):
            raise TypeError(f"channel '{name}' must be a dict")
        if "index" not in channel_spec:
            raise ValueError(f"channel '{name}' requires 'index'")
        if "topic_channel" not in channel_spec:
            raise ValueError(f"channel '{name}' requires 'topic_channel'")
        idx = channel_spec["index"]
        if not isinstance(idx, int):
            raise TypeError(f"channel '{name}' index must be int, got {type(idx).__name__}")
        if not isinstance(channel_spec["topic_channel"], str):
            raise TypeError(f"channel '{name}' topic_channel must be str")

        # Deep copy each channel spec
        channels_copy[name] = dict(channel_spec)

    cfg["channels"] = channels_copy
    cfg.setdefault("gateway_id", None)
    cfg.setdefault("max_text_bytes", 200)
    if not isinstance(cfg["max_text_bytes"], int):
        raise TypeError(
            f"max_text_bytes must be int, got {type(cfg['max_text_bytes']).__name__}"
        )

    return cfg


def channels_by_index(cfg):
    """Build reverse mapping from channel index to channel name.

    Returns dict[int, str] mapping channel index to name.
    """
    return {
        channel_spec["index"]: name
        for name, channel_spec in cfg["channels"].items()
    }


def parse_uplink(topic, event, by_index, gateway_id):
    """Parse a Meshtastic text uplink event into (name, sender, text, ts) or None.

    Args:
        topic: MQTT topic string, form <root>/2/json/<TopicChannel>/<!gatewayhex>
        event: dict with type, payload, channel, sender (optional), from (optional), timestamp (optional)
        by_index: dict[int, str] mapping channel index to channel name (from channels_by_index)
        gateway_id: str gateway_id from config (may be None for no filtering)

    Returns:
        (name, sender, text, ts) tuple if valid text event, else None.

    Gateway filtering: if gateway_id is set, compares last topic segment against it;
    mismatch returns None.

    Channel mapping: event["channel"] is looked up in by_index; unmapped returns None.

    Sender resolution: prefers event.get("sender"), falls back to f"!{event['from']:08x}" if
    'from' field is present, else None (drops message).

    Text validation: event["type"] must be "text", and payload["text"] must be
    non-empty string, else None.

    Timestamp: event.get("timestamp") (may be None).
    """
    # Type filter
    if event.get("type") != "text":
        return None

    # Text validation
    payload = event.get("payload") or {}
    text = payload.get("text")
    if not text or not isinstance(text, str):
        return None

    # Channel mapping
    channel_idx = event.get("channel")
    if channel_idx is None:
        return None
    if channel_idx not in by_index:
        return None
    name = by_index[channel_idx]

    # Sender resolution
    sender = event.get("sender")
    if sender is None:
        from_val = event.get("from")
        if from_val is not None:
            sender = f"!{from_val:08x}"
        else:
            return None

    # Gateway filter (if gateway_id is set, check last topic segment)
    if gateway_id is not None:
        last_segment = topic.rsplit("/", 1)[-1] if "/" in topic else None
        if last_segment != gateway_id:
            return None

    ts = event.get("timestamp")

    return name, sender, text, ts


def parse_broker_url(url):
    """Parse a Meshtastic plugin broker URL into (host, port).

    Mirrors plugins/mqtt's Rust parse_broker rule: requires an "mqtt://"
    scheme, and defaults the port to 1883 when omitted.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "mqtt" or not parsed.hostname:
        raise ValueError("broker must be mqtt://host[:port]")
    return parsed.hostname, parsed.port or 1883


class MqttJsonBackend:
    """paho-mqtt transport for the Meshtastic MQTT JSON gateway format.

    The backend seam Bridge depends on (swappable for FakeBackend in tests,
    per the signal plugin's SignalCliBackend). paho is imported lazily here
    so the rest of the module stays importable without it (see module
    docstring).
    """

    def __init__(self, broker_url, topic_root):
        import paho.mqtt.client as mqtt

        self.topic_root = topic_root
        self._host, self._port = parse_broker_url(broker_url)
        self._sub_topic = f"{topic_root}/2/json/#"
        self._pub_topic = f"{topic_root}/2/json/mqtt/"
        # Bounded, like the Rust mqtt plugin's mpsc::channel(64/256): an
        # unbounded queue would let a stalled/slow reader thread accumulate
        # inbound events without limit. put_nowait in _on_message drops (with
        # a debug log) on Full rather than blocking paho's network thread.
        self._queue = queue.Queue(maxsize=256)
        self._client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect

    def _on_connect(self, client, userdata, connect_flags, reason_code, properties):
        # re-subscribe on every (re)connect: paho's auto-reconnect does not
        # replay subscriptions itself for a fresh session.
        client.subscribe(self._sub_topic, qos=1)
        log.info(f"MQTT connected, subscribed to {self._sub_topic!r}")

    def _on_message(self, client, userdata, msg):
        try:
            event = json.loads(msg.payload)
        except (ValueError, UnicodeDecodeError) as e:
            log.debug(f"Dropping non-JSON MQTT message on {msg.topic}: {e}")
            return
        if not isinstance(event, dict):
            # valid JSON but not an object (e.g. "[1]" or "42") -- any
            # tenant on a shared broker can publish this. parse_uplink
            # assumes a dict; drop here instead of queuing something that
            # would raise AttributeError in the reader loop.
            log.debug(f"Dropping non-dict MQTT JSON payload on {msg.topic}: {type(event).__name__}")
            return
        try:
            self._queue.put_nowait((msg.topic, event))
        except queue.Full:
            # never block paho's network thread; a full queue means the
            # reader thread is falling behind, so drop this newest event
            # (put_nowait raises Full without touching the queue's
            # existing contents) rather than wedge inbound MQTT processing
            # entirely.
            log.debug(f"Dropping MQTT message on {msg.topic}: event queue full")

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        log.warning(f"MQTT disconnected: {reason_code}")

    def start(self):
        # connect_async() (not connect()) defers the actual TCP attempt to
        # the network thread loop_start() below spawns: connect() is
        # blocking and raises synchronously (e.g. ConnectionRefusedError) if
        # the broker is briefly unreachable at startup, which would crash
        # the whole plugin process before it ever got a chance to retry.
        # connect_async() + loop_start() gives paho's built-in auto-reconnect
        # (reconnect_on_failure, on by default) instead.
        self._client.connect_async(self._host, self._port)
        self._client.loop_start()

    def events(self):
        """Yield (topic, parsed-json) tuples from the queue forever."""
        while True:
            yield self._queue.get()

    def queue_depth(self):
        """Current backlog of not-yet-bridged inbound events -- the gauges
        fallback (design §3) for an uplink whose JSON carries no rssi/snr."""
        return self._queue.qsize()

    def publish_downlink(self, obj):
        payload = json.dumps(obj)
        info = self._client.publish(self._pub_topic, payload, qos=1)
        try:
            info.wait_for_publish(timeout=30)
        except (ValueError, RuntimeError) as e:
            raise RuntimeError(f"mqtt publish failed: {e}") from e
        if not info.is_published():
            raise RuntimeError(f"mqtt publish to {self._pub_topic!r} timed out")


class Bridge(FrameWriter):
    """Bridges parsed Meshtastic MQTT JSON events <-> Plugin Protocol frames.

    Mirrors plugins/signal's Bridge exactly (write lock, _send_frame).
    handle_event runs on the backend's reader thread; handle_send runs on the
    main thread; all daemon-socket writes go through _send_frame, serialized
    by one lock.

    Unlike signal's Bridge, there is no sync/non-sync distinction for the
    loop guard: the Meshtastic node re-uplinks our own downlinks verbatim, so
    ANY uplink whose (channel name, text) matches the SentCache is dropped.
    """

    def __init__(self, cfg, backend, sock_file):
        from relayfabric_sdk import SentCache

        super().__init__(sock_file)
        self.cfg = cfg
        self.backend = backend
        # 1h, not SentCache's 86400s default: a Meshtastic radio echo (our
        # downlink re-uplinked by the node) arrives fast, so this only needs
        # to bound how long a lost echo can leave a stale entry able to
        # swallow one genuine identical-text message (see README).
        self.sent_cache = SentCache(ttl_secs=3600)
        self.by_index = channels_by_index(cfg)
        # baseline to "now", not 0/never: a fresh Bridge must not emit a
        # gauges frame on its very first handled event (see
        # _maybe_emit_gauges), only after GAUGES_INTERVAL_SECS has elapsed.
        self._last_gauges_at = time.monotonic()

    def start(self):
        self.backend.start()
        threading.Thread(target=self._reader_loop, daemon=True).start()

    def _reader_loop(self):
        for topic, event in self.backend.events():
            try:
                self.handle_event(topic, event)
            except Exception as e:  # noqa: BLE001 - one bad event must not kill the reader
                log.error(f"Meshtastic event handler error: {e}")

    def _maybe_emit_gauges(self, event):
        """Best-effort gauge snapshot (design §3), rate-limited to at most
        once every GAUGES_INTERVAL_SECS. Uses rssi/snr straight off the MQTT
        JSON gateway envelope when the gateway included them (data already
        flowing through this same `event` dict -- no new backend call);
        falls back to the backend's inbound queue depth when neither is
        present.

        rssi/snr are attacker-influenced (an untrusted MQTT gateway/broker
        controls this JSON, and Python's stdlib json module parses the
        NaN/Infinity/-Infinity literals by default), so both are checked
        with math.isfinite here -- defense in depth alongside the daemon's
        own PluginGauges::record boundary check, which is the enforced one.
        """
        now = time.monotonic()
        if now - self._last_gauges_at < GAUGES_INTERVAL_SECS:
            return
        self._last_gauges_at = now
        values = {}
        rssi = event.get("rssi")
        if isinstance(rssi, (int, float)) and math.isfinite(rssi):
            values["rssi"] = rssi
        snr = event.get("snr")
        if isinstance(snr, (int, float)) and math.isfinite(snr):
            values["snr"] = snr
        if not values:
            values["queue_depth"] = self.backend.queue_depth()
        from relayfabric_sdk import ipc as relay_ipc

        self._send_frame(relay_ipc.gauges(values))

    # ----- inbound (Meshtastic -> daemon); called from the backend's reader thread -----

    def handle_event(self, topic, event):
        self._maybe_emit_gauges(event)
        parsed = parse_uplink(topic, event, self.by_index, self.cfg["gateway_id"])
        if parsed is None:
            return
        name, sender, text, ts = parsed

        if self.sent_cache.match(name, text):
            return  # loop guard: node re-uplinked our own downlink verbatim

        from relayfabric_sdk import ipc as relay_ipc

        self._send_frame(relay_ipc.inbound(name, sender, text, ts))
        log.info(f"Bridged Meshtastic message from {sender} to '{name}' "
                 f"({len(text)} chars)")

    # ----- egress (daemon -> Meshtastic); called from the main thread -----

    def handle_send(self, frame):
        capped_text_send(self, frame, "Meshtastic", "Meshtastic message",
                         lambda spec, endpoint, body: self.backend.publish_downlink({
                             "from": 0,
                             "channel": spec["index"],
                             "type": "sendtext",
                             "payload": body,
                         }))


def hello_max_payload(cfg):
    """Advertised Hello capabilities.max_payload for this config.

    200 is the hard Meshtastic-practical ceiling regardless of config: it
    keeps the advertised cap (which the daemon min()s against its own
    policy caps to decide truncation) independent of the local defensive
    check in Bridge.handle_send (cfg["max_text_bytes"]), so one
    misconfigured max_text_bytes can't disable both safety layers at once.
    A lower operator max_text_bytes tightens the advertised cap; a higher
    one can never loosen it past 200.
    """
    return min(MESHTASTIC_MAX_PAYLOAD, cfg["max_text_bytes"])


def _caps(raw_cfg):
    from relayfabric_sdk import ipc as relay_ipc

    return relay_ipc.capabilities(groups=True,
                                  max_payload=hello_max_payload(load_config(raw_cfg)))


def _make_bridge(raw_cfg, sock):
    cfg = load_config(raw_cfg)
    return Bridge(cfg, MqttJsonBackend(cfg["broker"], cfg["topic_root"]), sock)


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    from relayfabric_sdk import run_plugin

    run_plugin(os.environ.get("RELAYFABRIC_PLUGIN_NAME", "meshtastic"),
               PLUGIN_VERSION, _make_bridge, _caps)
