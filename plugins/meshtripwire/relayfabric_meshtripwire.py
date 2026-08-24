"""RelayFabric meshtripwire plugin: relays meshtripwire tripwire alerts into
the fabric so they reach an off-grid LXMF/Reticulum/Meshtastic destination.

meshtripwire (github.com/OutandBack/meshtripwire, MIT) is a wireless tripwire:
ESP32 sensor nodes detect unknown WiFi/BLE MACs and relay them over LoRa to a
base station whose monitor filters (whitelist, RSSI, per-MAC cooldown) and
alerts. Its built-in alert channels (ntfy/webhook/Twilio) all need the
Internet -- the opposite of the remote sites it's built for. meshtripwire's
MQTT alert output publishes each filtered alert to a broker topic; this plugin
subscribes to that topic and emits it as an inbound message on one endpoint,
which a route can carry into LXMF or a Meshtastic channel.

Ingest-only: alerts flow one way (meshtripwire -> fabric). Routed `send`
frames are rejected. Per-MAC rate limiting is meshtripwire's job (its
AlertCooldownSeconds), so this plugin does not duplicate it.

Payloads are accepted as either the meshtripwire JSON alert
({mac, node, rssi, lat, lon, message}) or a plain-text line -- so it works
whether meshtripwire is configured to publish JSON or a bare message.
"""

import json
import logging
import os
import queue
import threading
import time
import urllib.parse

from relayfabric_sdk.bridge import FrameWriter

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"
GAUGES_INTERVAL_SECS = 30


def load_config(raw):
    """Validate config. Required: broker (mqtt://host[:port]).
    Optional: topic (meshtripwire/alerts), endpoint (alerts), client_id."""
    cfg = dict(raw)
    if not cfg.get("broker"):
        raise ValueError("config requires 'broker' (mqtt://host[:port])")
    parse_broker_url(cfg["broker"])  # validate early
    cfg.setdefault("topic", "meshtripwire/alerts")
    cfg.setdefault("endpoint", "alerts")
    cfg.setdefault("client_id", None)
    return cfg


def parse_broker_url(url):
    """mqtt://host[:port] -> (host, port); mirrors the meshtastic/potatomesh plugins."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "mqtt" or not parsed.hostname:
        raise ValueError("broker must be mqtt://host[:port]")
    return parsed.hostname, parsed.port or 1883


def parse_payload(payload_bytes):
    """Decode an MQTT payload to a JSON dict, or the raw stripped text if it
    isn't JSON. Returns None for empty payloads."""
    try:
        text = payload_bytes.decode("utf-8", "replace").strip()
    except AttributeError:
        return None
    if not text:
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        return text  # plain-text alert line
    if isinstance(obj, dict):
        return obj
    return text  # JSON scalar/array: treat its text form as the message


def format_alert(obj):
    """Human-readable alert line(s) from a meshtripwire payload (dict or str).

    A plain-text payload is already a finished alert line (meshtripwire, or a
    generic producer, formatted it) -- pass it through verbatim. For the JSON
    alert, build the line from the structured fields so it reads the same
    regardless of the producer's own `message` wording; `message` is only the
    fallback headline when no MAC is present."""
    if not isinstance(obj, dict):
        return str(obj).strip()
    mac = obj.get("mac")
    node = obj.get("node")
    rssi = obj.get("rssi")
    lat = obj.get("lat")
    lon = obj.get("lon")
    message = obj.get("message")

    if mac:
        head = f"Unknown MAC {mac}" + (f" at node {node}" if node else "")
    elif message:
        head = str(message)
    else:
        head = "meshtripwire alert"

    line = f"⚠️ {head}"
    if rssi is not None:
        line += f" · RSSI {rssi} dBm"
    if lat is not None and lon is not None:
        line += f"\n📍 https://www.google.com/maps?q={lat},{lon}"
    return line


def alert_sender(obj):
    """Sender identity: distinguish sensor nodes when the payload names one."""
    if isinstance(obj, dict):
        node = obj.get("node")
        if node:
            return f"meshtripwire:{node}"
    return "meshtripwire"


class Bridge(FrameWriter):
    """Plugin Protocol side: ingest-only. Rejects sends; formats each
    meshtripwire alert and emits it inbound on the configured endpoint."""

    def __init__(self, cfg, sock_file, backend=None):
        super().__init__(sock_file)
        self.cfg = cfg
        self.backend = backend if backend is not None else MqttAlertBackend(
            cfg["broker"], cfg["topic"], cfg["client_id"])
        self.alerts = 0
        self._last_gauges_at = time.monotonic()

    def handle_send(self, frame):
        from relayfabric_sdk import ipc as relay_ipc

        self._send_frame(relay_ipc.delivery_result(
            frame["corr"], False, "meshtripwire is ingest-only"))

    def start(self):
        self.backend.start()
        threading.Thread(target=self._reader_loop, daemon=True).start()

    def _reader_loop(self):
        for topic, payload in self.backend.events():
            try:
                self.handle_message(topic, payload)
            except Exception as e:  # noqa: BLE001 - one bad alert must not kill the reader
                log.error(f"meshtripwire alert handler error: {e}")

    def handle_message(self, topic, payload_bytes):
        from relayfabric_sdk import ipc as relay_ipc

        obj = parse_payload(payload_bytes)
        if obj is None:
            return
        body = format_alert(obj)
        ts = obj.get("ts") if isinstance(obj, dict) else None
        self._send_frame(relay_ipc.inbound(self.cfg["endpoint"], alert_sender(obj), body, ts))
        self.alerts += 1
        self._maybe_emit_gauges()

    def _maybe_emit_gauges(self):
        now = time.monotonic()
        if now - self._last_gauges_at < GAUGES_INTERVAL_SECS:
            return
        self._last_gauges_at = now
        from relayfabric_sdk import ipc as relay_ipc

        self._send_frame(relay_ipc.gauges({
            "alerts": self.alerts,
            "queue_depth": self.backend.queue_depth(),
        }))


class MqttAlertBackend:
    """paho-mqtt subscriber for meshtripwire's alert topic (bounded queue,
    drop-on-full, lazy paho import, connect_async + auto-reconnect)."""

    def __init__(self, broker_url, topic, client_id=None):
        import paho.mqtt.client as mqtt

        self._host, self._port = parse_broker_url(broker_url)
        self._topic = topic
        self._queue = queue.Queue(maxsize=256)
        self._client = mqtt.Client(
            client_id=client_id or "",
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect

    def _on_connect(self, client, userdata, connect_flags, reason_code, properties):
        client.subscribe(self._topic, qos=1)
        log.info(f"MQTT connected, subscribed to {self._topic!r}")

    def _on_message(self, client, userdata, msg):
        try:
            self._queue.put_nowait((msg.topic, msg.payload))
        except queue.Full:
            log.debug(f"Dropping alert on {msg.topic}: queue full")

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        log.warning(f"MQTT disconnected: {reason_code}")

    def start(self):
        self._client.connect_async(self._host, self._port)
        self._client.loop_start()

    def events(self):
        while True:
            yield self._queue.get()

    def queue_depth(self):
        return self._queue.qsize()


def _make_bridge(raw_cfg, sock):
    return Bridge(load_config(raw_cfg), sock)


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    from relayfabric_sdk import ipc as relay_ipc
    from relayfabric_sdk import run_plugin

    # text=False: ingest-only (handle_send rejects every send), so it must not
    # advertise the default text=True -- otherwise the daemon routes text sends
    # here expecting delivery and they all fail.
    run_plugin(os.environ.get("RELAYFABRIC_PLUGIN_NAME", "meshtripwire"),
               PLUGIN_VERSION, _make_bridge, relay_ipc.capabilities(text=False))
