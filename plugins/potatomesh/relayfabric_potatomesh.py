"""RelayFabric PotatoMesh plugin: feeds a PotatoMesh dashboard from the
Meshtastic MQTT JSON gateway stream.

Ingest-only: it subscribes to the same MQTT JSON topics the meshtastic plugin
uses, maps text/position/telemetry/nodeinfo events onto PotatoMesh's ingest
contract (data/mesh_ingestor/CONTRACTS.md in l5yth/potato-mesh, Apache-2.0),
and POSTs them with a bearer token. It never sends to the mesh; routed `send`
frames are rejected.

Module top level imports only stdlib plus the stdlib-only
relayfabric_sdk.bridge (mirrors the meshtastic plugin): the rest of
relayfabric_sdk and paho.mqtt are imported lazily so config/mapping helpers
stay importable without them. Message text is posted to PotatoMesh but never
logged here.
"""

import datetime
import json
import logging
import math
import os
import queue
import threading
import time
import urllib.parse
import urllib.request

from relayfabric_sdk.bridge import FrameWriter

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"

GAUGES_INTERVAL_SECS = 30

# Firmware MeshPacketSerializer telemetry payload keys -> PotatoMesh
# POST /api/telemetry metric keys (identity unless renamed; anything not
# listed is dropped rather than forwarded blind).
TELEMETRY_KEY_MAP = {
    # device metrics
    "battery_level": "battery_level",
    "voltage": "voltage",
    "channel_utilization": "channel_utilization",
    "air_util_tx": "air_util_tx",
    "uptime_seconds": "uptime_seconds",
    # environment metrics
    "temperature": "temperature",
    "relative_humidity": "relative_humidity",
    "barometric_pressure": "barometric_pressure",
    "gas_resistance": "gas_resistance",
    "current": "current",
    "iaq": "iaq",
    "distance": "distance",
    "lux": "lux",
    "white_lux": "white_lux",
    "ir_lux": "ir_lux",
    "uv_lux": "uv_lux",
    "wind_speed": "wind_speed",
    "wind_direction": "wind_direction",
    "wind_gust": "wind_gust",
    "wind_lull": "wind_lull",
    "weight": "weight",
    "radiation": "radiation",
    "rainfall_1h": "rainfall_1h",
    "rainfall_24h": "rainfall_24h",
    "soil_moisture": "soil_moisture",
    "soil_temperature": "soil_temperature",
    # air quality (firmware flattens *_standard to bare pm names)
    "pm10": "pm10_standard",
    "pm25": "pm25_standard",
    "pm100": "pm100_standard",
    "co2": "co2",
    "co2_temperature": "co2_temperature",
    "co2_humidity": "co2_humidity",
    "form_formaldehyde": "form_formaldehyde",
    "form_temperature": "form_temperature",
    "form_humidity": "form_humidity",
    # power metrics (firmware uses voltage_chN, PotatoMesh chN_voltage)
    "voltage_ch1": "ch1_voltage",
    "current_ch1": "ch1_current",
    "voltage_ch2": "ch2_voltage",
    "current_ch2": "ch2_current",
    "voltage_ch3": "ch3_voltage",
    "current_ch3": "ch3_current",
}

# device-metrics subset that also feeds the node row's camelCase deviceMetrics
DEVICE_METRICS_CAMEL = {
    "battery_level": "batteryLevel",
    "voltage": "voltage",
    "channel_utilization": "channelUtilization",
    "air_util_tx": "airUtilTx",
    "uptime_seconds": "uptimeSeconds",
}

BROADCAST_NUM = 0xFFFFFFFF


def load_config(raw):
    """Load and validate PotatoMesh plugin configuration.

    Required: broker, topic_root, url, token. Optional: gateway_id (None).
    """
    cfg = dict(raw)
    for field in ("broker", "topic_root", "url", "token"):
        if not cfg.get(field):
            raise ValueError(f"config requires '{field}'")
    cfg["url"] = cfg["url"].rstrip("/")
    cfg.setdefault("gateway_id", None)
    if cfg["gateway_id"] is None:
        # PotatoMesh's premise is a dashboard fed by radios the community
        # operates; on a shared/public broker a null filter forwards every
        # gateway's traffic — the worldwide soup that premise exists to avoid.
        log.warning(
            "gateway_id is null: accepting packets from ALL gateways on the "
            "topic. On a shared or public broker this feeds PotatoMesh "
            "non-local traffic; set gateway_id to your own node's hex ID.")
    return cfg


def canonical_node_id(num):
    """PotatoMesh canonical node id: !%08x, lowercase, 32-bit."""
    return f"!{num & 0xFFFFFFFF:08x}"


def parse_broker_url(url):
    """mqtt://host[:port] -> (host, port); mirrors the meshtastic plugin."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "mqtt" or not parsed.hostname:
        raise ValueError("broker must be mqtt://host[:port]")
    return parsed.hostname, parsed.port or 1883


def _finite(value):
    return isinstance(value, (int, float)) and math.isfinite(value)


def _iso_utc(epoch):
    return datetime.datetime.fromtimestamp(
        epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _topic_channel_name(topic):
    """<root...>/2/json/<TopicChannel>/<!gateway> -> TopicChannel or None."""
    parts = topic.split("/")
    try:
        json_idx = len(parts) - 1 - parts[::-1].index("json")
    except ValueError:
        return None
    if json_idx + 1 < len(parts) - 1:  # channel segment exists before gateway
        return parts[json_idx + 1]
    return None


class Mapper:
    """Maps MQTT JSON gateway events onto PotatoMesh POST payloads.

    handle(topic, event) -> list of (api_path, payload) posts. Pure logic —
    no I/O — so it is the unit under test. Keeps a per-node aggregate so
    /api/nodes rows accumulate identity + position + device metrics across
    events (in-memory only; restart re-learns from the next beacons).
    """

    def __init__(self, cfg, now_fn=time.time):
        self.cfg = cfg
        self.now_fn = now_fn
        self.nodes = {}

    def handle(self, topic, event):
        if self.cfg["gateway_id"] is not None:
            last_segment = topic.rsplit("/", 1)[-1] if "/" in topic else None
            if last_segment != self.cfg["gateway_id"]:
                return []
        etype = event.get("type")
        handler = {
            "text": self._map_text,
            "position": self._map_position,
            "telemetry": self._map_telemetry,
            "nodeinfo": self._map_nodeinfo,
        }.get(etype)
        if handler is None:
            return []
        from_num = event.get("from")
        if not isinstance(from_num, int):
            return []
        return handler(topic, event, from_num)

    # ----- shared field helpers -----

    def _rx_time(self, event):
        ts = event.get("timestamp")
        if isinstance(ts, int) and ts > 0:
            return ts
        return int(self.now_fn())

    def _base(self, event, from_num):
        payload = {
            "id": event.get("id"),
            "rx_time": self._rx_time(event),
            "from_id": canonical_node_id(from_num),
            "protocol": "meshtastic",
        }
        payload["rx_iso"] = _iso_utc(payload["rx_time"])
        sender = event.get("sender")
        if isinstance(sender, str) and sender:
            payload["ingestor"] = sender
        if _finite(event.get("snr")):
            payload["snr"] = event["snr"]
        if _finite(event.get("rssi")):
            payload["rssi"] = int(event["rssi"])
        return payload

    def _to_id(self, event):
        to = event.get("to")
        if not isinstance(to, int):
            return None
        if to & 0xFFFFFFFF == BROADCAST_NUM:
            return "^all"
        return canonical_node_id(to)

    def _node_upsert(self, event, from_num, **fields):
        """Update the per-node aggregate and build the /api/nodes post."""
        node_id = canonical_node_id(from_num)
        entry = self.nodes.setdefault(node_id, {"num": from_num & 0xFFFFFFFF})
        entry["lastHeard"] = self._rx_time(event)
        if _finite(event.get("snr")):
            entry["snr"] = event["snr"]
        if isinstance(event.get("hops_away"), int):
            entry["hopsAway"] = event["hops_away"]
        for key, value in fields.items():
            if value:
                entry[key] = value
        wrapper = {node_id: dict(entry), "protocol": "meshtastic"}
        sender = event.get("sender")
        if isinstance(sender, str) and sender:
            wrapper["ingestor"] = sender
        return ("/api/nodes", wrapper)

    # ----- per-type mapping -----

    def _map_text(self, topic, event, from_num):
        text = (event.get("payload") or {}).get("text")
        if not text or not isinstance(text, str):
            return []
        msg = self._base(event, from_num)
        msg["to_id"] = self._to_id(event)
        msg["channel"] = event.get("channel")
        msg["portnum"] = "TEXT_MESSAGE_APP"
        msg["text"] = text
        if isinstance(event.get("hops_away"), int):
            msg["hops"] = event["hops_away"]
        channel_name = _topic_channel_name(topic)
        if channel_name:
            msg["channel_name"] = channel_name
        return [("/api/messages", msg)]

    def _map_position(self, topic, event, from_num):
        payload = event.get("payload") or {}
        lat_i = payload.get("latitude_i")
        lon_i = payload.get("longitude_i")
        if not isinstance(lat_i, int) or not isinstance(lon_i, int):
            return []
        pos = self._base(event, from_num)
        pos["node_id"] = pos["from_id"]
        pos["node_num"] = from_num & 0xFFFFFFFF
        pos["to_id"] = self._to_id(event)
        node_position = {}
        # CONTRACTS.md sentinel rule: (0, 0) means "no GPS fix" — strip the
        # whole coordinate; a single zero axis is a real equator/meridian fix.
        if not (lat_i == 0 and lon_i == 0):
            pos["latitude"] = lat_i * 1e-7
            pos["longitude"] = lon_i * 1e-7
            node_position["latitude"] = pos["latitude"]
            node_position["longitude"] = pos["longitude"]
            if isinstance(payload.get("altitude"), int):
                pos["altitude"] = payload["altitude"]
                node_position["altitude"] = payload["altitude"]
        pos_time = payload.get("time")
        if isinstance(pos_time, int) and pos_time > 0:
            pos["position_time"] = pos_time
            node_position["time"] = pos_time
        for src, dst in (("sats_in_view", "sats_in_view"), ("PDOP", "pdop"),
                         ("precision_bits", "precision_bits"),
                         ("ground_speed", "ground_speed"),
                         ("ground_track", "ground_track")):
            if _finite(payload.get(src)):
                pos[dst] = payload[src]
        return [("/api/positions", pos),
                self._node_upsert(event, from_num, position=node_position)]

    def _map_telemetry(self, topic, event, from_num):
        payload = event.get("payload") or {}
        tel = self._base(event, from_num)
        tel["node_id"] = tel["from_id"]
        tel["node_num"] = from_num & 0xFFFFFFFF
        tel["to_id"] = self._to_id(event)
        tel["channel"] = event.get("channel")
        tel["payload_b64"] = ""
        device_metrics = {}
        for src, value in payload.items():
            dst = TELEMETRY_KEY_MAP.get(src)
            if dst is None or not _finite(value):
                continue
            tel[dst] = value
            camel = DEVICE_METRICS_CAMEL.get(src)
            if camel:
                device_metrics[camel] = value
        posts = [("/api/telemetry", tel)]
        if device_metrics:
            posts.append(self._node_upsert(event, from_num,
                                           deviceMetrics=device_metrics))
        return posts

    def _map_nodeinfo(self, topic, event, from_num):
        payload = event.get("payload") or {}
        user = {}
        if isinstance(payload.get("shortname"), str):
            user["shortName"] = payload["shortname"]
        if isinstance(payload.get("longname"), str):
            user["longName"] = payload["longname"]
        # payload also carries int hardware/role enum codes; mapping them to
        # the contract's name strings would need the (GPL) protobuf enum
        # tables, and the fields are optional — so they are omitted.
        return [self._node_upsert(event, from_num, user=user)]


class Poster:
    """Bearer-token JSON POSTer to a PotatoMesh instance. Best-effort:
    failures are logged and counted, never retried — node/position rows are
    re-upserted by the next beacon anyway.
    """

    def __init__(self, base_url, token, urlopen=urllib.request.urlopen):
        self.base_url = base_url
        self.token = token
        self.urlopen = urlopen
        self.posted = 0
        self.failures = 0

    def post(self, path, payload):
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self.urlopen(req, timeout=10):
                pass
        except (OSError, ValueError) as e:
            self.failures += 1
            log.warning(f"POST {path} failed: {e}")
            return False
        self.posted += 1
        return True


class Bridge(FrameWriter):
    """Plugin Protocol side: rejects sends (ingest-only); owns the MQTT
    backend, mapper, and poster, and runs the map-and-POST worker."""

    def __init__(self, cfg, sock_file):
        super().__init__(sock_file)
        self.mapper = Mapper(cfg)
        self.poster = Poster(cfg["url"], cfg["token"])
        self.backend = MqttJsonBackend(cfg["broker"], cfg["topic_root"])

    def handle_send(self, frame):
        from relayfabric_sdk import ipc as relay_ipc

        self._send_frame(relay_ipc.delivery_result(
            frame["corr"], False, "potatomesh is ingest-only"))

    def start(self):
        self.backend.start()
        threading.Thread(target=self._worker_loop, daemon=True).start()

    def _worker_loop(self):
        from relayfabric_sdk import ipc as relay_ipc

        last_gauges_at = time.monotonic()
        for topic, event in self.backend.events():
            try:
                for path, payload in self.mapper.handle(topic, event):
                    self.poster.post(path, payload)
            except Exception as e:  # noqa: BLE001 - one bad event must not kill the worker
                log.error(f"PotatoMesh event handler error: {e}")
            now = time.monotonic()
            if now - last_gauges_at >= GAUGES_INTERVAL_SECS:
                last_gauges_at = now
                self._send_frame(relay_ipc.gauges({
                    "posted": self.poster.posted,
                    "http_failures": self.poster.failures,
                    "queue_depth": self.backend.queue_depth(),
                }))


class MqttJsonBackend:
    """paho-mqtt subscriber for the JSON gateway topics; mirrors the
    meshtastic plugin's backend (bounded queue, drop-on-full, lazy paho
    import, connect_async + auto-reconnect).
    """

    def __init__(self, broker_url, topic_root):
        import paho.mqtt.client as mqtt

        self._host, self._port = parse_broker_url(broker_url)
        self._sub_topic = f"{topic_root}/2/json/#"
        self._queue = queue.Queue(maxsize=256)
        self._client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect

    def _on_connect(self, client, userdata, connect_flags, reason_code, properties):
        client.subscribe(self._sub_topic, qos=1)
        log.info(f"MQTT connected, subscribed to {self._sub_topic!r}")

    def _on_message(self, client, userdata, msg):
        try:
            event = json.loads(msg.payload)
        except (ValueError, UnicodeDecodeError) as e:
            log.debug(f"Dropping non-JSON MQTT message on {msg.topic}: {e}")
            return
        if not isinstance(event, dict):
            log.debug(f"Dropping non-dict MQTT JSON payload on {msg.topic}")
            return
        try:
            self._queue.put_nowait((msg.topic, event))
        except queue.Full:
            log.debug(f"Dropping MQTT message on {msg.topic}: event queue full")

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

    # text=False: this plugin is ingest-only (handle_send rejects every
    # send), so it must NOT advertise the default text=True -- otherwise the
    # daemon routes text sends here expecting delivery and they all fail.
    run_plugin(os.environ.get("RELAYFABRIC_PLUGIN_NAME", "potatomesh"),
               PLUGIN_VERSION, _make_bridge, relay_ipc.capabilities(text=False))
