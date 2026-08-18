import json
import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sdk", "python"))

import relayfabric_potatomesh as plug
from relayfabric_sdk import FakeSock


def base_cfg(**overrides):
    cfg = {
        "broker": "mqtt://localhost",
        "topic_root": "msh/US",
        "url": "https://potato.example.org",
        "token": "sekrit",
    }
    cfg.update(overrides)
    return cfg


TOPIC = "msh/US/2/json/LongFast/!aabbccdd"


def text_event(**overrides):
    ev = {
        "id": 452664778,
        "channel": 0,
        "from": 0x7EFEEE00,
        "to": 0xFFFFFFFF,
        "sender": "!aabbccdd",
        "timestamp": 1646832724,
        "type": "text",
        "snr": 5.75,
        "rssi": -42,
        "hops_away": 2,
        "hop_start": 5,
        "payload": {"text": "hello mesh"},
    }
    ev.update(overrides)
    return ev


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = plug.load_config(base_cfg())
        self.assertIsNone(cfg["gateway_id"])
        self.assertEqual(cfg["url"], "https://potato.example.org")

    def test_url_trailing_slash_stripped(self):
        cfg = plug.load_config(base_cfg(url="https://potato.example.org/"))
        self.assertEqual(cfg["url"], "https://potato.example.org")

    def test_required_fields(self):
        for missing in ("broker", "topic_root", "url", "token"):
            raw = base_cfg()
            del raw[missing]
            with self.assertRaises(ValueError):
                plug.load_config(raw)


class CanonicalIdTests(unittest.TestCase):
    def test_formats_lowercase_hex8(self):
        self.assertEqual(plug.canonical_node_id(0x7EFEEE00), "!7efeee00")

    def test_masks_to_32_bits(self):
        self.assertEqual(plug.canonical_node_id(0x1_0000_0001), "!00000001")


class MapperTextTests(unittest.TestCase):
    def setUp(self):
        self.mapper = plug.Mapper(plug.load_config(base_cfg()), now_fn=lambda: 1700000000)

    def test_text_maps_to_messages_post(self):
        posts = self.mapper.handle(TOPIC, text_event())
        self.assertEqual(len(posts), 1)
        path, payload = posts[0]
        self.assertEqual(path, "/api/messages")
        self.assertEqual(payload["id"], 452664778)
        self.assertEqual(payload["rx_time"], 1646832724)
        self.assertEqual(payload["rx_iso"], "2022-03-09T13:32:04Z")
        self.assertEqual(payload["from_id"], "!7efeee00")
        self.assertEqual(payload["to_id"], "^all")
        self.assertEqual(payload["channel"], 0)
        self.assertEqual(payload["portnum"], "TEXT_MESSAGE_APP")
        self.assertEqual(payload["text"], "hello mesh")
        self.assertEqual(payload["snr"], 5.75)
        self.assertEqual(payload["rssi"], -42)
        self.assertEqual(payload["hops"], 2)
        self.assertEqual(payload["channel_name"], "LongFast")
        self.assertEqual(payload["protocol"], "meshtastic")
        self.assertEqual(payload["ingestor"], "!aabbccdd")

    def test_text_directed_to_canonical(self):
        posts = self.mapper.handle(TOPIC, text_event(to=0x11223344))
        self.assertEqual(posts[0][1]["to_id"], "!11223344")

    def test_zero_timestamp_uses_now(self):
        posts = self.mapper.handle(TOPIC, text_event(timestamp=0))
        self.assertEqual(posts[0][1]["rx_time"], 1700000000)

    def test_non_finite_rf_dropped(self):
        posts = self.mapper.handle(TOPIC, text_event(snr=float("nan")))
        self.assertNotIn("snr", posts[0][1])

    def test_empty_text_dropped(self):
        self.assertEqual(self.mapper.handle(TOPIC, text_event(payload={})), [])

    def test_unknown_type_dropped(self):
        self.assertEqual(self.mapper.handle(TOPIC, text_event(type="paxcounter")), [])

    def test_gateway_filter(self):
        mapper = plug.Mapper(
            plug.load_config(base_cfg(gateway_id="!aabbccdd")), now_fn=lambda: 0)
        self.assertEqual(len(mapper.handle(TOPIC, text_event())), 1)
        other = "msh/US/2/json/LongFast/!99999999"
        self.assertEqual(mapper.handle(other, text_event()), [])


def position_event(**payload_overrides):
    payload = {
        "latitude_i": 525200000,
        "longitude_i": 133700000,
        "altitude": 40,
        "time": 1646832000,
        "sats_in_view": 7,
        "PDOP": 190,
        "precision_bits": 32,
        "ground_speed": 3,
        "ground_track": 180,
    }
    payload.update(payload_overrides)
    return text_event(type="position", payload=payload)


class MapperPositionTests(unittest.TestCase):
    def setUp(self):
        self.mapper = plug.Mapper(plug.load_config(base_cfg()), now_fn=lambda: 1700000000)

    def test_position_maps_to_positions_and_nodes(self):
        posts = dict(self.mapper.handle(TOPIC, position_event()))
        self.assertIn("/api/positions", posts)
        self.assertIn("/api/nodes", posts)
        pos = posts["/api/positions"]
        self.assertEqual(pos["node_id"], "!7efeee00")
        self.assertEqual(pos["from_id"], "!7efeee00")
        self.assertAlmostEqual(pos["latitude"], 52.52, places=6)
        self.assertAlmostEqual(pos["longitude"], 13.37, places=6)
        self.assertEqual(pos["altitude"], 40)
        self.assertEqual(pos["position_time"], 1646832000)
        self.assertEqual(pos["sats_in_view"], 7)
        self.assertEqual(pos["pdop"], 190)
        self.assertEqual(pos["precision_bits"], 32)
        self.assertEqual(pos["protocol"], "meshtastic")
        node_entry = posts["/api/nodes"]["!7efeee00"]
        self.assertAlmostEqual(node_entry["position"]["latitude"], 52.52, places=6)
        self.assertEqual(node_entry["position"]["time"], 1646832000)
        self.assertEqual(node_entry["lastHeard"], 1646832724)

    def test_zero_latlon_sentinel_stripped(self):
        posts = dict(self.mapper.handle(
            TOPIC, position_event(latitude_i=0, longitude_i=0)))
        pos = posts["/api/positions"]
        for key in ("latitude", "longitude", "altitude", "location_source"):
            self.assertNotIn(key, pos)
        # a coordinate-less node position carries nothing useful either
        self.assertNotIn("latitude", posts["/api/nodes"]["!7efeee00"].get("position", {}))

    def test_single_axis_zero_survives(self):
        posts = dict(self.mapper.handle(TOPIC, position_event(latitude_i=0)))
        self.assertEqual(posts["/api/positions"]["latitude"], 0.0)
        self.assertAlmostEqual(posts["/api/positions"]["longitude"], 13.37, places=6)

    def test_zero_time_sentinel_omitted(self):
        posts = dict(self.mapper.handle(TOPIC, position_event(time=0)))
        self.assertNotIn("position_time", posts["/api/positions"])


def telemetry_event(**payload_overrides):
    payload = {
        "battery_level": 87,
        "voltage": 4.01,
        "channel_utilization": 5.2,
        "air_util_tx": 1.1,
        "uptime_seconds": 3600,
    }
    payload.update(payload_overrides)
    return text_event(type="telemetry", payload=payload)


class MapperTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.mapper = plug.Mapper(plug.load_config(base_cfg()), now_fn=lambda: 1700000000)

    def test_device_telemetry_maps(self):
        posts = dict(self.mapper.handle(TOPIC, telemetry_event()))
        tel = posts["/api/telemetry"]
        self.assertEqual(tel["node_id"], "!7efeee00")
        self.assertEqual(tel["battery_level"], 87)
        self.assertEqual(tel["voltage"], 4.01)
        self.assertEqual(tel["uptime_seconds"], 3600)
        self.assertEqual(tel["payload_b64"], "")
        node = posts["/api/nodes"]["!7efeee00"]
        self.assertEqual(node["deviceMetrics"]["batteryLevel"], 87)
        self.assertEqual(node["deviceMetrics"]["uptimeSeconds"], 3600)

    def test_environment_telemetry_passthrough_no_node_metrics(self):
        posts = dict(self.mapper.handle(
            TOPIC, text_event(type="telemetry",
                              payload={"temperature": 21.5, "relative_humidity": 40.0})))
        self.assertEqual(posts["/api/telemetry"]["temperature"], 21.5)
        self.assertNotIn("deviceMetrics", posts.get("/api/nodes", {}).get("!7efeee00", {}))

    def test_air_quality_and_power_key_mapping(self):
        posts = dict(self.mapper.handle(
            TOPIC, text_event(type="telemetry",
                              payload={"pm10": 3, "pm25": 5, "pm100": 7,
                                       "voltage_ch1": 3.3, "current_ch2": 12.5})))
        tel = posts["/api/telemetry"]
        self.assertEqual(tel["pm10_standard"], 3)
        self.assertEqual(tel["pm25_standard"], 5)
        self.assertEqual(tel["pm100_standard"], 7)
        self.assertEqual(tel["ch1_voltage"], 3.3)
        self.assertEqual(tel["ch2_current"], 12.5)

    def test_unknown_metric_keys_dropped(self):
        posts = dict(self.mapper.handle(
            TOPIC, text_event(type="telemetry", payload={"bogus_metric": 1,
                                                         "voltage": 3.7})))
        tel = posts["/api/telemetry"]
        self.assertNotIn("bogus_metric", tel)
        self.assertEqual(tel["voltage"], 3.7)


def nodeinfo_event(**payload_overrides):
    payload = {
        "id": "!7efeee00",
        "longname": "base0",
        "shortname": "BA0",
        "hardware": 10,
        "role": 1,
    }
    payload.update(payload_overrides)
    return text_event(type="nodeinfo", payload=payload)


class MapperNodeinfoTests(unittest.TestCase):
    def setUp(self):
        self.mapper = plug.Mapper(plug.load_config(base_cfg()), now_fn=lambda: 1700000000)

    def test_nodeinfo_maps_to_nodes_post(self):
        posts = self.mapper.handle(TOPIC, nodeinfo_event())
        self.assertEqual(len(posts), 1)
        path, payload = posts[0]
        self.assertEqual(path, "/api/nodes")
        self.assertEqual(payload["protocol"], "meshtastic")
        self.assertEqual(payload["ingestor"], "!aabbccdd")
        entry = payload["!7efeee00"]
        self.assertEqual(entry["num"], 0x7EFEEE00)
        self.assertEqual(entry["lastHeard"], 1646832724)
        self.assertEqual(entry["snr"], 5.75)
        self.assertEqual(entry["hopsAway"], 2)
        self.assertEqual(entry["user"]["shortName"], "BA0")
        self.assertEqual(entry["user"]["longName"], "base0")
        # int hardware/role codes are firmware-enum values we deliberately
        # don't map to names; the contract's user fields are optional.
        self.assertNotIn("hwModel", entry["user"])
        self.assertNotIn("role", entry["user"])

    def test_node_aggregates_across_events(self):
        self.mapper.handle(TOPIC, nodeinfo_event())
        posts = dict(self.mapper.handle(TOPIC, position_event()))
        entry = posts["/api/nodes"]["!7efeee00"]
        self.assertEqual(entry["user"]["shortName"], "BA0")
        self.assertIn("position", entry)


class PosterTests(unittest.TestCase):
    def test_posts_json_with_bearer(self):
        seen = {}

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["auth"] = req.get_header("Authorization")
            seen["ctype"] = req.get_header("Content-type")
            seen["body"] = json.loads(req.data)
            seen["timeout"] = timeout

            class Resp:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def read(self):
                    return b"{}"

            return Resp()

        poster = plug.Poster("https://potato.example.org", "sekrit",
                             urlopen=fake_urlopen)
        ok = poster.post("/api/messages", {"id": 1})
        self.assertTrue(ok)
        self.assertEqual(seen["url"], "https://potato.example.org/api/messages")
        self.assertEqual(seen["auth"], "Bearer sekrit")
        self.assertEqual(seen["ctype"], "application/json")
        self.assertEqual(seen["body"], {"id": 1})
        self.assertEqual(seen["timeout"], 10)

    def test_failure_returns_false_and_counts(self):
        def failing_urlopen(req, timeout=None):
            raise OSError("connection refused")

        poster = plug.Poster("https://x", "t", urlopen=failing_urlopen)
        self.assertFalse(poster.post("/api/messages", {"id": 1}))
        self.assertEqual(poster.failures, 1)
        self.assertEqual(poster.posted, 0)


class BridgeTests(unittest.TestCase):
    def test_send_rejected_as_ingest_only(self):
        sock = FakeSock()
        bridge = plug.Bridge(sock)
        bridge.handle_send({"t": "send", "corr": "c1", "endpoint": "x", "body": "hi"})
        frames = sock.frames()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["t"], "delivery_result")
        self.assertEqual(frames[0]["corr"], "c1")
        self.assertFalse(frames[0]["delivered"])


if __name__ == "__main__":
    unittest.main()
