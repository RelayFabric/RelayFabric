import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sdk", "python"))

import relayfabric_meshtripwire as plug
from relayfabric_sdk import FakeSock


def base_cfg(**overrides):
    cfg = {"broker": "mqtt://localhost"}
    cfg.update(overrides)
    return cfg


class ConfigTests(unittest.TestCase):
    def test_requires_broker(self):
        with self.assertRaises(ValueError):
            plug.load_config({})

    def test_defaults(self):
        cfg = plug.load_config(base_cfg())
        self.assertEqual(cfg["topic"], "meshtripwire/alerts")
        self.assertEqual(cfg["endpoint"], "alerts")

    def test_broker_url_parsed(self):
        self.assertEqual(plug.parse_broker_url("mqtt://host:1884"), ("host", 1884))
        self.assertEqual(plug.parse_broker_url("mqtt://host"), ("host", 1883))
        with self.assertRaises(ValueError):
            plug.parse_broker_url("http://host")


class FormatTests(unittest.TestCase):
    def test_full_json(self):
        obj = {"mac": "AA:BB:CC:DD:EE:FF", "node": "gate1", "rssi": -58,
               "lat": 40.1, "lon": -74.2, "message": "ALERT: Unknown MAC"}
        out = plug.format_alert(obj)
        self.assertIn("AA:BB:CC:DD:EE:FF", out)
        self.assertIn("gate1", out)
        self.assertIn("-58", out)
        self.assertIn("40.1", out)
        self.assertIn("-74.2", out)

    def test_message_only(self):
        out = plug.format_alert({"message": "ALERT: Unknown MAC X at node Y"})
        self.assertIn("ALERT: Unknown MAC X at node Y", out)

    def test_mac_and_node_without_message(self):
        out = plug.format_alert({"mac": "AA:BB", "node": "gate1"})
        self.assertIn("AA:BB", out)
        self.assertIn("gate1", out)

    def test_raw_text_passthrough(self):
        # meshtripwire (or a generic producer) publishing a plain-text payload
        self.assertEqual(plug.format_alert("hello alert").strip(), "hello alert")

    def test_gps_only_partial_axis_omitted(self):
        out = plug.format_alert({"mac": "AA:BB", "lat": 40.1})  # no lon
        self.assertNotIn("maps", out.lower())

    def test_sender_uses_node(self):
        self.assertEqual(plug.alert_sender({"node": "gate1"}), "meshtripwire:gate1")
        self.assertEqual(plug.alert_sender({}), "meshtripwire")
        self.assertEqual(plug.alert_sender("raw text"), "meshtripwire")


class StubBackend:
    def queue_depth(self):
        return 0


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = plug.load_config(base_cfg())
        self.sock = FakeSock()
        self.bridge = plug.Bridge(self.cfg, self.sock, backend=StubBackend())

    def test_json_alert_emits_inbound(self):
        payload = json.dumps({"mac": "AA:BB", "node": "gate1",
                              "message": "ALERT: Unknown MAC AA:BB"}).encode()
        self.bridge.handle_message("meshtripwire/alerts", payload)
        frames = self.sock.frames()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["t"], "inbound")
        self.assertEqual(frames[0]["endpoint"], "alerts")
        self.assertEqual(frames[0]["sender"], "meshtripwire:gate1")
        self.assertIn("AA:BB", frames[0]["body"])

    def test_plain_text_alert_bridged(self):
        self.bridge.handle_message("meshtripwire/alerts", b"tripwire tripped")
        frames = self.sock.frames()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["body"].strip(), "tripwire tripped")
        self.assertEqual(frames[0]["sender"], "meshtripwire")

    def test_empty_payload_dropped(self):
        self.bridge.handle_message("meshtripwire/alerts", b"   ")
        self.assertEqual(self.sock.frames(), [])

    def test_send_is_rejected_ingest_only(self):
        self.bridge.handle_send({"corr": 7, "endpoint": "alerts", "body": "x"})
        frames = self.sock.frames()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["t"], "delivery_result")
        self.assertFalse(frames[0]["delivered"])


if __name__ == "__main__":
    unittest.main()
