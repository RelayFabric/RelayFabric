import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sdk", "python"))

import relayfabric_meshtastic_direct as plug
from relayfabric_sdk import FakeSock


def base_cfg(**overrides):
    cfg = {
        "connection": "serial:///dev/ttyUSB0",
        "channels": {"mesh": {"index": 0}, "tac": {"index": 1}},
    }
    cfg.update(overrides)
    return cfg


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = plug.load_config(base_cfg())
        self.assertEqual(cfg["max_text_bytes"], 200)
        self.assertEqual(cfg["channels"]["mesh"]["index"], 0)

    def test_required_connection(self):
        raw = base_cfg()
        del raw["connection"]
        with self.assertRaises(ValueError):
            plug.load_config(raw)

    def test_required_channels(self):
        with self.assertRaises(ValueError):
            plug.load_config({"connection": "serial:///dev/ttyUSB0"})
        with self.assertRaises(ValueError):
            plug.load_config({"connection": "serial:///dev/ttyUSB0", "channels": {}})

    def test_channel_index_must_be_int(self):
        with self.assertRaises(TypeError):
            plug.load_config(base_cfg(channels={"mesh": {"index": "0"}}))

    def test_channel_requires_index(self):
        with self.assertRaises(ValueError):
            plug.load_config(base_cfg(channels={"mesh": {}}))

    def test_channels_deep_copied(self):
        raw = base_cfg()
        cfg = plug.load_config(raw)
        cfg["channels"]["mesh"]["index"] = 99
        self.assertEqual(raw["channels"]["mesh"]["index"], 0)


class ParseConnectionTests(unittest.TestCase):
    def test_serial(self):
        self.assertEqual(plug.parse_connection("serial:///dev/ttyUSB0"),
                         ("serial", "/dev/ttyUSB0", {}))

    def test_tcp_default_port(self):
        self.assertEqual(plug.parse_connection("tcp://10.0.0.5"),
                         ("tcp", ("10.0.0.5", 4403), {}))

    def test_tcp_explicit_port(self):
        self.assertEqual(plug.parse_connection("tcp://10.0.0.5:4404"),
                         ("tcp", ("10.0.0.5", 4404), {}))

    def test_ble(self):
        self.assertEqual(plug.parse_connection("ble://AA:BB:CC:DD:EE:FF"),
                         ("ble", "AA:BB:CC:DD:EE:FF", {}))

    def test_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            plug.parse_connection("http://x")


class ChannelsByIndexTests(unittest.TestCase):
    def test_reverse_map(self):
        by_index = plug.channels_by_index(plug.load_config(base_cfg()))
        self.assertEqual(by_index, {0: "mesh", 1: "tac"})


def packet(**overrides):
    p = {
        "from": 0x7EFEEE00,
        "fromId": "!7efeee00",
        "to": 0xFFFFFFFF,
        "channel": 0,
        "rxTime": 1700000000,
        "rxSnr": 5.5,
        "rxRssi": -42,
        "decoded": {"portnum": "TEXT_MESSAGE_APP", "text": "hello mesh"},
    }
    p.update(overrides)
    return p


class NormalizeTests(unittest.TestCase):
    def setUp(self):
        self.by_index = plug.channels_by_index(plug.load_config(base_cfg()))

    def test_text_packet(self):
        r = plug.normalize_packet(packet(), self.by_index)
        self.assertEqual(r, ("mesh", "!7efeee00", "hello mesh", 1700000000))

    def test_channel_absent_defaults_to_primary(self):
        p = packet()
        del p["channel"]
        r = plug.normalize_packet(p, self.by_index)
        self.assertEqual(r[0], "mesh")

    def test_mapped_secondary_channel(self):
        r = plug.normalize_packet(packet(channel=1), self.by_index)
        self.assertEqual(r[0], "tac")

    def test_unmapped_channel_dropped(self):
        self.assertIsNone(plug.normalize_packet(packet(channel=7), self.by_index))

    def test_non_text_dropped(self):
        self.assertIsNone(plug.normalize_packet(
            packet(decoded={"portnum": "POSITION_APP"}), self.by_index))

    def test_empty_text_dropped(self):
        self.assertIsNone(plug.normalize_packet(
            packet(decoded={"portnum": "TEXT_MESSAGE_APP", "text": ""}), self.by_index))

    def test_sender_falls_back_to_from_hex_when_fromid_absent(self):
        p = packet()
        del p["fromId"]
        r = plug.normalize_packet(p, self.by_index)
        self.assertEqual(r[1], "!7efeee00")

    def test_no_sender_dropped(self):
        p = packet()
        del p["fromId"]
        del p["from"]
        self.assertIsNone(plug.normalize_packet(p, self.by_index))


class HelloMaxPayloadTests(unittest.TestCase):
    def test_hard_ceiling(self):
        self.assertEqual(plug.hello_max_payload(plug.load_config(base_cfg(max_text_bytes=500))), 237)

    def test_lower_config_tightens(self):
        self.assertEqual(plug.hello_max_payload(plug.load_config(base_cfg(max_text_bytes=100))), 100)


class FakeBackend:
    def __init__(self):
        self.sent = []
        self.qd = 0

    def send_channel(self, idx, text):
        self.sent.append((idx, text))

    def queue_depth(self):
        return self.qd


class BridgeTests(unittest.TestCase):
    def _bridge(self):
        sock = FakeSock()
        backend = FakeBackend()
        bridge = plug.Bridge(plug.load_config(base_cfg()), backend, sock)
        return bridge, backend, sock

    def test_inbound_bridges(self):
        bridge, _b, sock = self._bridge()
        bridge.handle_event(packet())
        frames = [f for f in sock.frames() if f["t"] == "inbound"]
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["endpoint"], "mesh")
        self.assertEqual(frames[0]["sender"], "!7efeee00")
        self.assertEqual(frames[0]["body"], "hello mesh")

    def test_send_delivers_by_index(self):
        bridge, backend, sock = self._bridge()
        bridge.handle_send({"t": "send", "corr": "c1", "endpoint": "tac", "body": "hi"})
        self.assertEqual(backend.sent, [(1, "hi")])
        dr = [f for f in sock.frames() if f["t"] == "delivery_result"][0]
        self.assertTrue(dr["delivered"])

    def test_send_unknown_endpoint(self):
        bridge, backend, sock = self._bridge()
        bridge.handle_send({"t": "send", "corr": "c2", "endpoint": "nope", "body": "hi"})
        self.assertEqual(backend.sent, [])
        dr = [f for f in sock.frames() if f["t"] == "delivery_result"][0]
        self.assertFalse(dr["delivered"])

    def test_echo_loop_guard(self):
        bridge, backend, sock = self._bridge()
        # our own downlink to "mesh" ...
        bridge.handle_send({"t": "send", "corr": "c3", "endpoint": "mesh", "body": "echo me"})
        # ... comes back as an uplink on the same channel and is suppressed
        bridge.handle_event(packet(decoded={"portnum": "TEXT_MESSAGE_APP", "text": "echo me"}))
        inbound = [f for f in sock.frames() if f["t"] == "inbound"]
        self.assertEqual(inbound, [])


if __name__ == "__main__":
    unittest.main()
