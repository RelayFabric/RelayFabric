import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "signal"))

import relayfabric_meshcore as plug


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = plug.load_config({
            "connection": "serial:///dev/ttyUSB0",
            "channels": {
                "primary": {"index": 0}
            }
        })
        self.assertEqual(cfg["connection"], "serial:///dev/ttyUSB0")
        self.assertEqual(cfg["max_text_bytes"], 160)

    def test_required_connection(self):
        # Missing connection
        with self.assertRaises(ValueError):
            plug.load_config({
                "channels": {"primary": {"index": 0}}
            })

    def test_required_channels(self):
        # Missing channels
        with self.assertRaises(ValueError):
            plug.load_config({
                "connection": "serial:///dev/ttyUSB0"
            })

    def test_empty_channels(self):
        # Empty channels dict
        with self.assertRaises(ValueError):
            plug.load_config({
                "connection": "serial:///dev/ttyUSB0",
                "channels": {}
            })

    def test_channel_missing_index(self):
        with self.assertRaises(ValueError):
            plug.load_config({
                "connection": "serial:///dev/ttyUSB0",
                "channels": {
                    "primary": {}  # missing index
                }
            })

    def test_channel_index_not_int(self):
        with self.assertRaises(TypeError):
            plug.load_config({
                "connection": "serial:///dev/ttyUSB0",
                "channels": {
                    "primary": {"index": "0"}
                }
            })

    def test_max_text_bytes_not_int(self):
        with self.assertRaises(TypeError):
            plug.load_config({
                "connection": "serial:///dev/ttyUSB0",
                "channels": {"primary": {"index": 0}},
                "max_text_bytes": "160"
            })

    def test_max_text_bytes_override(self):
        cfg = plug.load_config({
            "connection": "serial:///dev/ttyUSB0",
            "channels": {"primary": {"index": 0}},
            "max_text_bytes": 100
        })
        self.assertEqual(cfg["max_text_bytes"], 100)

    def test_connection_not_string(self):
        with self.assertRaises(TypeError):
            plug.load_config({
                "connection": 123,
                "channels": {"primary": {"index": 0}}
            })

    def test_channels_dict_copied(self):
        raw_channels = {"primary": {"index": 0}}
        cfg = plug.load_config({
            "connection": "serial:///dev/ttyUSB0",
            "channels": raw_channels
        })
        # Modifying raw_channels should not affect cfg
        raw_channels["primary"]["index"] = 99
        self.assertEqual(cfg["channels"]["primary"]["index"], 0)


class ChannelsByIndexTests(unittest.TestCase):
    def test_maps_index_to_name(self):
        cfg = plug.load_config({
            "connection": "serial:///dev/ttyUSB0",
            "channels": {
                "primary": {"index": 0},
                "secondary": {"index": 1}
            }
        })
        by_index = plug.channels_by_index(cfg)
        self.assertEqual(by_index[0], "primary")
        self.assertEqual(by_index[1], "secondary")

    def test_sparse_channel_indices(self):
        cfg = plug.load_config({
            "connection": "serial:///dev/ttyUSB0",
            "channels": {
                "solo": {"index": 5}
            }
        })
        by_index = plug.channels_by_index(cfg)
        self.assertEqual(len(by_index), 1)
        self.assertEqual(by_index[5], "solo")


class ParseConnectionTests(unittest.TestCase):
    def test_serial_no_baud(self):
        kind, target, opts = plug.parse_connection("serial:///dev/ttyUSB0")
        self.assertEqual(kind, "serial")
        self.assertEqual(target, "/dev/ttyUSB0")
        self.assertEqual(opts["baud"], 115200)

    def test_serial_with_baud(self):
        kind, target, opts = plug.parse_connection("serial:///dev/ttyUSB0?baud=9600")
        self.assertEqual(kind, "serial")
        self.assertEqual(target, "/dev/ttyUSB0")
        self.assertEqual(opts["baud"], 9600)

    def test_serial_bad_baud_value(self):
        with self.assertRaises(ValueError):
            plug.parse_connection("serial:///dev/ttyUSB0?baud=abc")

    def test_serial_no_path(self):
        with self.assertRaises(ValueError):
            plug.parse_connection("serial://")

    def test_tcp_valid(self):
        kind, target, opts = plug.parse_connection("tcp://192.168.1.1:5000")
        self.assertEqual(kind, "tcp")
        self.assertEqual(target, ("192.168.1.1", 5000))
        self.assertEqual(opts, {})

    def test_tcp_hostname(self):
        kind, target, _opts = plug.parse_connection("tcp://localhost:8080")
        self.assertEqual(kind, "tcp")
        self.assertEqual(target, ("localhost", 8080))

    def test_tcp_no_port(self):
        with self.assertRaises(ValueError):
            plug.parse_connection("tcp://192.168.1.1")

    def test_tcp_no_host(self):
        with self.assertRaises(ValueError):
            plug.parse_connection("tcp://:5000")

    def test_ble_valid(self):
        kind, target, opts = plug.parse_connection("ble://AA:BB:CC:DD:EE:FF")
        self.assertEqual(kind, "ble")
        self.assertEqual(target, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(opts, {})

    def test_ble_no_addr(self):
        with self.assertRaises(ValueError):
            plug.parse_connection("ble://")

    def test_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            plug.parse_connection("http://example.com")

    def test_unsupported_scheme_message(self):
        with self.assertRaises(ValueError) as cm:
            plug.parse_connection("http://example.com")
        self.assertIn("unsupported connection scheme", str(cm.exception))
        self.assertIn("serial", str(cm.exception))
        self.assertIn("tcp", str(cm.exception))
        self.assertIn("ble", str(cm.exception))


class NormalizeEventTests(unittest.TestCase):
    def setUp(self):
        cfg = plug.load_config({
            "connection": "serial:///dev/ttyUSB0",
            "channels": {
                "primary": {"index": 0},
                "secondary": {"index": 1}
            }
        })
        self.by_index = plug.channels_by_index(cfg)

    def test_valid_event(self):
        ev = {
            "kind": "channel_msg",
            "channel_idx": 0,
            "sender": "user1",
            "text": "hello",
            "ts": 1234567890
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNotNone(result)
        name, sender, text, ts = result
        self.assertEqual(name, "primary")
        self.assertEqual(sender, "user1")
        self.assertEqual(text, "hello")
        self.assertEqual(ts, 1234567890)

    def test_kind_not_channel_msg(self):
        ev = {
            "kind": "admin",
            "channel_idx": 0,
            "sender": "user1",
            "text": "hello",
            "ts": 1234567890
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNone(result)

    def test_missing_text(self):
        ev = {
            "kind": "channel_msg",
            "channel_idx": 0,
            "sender": "user1",
            "ts": 1234567890
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNone(result)

    def test_empty_text(self):
        ev = {
            "kind": "channel_msg",
            "channel_idx": 0,
            "sender": "user1",
            "text": "",
            "ts": 1234567890
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNone(result)

    def test_unmapped_channel_idx(self):
        ev = {
            "kind": "channel_msg",
            "channel_idx": 99,
            "sender": "user1",
            "text": "hello",
            "ts": 1234567890
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNone(result)

    def test_missing_channel_idx(self):
        ev = {
            "kind": "channel_msg",
            "sender": "user1",
            "text": "hello",
            "ts": 1234567890
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNone(result)

    def test_missing_sender(self):
        ev = {
            "kind": "channel_msg",
            "channel_idx": 0,
            "text": "hello",
            "ts": 1234567890
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNone(result)

    def test_optional_ts(self):
        ev = {
            "kind": "channel_msg",
            "channel_idx": 0,
            "sender": "user1",
            "text": "hello"
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNotNone(result)
        _name, _sender, _text, ts = result
        self.assertIsNone(ts)

    def test_secondary_channel(self):
        ev = {
            "kind": "channel_msg",
            "channel_idx": 1,
            "sender": "user2",
            "text": "world",
            "ts": 1234567891
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNotNone(result)
        name, sender, text, _ts = result
        self.assertEqual(name, "secondary")
        self.assertEqual(sender, "user2")
        self.assertEqual(text, "world")

    def test_sender_hex_format(self):
        ev = {
            "kind": "channel_msg",
            "channel_idx": 0,
            "sender": "mc:deadbeef",
            "text": "test",
            "ts": 1234567890
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNotNone(result)
        _name, sender, _text, _ts = result
        self.assertEqual(sender, "mc:deadbeef")


class HelloMaxPayloadTests(unittest.TestCase):
    """capabilities.max_payload = min(160, cfg["max_text_bytes"]): the
    advertised cap must stay independent of an operator's max_text_bytes
    override, so a misconfiguration can't disable both the daemon-side
    truncation and Bridge.handle_send's local defensive check at once."""

    def test_default_max_text_bytes_yields_160(self):
        cfg = plug.load_config({
            "connection": "serial:///dev/ttyUSB0",
            "channels": {"primary": {"index": 0}}
        })
        self.assertEqual(cfg["max_text_bytes"], 160)
        self.assertEqual(plug.hello_max_payload(cfg), 160)

    def test_higher_max_text_bytes_cannot_loosen_past_160(self):
        cfg = plug.load_config({
            "connection": "serial:///dev/ttyUSB0",
            "channels": {"primary": {"index": 0}},
            "max_text_bytes": 500
        })
        self.assertEqual(plug.hello_max_payload(cfg), 160)

    def test_lower_max_text_bytes_tightens_the_cap(self):
        cfg = plug.load_config({
            "connection": "serial:///dev/ttyUSB0",
            "channels": {"primary": {"index": 0}},
            "max_text_bytes": 100
        })
        self.assertEqual(plug.hello_max_payload(cfg), 100)


class SentCacheSmokeTests(unittest.TestCase):
    def test_sent_cache_import(self):
        from relayfabric_signal import SentCache
        c = SentCache(ttl_secs=60)
        c.record("test_group", "test_body")
        self.assertTrue(c.match("test_group", "test_body"))
        self.assertFalse(c.match("test_group", "test_body"))


if __name__ == "__main__":
    unittest.main()
