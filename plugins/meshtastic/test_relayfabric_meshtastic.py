import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lxmf"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "signal"))

import relayfabric_meshtastic as plug


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {
                "primary": {"index": 0, "topic_channel": "ch-0"}
            }
        })
        self.assertEqual(cfg["broker"], "localhost")
        self.assertEqual(cfg["topic_root"], "msh")
        self.assertIsNone(cfg["gateway_id"])
        self.assertEqual(cfg["max_text_bytes"], 200)

    def test_required_fields(self):
        # Missing broker
        with self.assertRaises(ValueError):
            plug.load_config({
                "topic_root": "msh",
                "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}}
            })
        # Missing topic_root
        with self.assertRaises(ValueError):
            plug.load_config({
                "broker": "localhost",
                "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}}
            })
        # Missing channels
        with self.assertRaises(ValueError):
            plug.load_config({
                "broker": "localhost",
                "topic_root": "msh"
            })
        # Empty channels
        with self.assertRaises(ValueError):
            plug.load_config({
                "broker": "localhost",
                "topic_root": "msh",
                "channels": {}
            })

    def test_channel_missing_index(self):
        with self.assertRaises(ValueError):
            plug.load_config({
                "broker": "localhost",
                "topic_root": "msh",
                "channels": {
                    "primary": {"topic_channel": "ch-0"}  # missing index
                }
            })

    def test_channel_missing_topic_channel(self):
        with self.assertRaises(ValueError):
            plug.load_config({
                "broker": "localhost",
                "topic_root": "msh",
                "channels": {
                    "primary": {"index": 0}  # missing topic_channel
                }
            })

    def test_channel_index_not_int(self):
        with self.assertRaises(TypeError):
            plug.load_config({
                "broker": "localhost",
                "topic_root": "msh",
                "channels": {
                    "primary": {"index": "0", "topic_channel": "ch-0"}
                }
            })

    def test_gateway_id_override(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}},
            "gateway_id": "!12345678"
        })
        self.assertEqual(cfg["gateway_id"], "!12345678")

    def test_max_text_bytes_override(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}},
            "max_text_bytes": 500
        })
        self.assertEqual(cfg["max_text_bytes"], 500)

    def test_channels_dict_copied(self):
        raw_channels = {"primary": {"index": 0, "topic_channel": "ch-0"}}
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": raw_channels
        })
        # Modifying raw_channels should not affect cfg
        raw_channels["primary"]["index"] = 99
        self.assertEqual(cfg["channels"]["primary"]["index"], 0)


class ChannelsByIndexTests(unittest.TestCase):
    def test_maps_index_to_name(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {
                "primary": {"index": 0, "topic_channel": "ch-0"},
                "secondary": {"index": 1, "topic_channel": "ch-1"}
            }
        })
        by_index = plug.channels_by_index(cfg)
        self.assertEqual(by_index[0], "primary")
        self.assertEqual(by_index[1], "secondary")

    def test_empty_channels(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {
                "solo": {"index": 5, "topic_channel": "ch-5"}
            }
        })
        by_index = plug.channels_by_index(cfg)
        self.assertEqual(len(by_index), 1)
        self.assertEqual(by_index[5], "solo")


class ParserTests(unittest.TestCase):
    def test_text_ok(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}}
        })
        by_index = plug.channels_by_index(cfg)
        result = plug.parse_uplink(
            "msh/2/json/ch-0/!12345678",
            {
                "type": "text",
                "payload": {"text": "hello"},
                "channel": 0,
                "sender": "!abcdef01",
                "timestamp": 1755280000
            },
            by_index,
            "!12345678"
        )
        self.assertIsNotNone(result)
        name, sender, text, ts = result
        self.assertEqual(name, "primary")
        self.assertEqual(sender, "!abcdef01")
        self.assertEqual(text, "hello")
        self.assertEqual(ts, 1755280000)

    def test_position_dropped(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}}
        })
        by_index = plug.channels_by_index(cfg)
        result = plug.parse_uplink(
            "msh/2/json/ch-0/!12345678",
            {
                "type": "position",
                "channel": 0,
                "sender": "!abcdef01",
                "timestamp": 1755280000
            },
            by_index,
            "!12345678"
        )
        self.assertIsNone(result)

    def test_unmapped_channel(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}}
        })
        by_index = plug.channels_by_index(cfg)
        result = plug.parse_uplink(
            "msh/2/json/ch-0/!12345678",
            {
                "type": "text",
                "payload": {"text": "hello"},
                "channel": 5,  # unmapped
                "sender": "!abcdef01",
                "timestamp": 1755280000
            },
            by_index,
            "!12345678"
        )
        self.assertIsNone(result)

    def test_gateway_filter_hit(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}},
            "gateway_id": "!12345678"
        })
        by_index = plug.channels_by_index(cfg)
        # Gateway filter matches
        result = plug.parse_uplink(
            "msh/2/json/ch-0/!12345678",
            {
                "type": "text",
                "payload": {"text": "hello"},
                "channel": 0,
                "sender": "!abcdef01",
                "timestamp": 1755280000
            },
            by_index,
            "!12345678"
        )
        self.assertIsNotNone(result)

    def test_gateway_filter_miss(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}},
            "gateway_id": "!12345678"
        })
        by_index = plug.channels_by_index(cfg)
        # Gateway filter mismatch
        result = plug.parse_uplink(
            "msh/2/json/ch-0/!87654321",
            {
                "type": "text",
                "payload": {"text": "hello"},
                "channel": 0,
                "sender": "!abcdef01",
                "timestamp": 1755280000
            },
            by_index,
            "!12345678"
        )
        self.assertIsNone(result)

    def test_gateway_id_none_no_filter(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}}
        })
        by_index = plug.channels_by_index(cfg)
        # Gateway ID is None, so no filtering
        result = plug.parse_uplink(
            "msh/2/json/ch-0/!87654321",
            {
                "type": "text",
                "payload": {"text": "hello"},
                "channel": 0,
                "sender": "!abcdef01",
                "timestamp": 1755280000
            },
            by_index,
            None
        )
        self.assertIsNotNone(result)

    def test_sender_fallback_from_from_field(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}}
        })
        by_index = plug.channels_by_index(cfg)
        result = plug.parse_uplink(
            "msh/2/json/ch-0/!12345678",
            {
                "type": "text",
                "payload": {"text": "hello"},
                "channel": 0,
                "from": 0xabcdef01,  # fallback when no sender
                "timestamp": 1755280000
            },
            by_index,
            "!12345678"
        )
        self.assertIsNotNone(result)
        _name, sender, _text, _ts = result
        self.assertEqual(sender, "!abcdef01")

    def test_sender_none_drop(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}}
        })
        by_index = plug.channels_by_index(cfg)
        result = plug.parse_uplink(
            "msh/2/json/ch-0/!12345678",
            {
                "type": "text",
                "payload": {"text": "hello"},
                "channel": 0,
                # no sender, no from
                "timestamp": 1755280000
            },
            by_index,
            "!12345678"
        )
        self.assertIsNone(result)

    def test_textless_dropped(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}}
        })
        by_index = plug.channels_by_index(cfg)
        result = plug.parse_uplink(
            "msh/2/json/ch-0/!12345678",
            {
                "type": "text",
                "payload": {},  # missing text
                "channel": 0,
                "sender": "!abcdef01",
                "timestamp": 1755280000
            },
            by_index,
            "!12345678"
        )
        self.assertIsNone(result)

    def test_empty_text_dropped(self):
        cfg = plug.load_config({
            "broker": "localhost",
            "topic_root": "msh",
            "channels": {"primary": {"index": 0, "topic_channel": "ch-0"}}
        })
        by_index = plug.channels_by_index(cfg)
        result = plug.parse_uplink(
            "msh/2/json/ch-0/!12345678",
            {
                "type": "text",
                "payload": {"text": ""},
                "channel": 0,
                "sender": "!abcdef01",
                "timestamp": 1755280000
            },
            by_index,
            "!12345678"
        )
        self.assertIsNone(result)


class SentCacheSmokeTests(unittest.TestCase):
    def test_sent_cache_import(self):
        from relayfabric_signal import SentCache
        c = SentCache(ttl_secs=60)
        c.record("test_group", "test_body")
        self.assertTrue(c.match("test_group", "test_body"))
        self.assertFalse(c.match("test_group", "test_body"))


if __name__ == "__main__":
    unittest.main()
