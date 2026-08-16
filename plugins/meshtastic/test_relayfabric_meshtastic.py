import json
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


def base_cfg(**overrides):
    cfg = {
        "broker": "mqtt://localhost",
        "topic_root": "msh",
        "channels": {
            "primary": {"index": 0, "topic_channel": "ch-0"},
            "secondary": {"index": 1, "topic_channel": "ch-1"},
        },
    }
    cfg.update(overrides)
    return plug.load_config(cfg)


def text_event(text="hello", channel=0, sender="!abcdef01", ts=1755280000):
    return {"type": "text", "payload": {"text": text}, "channel": channel,
            "sender": sender, "timestamp": ts}


class FakeBackend:
    """Captures downlinks published via publish_downlink; events() replays a
    scripted list of (topic, event) tuples supplied by the test."""

    def __init__(self, scripted_events=None):
        self.published = []
        self.fail_with = None
        self._scripted = scripted_events or []

    def publish_downlink(self, obj):
        if self.fail_with:
            raise self.fail_with
        self.published.append(obj)

    def events(self):
        yield from self._scripted


class FakeSock:
    """Captures frames the bridge writes to the daemon.

    Copied from plugins/signal/test_relayfabric_signal.py's FakeSock (same
    write-lock/_send_frame shape as the signal Bridge) rather than imported,
    per house style of not sharing test code across plugins.
    """
    def __init__(self):
        import io
        self.buf = io.BytesIO()

    def write(self, data):
        self.buf.write(data)

    def flush(self):
        pass

    def frames(self):
        import io

        import relay_ipc
        out, rd = [], io.BytesIO(self.buf.getvalue())
        while True:
            try:
                out.append(relay_ipc.read_frame(rd))
            except EOFError:
                return out


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = base_cfg()
        self.backend = FakeBackend()
        self.sock = FakeSock()
        self.bridge = plug.Bridge(self.cfg, self.backend, self.sock)

    def test_inbound_mapped_channel_bridges(self):
        self.bridge.handle_event("msh/2/json/ch-0/!12345678", text_event())
        frames = self.sock.frames()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["t"], "inbound")
        self.assertEqual(frames[0]["endpoint"], "primary")
        self.assertEqual(frames[0]["sender"], "!abcdef01")
        self.assertEqual(frames[0]["body"], "hello")

    def test_deny_unmapped_channel_dropped(self):
        self.bridge.handle_event("msh/2/json/ch-9/!12345678", text_event(channel=9))
        self.assertEqual(self.sock.frames(), [])

    def test_deny_non_text_dropped(self):
        ev = {"type": "position", "channel": 0, "sender": "!abcdef01",
              "timestamp": 1755280000}
        self.bridge.handle_event("msh/2/json/ch-0/!12345678", ev)
        self.assertEqual(self.sock.frames(), [])

    def test_loop_guard_drops_reuplinked_own_text(self):
        # our own downlink send records (endpoint, body) in the loop guard
        self.bridge.handle_send({"corr": 1, "endpoint": "primary", "body": "out"})
        self.assertEqual(len(self.sock.frames()), 1)  # only the delivery_result
        # the node re-uplinks our own text verbatim on the same channel
        self.bridge.handle_event("msh/2/json/ch-0/!12345678", text_event(text="out"))
        self.assertEqual(len(self.sock.frames()), 1)  # still just the delivery_result

    def test_loop_guard_different_text_still_flows(self):
        self.bridge.handle_send({"corr": 1, "endpoint": "primary", "body": "out"})
        self.bridge.handle_event("msh/2/json/ch-0/!12345678", text_event(text="different"))
        frames = self.sock.frames()
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[-1]["t"], "inbound")
        self.assertEqual(frames[-1]["body"], "different")

    def test_downlink_payload_shape_and_channel_index(self):
        self.bridge.handle_send({"corr": 2, "endpoint": "secondary", "body": "ping"})
        self.assertEqual(self.backend.published, [
            {"from": 0, "channel": 1, "type": "sendtext", "payload": "ping"}
        ])

    def test_send_success_delivered_true(self):
        self.bridge.handle_send({"corr": 3, "endpoint": "primary", "body": "hi"})
        frames = self.sock.frames()
        self.assertEqual(frames[-1],
                         {"t": "delivery_result", "corr": 3,
                          "delivered": True, "detail": None})

    def test_send_unknown_endpoint_delivered_false(self):
        self.bridge.handle_send({"corr": 4, "endpoint": "nope", "body": "hi"})
        frames = self.sock.frames()
        self.assertFalse(frames[-1]["delivered"])
        self.assertEqual(self.backend.published, [])

    def test_send_backend_failure_delivered_false_with_detail(self):
        self.backend.fail_with = RuntimeError("broker down")
        self.bridge.handle_send({"corr": 5, "endpoint": "primary", "body": "hi"})
        frames = self.sock.frames()
        self.assertFalse(frames[-1]["delivered"])
        self.assertIn("broker down", frames[-1]["detail"])

    def test_oversize_body_defensive_drop(self):
        cfg = base_cfg(max_text_bytes=5)
        bridge = plug.Bridge(cfg, self.backend, self.sock)
        bridge.handle_send({"corr": 6, "endpoint": "primary", "body": "way too long"})
        frames = self.sock.frames()
        self.assertFalse(frames[-1]["delivered"])
        self.assertIsNotNone(frames[-1]["detail"])
        self.assertEqual(self.backend.published, [])


class MqttJsonBackendTests(unittest.TestCase):
    def test_parse_broker_default_port(self):
        backend = plug.MqttJsonBackend("mqtt://broker.local", "msh")
        self.assertEqual(backend._host, "broker.local")
        self.assertEqual(backend._port, 1883)

    def test_parse_broker_custom_port(self):
        backend = plug.MqttJsonBackend("mqtt://10.0.0.5:1884", "msh")
        self.assertEqual(backend._host, "10.0.0.5")
        self.assertEqual(backend._port, 1884)

    def test_parse_broker_rejects_non_mqtt_scheme(self):
        with self.assertRaises(ValueError):
            plug.MqttJsonBackend("http://broker.local", "msh")

    def test_on_message_valid_json_queued(self):
        backend = plug.MqttJsonBackend("mqtt://localhost", "msh")
        msg = type("Msg", (), {"topic": "msh/2/json/ch-0/!1", "payload": b'{"type": "text"}'})()
        backend._on_message(None, None, msg)
        topic, event = backend._queue.get_nowait()
        self.assertEqual(topic, "msh/2/json/ch-0/!1")
        self.assertEqual(event, {"type": "text"})

    def test_on_message_invalid_json_skipped(self):
        backend = plug.MqttJsonBackend("mqtt://localhost", "msh")
        msg = type("Msg", (), {"topic": "msh/2/json/ch-0/!1", "payload": b"not json"})()
        backend._on_message(None, None, msg)
        self.assertTrue(backend._queue.empty())

    def test_events_yields_from_queue(self):
        backend = plug.MqttJsonBackend("mqtt://localhost", "msh")
        backend._queue.put(("t", {"a": 1}))
        gen = backend.events()
        self.assertEqual(next(gen), ("t", {"a": 1}))

    def test_publish_downlink_raises_runtime_error_when_disconnected(self):
        backend = plug.MqttJsonBackend("mqtt://localhost", "msh")
        with self.assertRaises(RuntimeError):
            backend.publish_downlink({"from": 0, "channel": 0, "type": "sendtext",
                                       "payload": "hi"})

    def test_publish_downlink_uses_correct_topic_and_qos(self):
        from unittest import mock

        backend = plug.MqttJsonBackend("mqtt://localhost", "msh")
        info = mock.Mock()
        info.is_published.return_value = True
        backend._client.publish = mock.Mock(return_value=info)
        backend.publish_downlink({"from": 0, "channel": 0, "type": "sendtext",
                                   "payload": "hi"})
        args, kwargs = backend._client.publish.call_args
        self.assertEqual(args[0], "msh/2/json/mqtt/")
        self.assertEqual(json.loads(args[1]),
                         {"from": 0, "channel": 0, "type": "sendtext", "payload": "hi"})
        self.assertEqual(kwargs.get("qos"), 1)
        info.wait_for_publish.assert_called_once_with(timeout=30)


if __name__ == "__main__":
    unittest.main()
