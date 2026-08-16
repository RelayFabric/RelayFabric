import os
import queue
import sys
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lxmf"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "signal"))

import relayfabric_meshcore as plug


def _stop_and_close_loop(loop):
    """Test-only cleanup for a MeshCoreBackend's private event loop: stop()
    is scheduled onto the loop thread asynchronously, so poll briefly for it
    to actually take effect before close() -- closing a still-running loop
    raises, and never closing it emits a ResourceWarning at GC time."""
    loop.call_soon_threadsafe(loop.stop)
    deadline = time.time() + 2
    while loop.is_running() and time.time() < deadline:
        time.sleep(0.01)
    if not loop.is_running():
        loop.close()


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

    def test_sender_channel_keyed_format(self):
        # normalize_event presents sender as given by the Backend: the
        # Backend synthesizes "mc:channel:<idx>" (channel-scoped, not a
        # per-node identity -- see channel_event_to_dict), and
        # normalize_event just passes that string through unchanged.
        ev = {
            "kind": "channel_msg",
            "channel_idx": 0,
            "sender": "mc:channel:0",
            "text": "test",
            "ts": 1234567890
        }
        result = plug.normalize_event(ev, self.by_index)
        self.assertIsNotNone(result)
        _name, sender, _text, _ts = result
        self.assertEqual(sender, "mc:channel:0")


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


class ChannelEventToDictTests(unittest.TestCase):
    """channel_event_to_dict is a pure function over a meshcore
    CHANNEL_MSG_RECV Event.payload dict -- testable without importing
    meshcore (see module docstring: no meshcore/cbor2 required)."""

    def test_normalizes_payload(self):
        payload = {"channel_idx": 2, "text": "hello", "sender_timestamp": 1700000000}
        ev = plug.channel_event_to_dict(payload)
        self.assertEqual(ev["kind"], "channel_msg")
        self.assertEqual(ev["channel_idx"], 2)
        self.assertEqual(ev["text"], "hello")
        self.assertEqual(ev["ts"], 1700000000)
        self.assertEqual(ev["sender"], "mc:channel:2")

    def test_sender_is_channel_keyed_not_per_message(self):
        # Two different messages on the same channel (different
        # sender_timestamp and text) must produce the SAME sender: MeshCore
        # PSK channels carry no per-node identity, so a per-message value
        # (e.g. one derived from sender_timestamp) would look like a
        # per-node id but isn't one, and would silently defeat the daemon's
        # per-sender rate limiting (fresh key every message => limits never
        # trigger) and alias stability (a new alias every message). Keying
        # on channel_idx instead means quotas/aliases operate at CHANNEL
        # granularity -- the same trade-off the mqtt plugin makes with its
        # topic-as-sender.
        first = plug.channel_event_to_dict(
            {"channel_idx": 0, "text": "hi", "sender_timestamp": 1})
        second = plug.channel_event_to_dict(
            {"channel_idx": 0, "text": "bye", "sender_timestamp": 999})
        self.assertEqual(first["sender"], second["sender"])
        self.assertEqual(first["sender"], "mc:channel:0")

    def test_missing_timestamp_still_produces_channel_sender(self):
        payload = {"channel_idx": 0, "text": "hi"}
        ev = plug.channel_event_to_dict(payload)
        self.assertEqual(ev["sender"], "mc:channel:0")
        self.assertIsNone(ev["ts"])


class MeshCoreBackendTests(unittest.TestCase):
    """MeshCoreBackend tests that don't require importing meshcore: __init__
    only calls parse_connection (module-level pure helper); start() is the
    only method that lazily imports meshcore, so it's exercised only in the
    manual field test (see README), not here."""

    def test_init_accepts_valid_connection_url(self):
        backend = plug.MeshCoreBackend("serial:///dev/ttyUSB0")
        self.assertEqual(backend.connection_url, "serial:///dev/ttyUSB0")

    def test_init_rejects_bad_connection_url(self):
        with self.assertRaises(ValueError):
            plug.MeshCoreBackend("http://nope")

    def test_send_channel_before_start_raises_runtime_error(self):
        backend = plug.MeshCoreBackend("serial:///dev/ttyUSB0")
        with self.assertRaises(RuntimeError):
            backend.send_channel(0, "hi")

    def test_on_channel_msg_normalizes_and_queues(self):
        backend = plug.MeshCoreBackend("serial:///dev/ttyUSB0")
        fake_event = types.SimpleNamespace(
            payload={"channel_idx": 0, "text": "hi", "sender_timestamp": 1700000000}
        )
        backend._on_channel_msg(fake_event)
        ev = backend._queue.get_nowait()
        self.assertEqual(ev, {
            "kind": "channel_msg", "channel_idx": 0, "text": "hi",
            "ts": 1700000000, "sender": "mc:channel:0",
        })

    def test_on_channel_msg_drops_without_raising_when_queue_full(self):
        backend = plug.MeshCoreBackend("serial:///dev/ttyUSB0")
        backend._queue = queue.Queue(maxsize=1)
        backend._queue.put(plug.channel_event_to_dict(
            {"channel_idx": 0, "text": "first", "sender_timestamp": 1}))
        fake_event = types.SimpleNamespace(
            payload={"channel_idx": 0, "text": "second", "sender_timestamp": 2}
        )
        backend._on_channel_msg(fake_event)  # must not raise/block on Full
        self.assertEqual(backend._queue.qsize(), 1)
        self.assertEqual(backend._queue.get_nowait()["text"], "first")

    def test_events_yields_from_queue(self):
        backend = plug.MeshCoreBackend("serial:///dev/ttyUSB0")
        backend._queue.put({"kind": "channel_msg", "channel_idx": 0,
                             "sender": "mc:1", "text": "hi", "ts": 1})
        gen = backend.events()
        self.assertEqual(next(gen)["text"], "hi")

    def test_queue_is_bounded(self):
        backend = plug.MeshCoreBackend("serial:///dev/ttyUSB0")
        self.assertEqual(backend._queue.maxsize, 256)

    def test_on_disconnected_exits_process(self):
        # auto_reconnect is off, so a dropped radio connection is permanent;
        # os._exit(1), not sys.exit, because this callback runs on the
        # backend's loop thread while main() blocks in read_frame() on the
        # main thread (see _on_disconnected's comment). Patch os._exit so
        # the test process doesn't actually die.
        backend = plug.MeshCoreBackend("serial:///dev/ttyUSB0")
        fake_event = types.SimpleNamespace(payload={"reason": "unknown"})
        with mock.patch.object(plug.os, "_exit") as fake_exit:
            backend._on_disconnected(fake_event)
        fake_exit.assert_called_once_with(1)

    def test_start_timeout_raises_runtime_error(self):
        # ready.wait(timeout=30)'s return value must be checked: a timeout
        # (e.g. a slow BLE scan) previously returned silently, leaving
        # self._mc None forever -- a distinct, invisible dead-plugin mode.
        backend = plug.MeshCoreBackend("serial:///dev/ttyUSB0")
        fake_ready = mock.Mock()
        fake_ready.wait.return_value = False
        with mock.patch.object(plug.threading, "Event", return_value=fake_ready), \
             mock.patch.object(plug.threading, "Thread") as fake_thread_cls:
            fake_thread_cls.return_value = mock.Mock()
            with self.assertRaises(RuntimeError):
                backend.start()
        self.addCleanup(backend._loop.close)

    def test_start_calls_start_auto_message_fetching_and_subscribes_disconnected(self):
        # The Companion protocol is pull-based: CHANNEL_MSG_RECV frames are
        # replies to CMD_SYNC_NEXT_MESSAGE, driven by
        # start_auto_message_fetching()'s MESSAGES_WAITING drain loop --
        # connect() alone never triggers it, so this call is required for
        # inbound to work at all against real hardware. Injects a stub
        # "meshcore" module via sys.modules (never a real import), so this
        # runs without the meshcore package installed, per the module's
        # no-meshcore-import-in-tests constraint.
        calls = []

        class FakeCommands:
            async def send_chan_msg(self, chan, msg, timestamp=None):
                raise NotImplementedError

        class FakeMC:
            def __init__(self):
                self.commands = FakeCommands()
                self.subs = []

            def subscribe(self, event_type, callback):
                self.subs.append(event_type)

            async def start_auto_message_fetching(self):
                calls.append("start_auto_message_fetching")

        async def fake_create_serial(port, baudrate=115200, **kw):
            return FakeMC()

        fake_module = types.ModuleType("meshcore")
        fake_module.MeshCore = types.SimpleNamespace(create_serial=fake_create_serial)
        fake_module.EventType = types.SimpleNamespace(
            CHANNEL_MSG_RECV="channel_message", DISCONNECTED="disconnected")

        with mock.patch.dict(sys.modules, {"meshcore": fake_module}):
            backend = plug.MeshCoreBackend("serial:///dev/ttyUSB0")
            backend.start()

        self.addCleanup(_stop_and_close_loop, backend._loop)
        self.assertEqual(calls, ["start_auto_message_fetching"])
        self.assertIn(fake_module.EventType.CHANNEL_MSG_RECV, backend._mc.subs)
        self.assertIn(fake_module.EventType.DISCONNECTED, backend._mc.subs)


def base_cfg(**overrides):
    cfg = {
        "connection": "serial:///dev/ttyUSB0",
        "channels": {
            "primary": {"index": 0},
            "secondary": {"index": 1},
        },
    }
    cfg.update(overrides)
    return plug.load_config(cfg)


def channel_event(text="hello", channel_idx=0, sender=None, ts=1755280000):
    # default sender mirrors what channel_event_to_dict actually produces
    # (channel-keyed, not per-message) so Bridge fixtures stay realistic.
    if sender is None:
        sender = f"mc:channel:{channel_idx}"
    return {"kind": "channel_msg", "channel_idx": channel_idx, "sender": sender,
            "text": text, "ts": ts}


class FakeBackend:
    """Captures channel sends; events() replays a scripted list of
    already-normalized event dicts, the shape MeshCoreBackend.events() would
    yield after channel_event_to_dict()."""

    def __init__(self, scripted_events=None):
        self.sent = []
        self.fail_with = None
        self._scripted = scripted_events or []

    def send_channel(self, idx, text):
        if self.fail_with:
            raise self.fail_with
        self.sent.append((idx, text))

    def events(self):
        yield from self._scripted


class FakeSock:
    """Captures frames the bridge writes to the daemon.

    Copied from plugins/meshtastic/test_relayfabric_meshtastic.py's FakeSock
    (itself copied from plugins/signal's, same write-lock/_send_frame shape)
    rather than imported, per house style of not sharing test code across
    plugins.
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

    def test_sent_cache_ttl_is_one_hour(self):
        # design mandate: 1h, not SentCache's 86400s default (mirrors
        # meshtastic's radio-echo loop guard window).
        self.assertEqual(self.bridge.sent_cache.ttl, 3600)

    def test_inbound_mapped_channel_bridges(self):
        self.bridge.handle_event(channel_event())
        frames = self.sock.frames()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["t"], "inbound")
        self.assertEqual(frames[0]["endpoint"], "primary")
        self.assertEqual(frames[0]["sender"], "mc:channel:0")
        self.assertEqual(frames[0]["body"], "hello")

    def test_deny_unmapped_channel_dropped(self):
        self.bridge.handle_event(channel_event(channel_idx=9))
        self.assertEqual(self.sock.frames(), [])

    def test_deny_non_channel_msg_dropped(self):
        ev = {"kind": "advert", "channel_idx": 0, "sender": "mc:channel:0",
              "text": "hello", "ts": 1}
        self.bridge.handle_event(ev)
        self.assertEqual(self.sock.frames(), [])

    def test_loop_guard_drops_reechoed_own_text(self):
        # our own downlink send records (endpoint, body) in the loop guard
        self.bridge.handle_send({"corr": 1, "endpoint": "primary", "body": "out"})
        self.assertEqual(len(self.sock.frames()), 1)  # only the delivery_result
        # the radio (or firmware) echoes our own send back as a channel_msg
        self.bridge.handle_event(channel_event(text="out"))
        self.assertEqual(len(self.sock.frames()), 1)  # still just the delivery_result

    def test_loop_guard_different_text_still_flows(self):
        self.bridge.handle_send({"corr": 1, "endpoint": "primary", "body": "out"})
        self.bridge.handle_event(channel_event(text="different"))
        frames = self.sock.frames()
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[-1]["t"], "inbound")
        self.assertEqual(frames[-1]["body"], "different")

    def test_send_channel_call_args(self):
        self.bridge.handle_send({"corr": 2, "endpoint": "secondary", "body": "ping"})
        self.assertEqual(self.backend.sent, [(1, "ping")])

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
        self.assertEqual(self.backend.sent, [])

    def test_send_backend_failure_delivered_false_with_detail(self):
        self.backend.fail_with = RuntimeError("radio busy")
        self.bridge.handle_send({"corr": 5, "endpoint": "primary", "body": "hi"})
        frames = self.sock.frames()
        self.assertFalse(frames[-1]["delivered"])
        self.assertIn("radio busy", frames[-1]["detail"])

    def test_send_failure_does_not_poison_loop_guard(self):
        # A failed send must not record into SentCache: it never actually
        # went out over the radio, so a later channel_msg of the same text
        # is a real (not echoed) message and must still bridge.
        self.backend.fail_with = RuntimeError("radio busy")
        self.bridge.handle_send({"corr": 5, "endpoint": "primary", "body": "out"})
        self.backend.fail_with = None
        self.bridge.handle_event(channel_event(text="out"))
        frames = self.sock.frames()
        self.assertEqual(len(frames), 2)  # failed delivery_result + inbound
        self.assertEqual(frames[-1]["t"], "inbound")
        self.assertEqual(frames[-1]["body"], "out")

    def test_oversize_body_defensive_drop(self):
        cfg = base_cfg(max_text_bytes=5)
        bridge = plug.Bridge(cfg, self.backend, self.sock)
        bridge.handle_send({"corr": 6, "endpoint": "primary", "body": "way too long"})
        frames = self.sock.frames()
        self.assertFalse(frames[-1]["delivered"])
        self.assertIsNotNone(frames[-1]["detail"])
        self.assertEqual(self.backend.sent, [])


if __name__ == "__main__":
    unittest.main()
