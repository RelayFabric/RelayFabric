import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sdk", "python"))

import relayfabric_xmpp as plug
from relayfabric_sdk import FakeSock


def base_cfg(**overrides):
    cfg = {
        "jid": "relay@example.com",
        "password": "secret",
        "channels": {
            "townsquare": {"muc": "townsquare@conference.example.com"},
            "ops": {"muc": "ops@conference.example.com"},
        },
    }
    cfg.update(overrides)
    return cfg


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = plug.load_config(base_cfg())
        self.assertEqual(cfg["nick"], "relayfabric")
        self.assertEqual(cfg["max_text_bytes"], 4000)

    def test_required_jid(self):
        raw = base_cfg()
        del raw["jid"]
        with self.assertRaises(ValueError):
            plug.load_config(raw)

    def test_required_password(self):
        raw = base_cfg()
        del raw["password"]
        with self.assertRaises(ValueError):
            plug.load_config(raw)

    def test_required_channels(self):
        with self.assertRaises(ValueError):
            plug.load_config({"jid": "a@b", "password": "p"})
        with self.assertRaises(ValueError):
            plug.load_config({"jid": "a@b", "password": "p", "channels": {}})

    def test_channel_requires_muc(self):
        with self.assertRaises(ValueError):
            plug.load_config(base_cfg(channels={"x": {}}))

    def test_channels_deep_copied(self):
        raw = base_cfg()
        cfg = plug.load_config(raw)
        cfg["channels"]["townsquare"]["muc"] = "mutated"
        self.assertEqual(raw["channels"]["townsquare"]["muc"],
                         "townsquare@conference.example.com")

    def test_max_text_bytes_must_be_int(self):
        with self.assertRaises(TypeError):
            plug.load_config(base_cfg(max_text_bytes="4000"))


class JidAndMapTests(unittest.TestCase):
    def test_valid_jids(self):
        self.assertTrue(plug.looks_like_jid("dana@example.com"))

    def test_invalid_jids(self):
        for bad in ["", "no-at", "a@b@c", "@domain", "local@", "has space@x"]:
            self.assertFalse(plug.looks_like_jid(bad), bad)

    def test_rooms_by_jid(self):
        m = plug.rooms_by_jid(plug.load_config(base_cfg()))
        self.assertEqual(m["townsquare@conference.example.com"], "townsquare")
        self.assertEqual(m["ops@conference.example.com"], "ops")


class FakeBackend:
    def __init__(self):
        self.muc_sends = []
        self.chat_sends = []
        self.stopped = 0

    def send_muc(self, room, text):
        self.muc_sends.append((room, text))

    def send_chat(self, jid, text):
        self.chat_sends.append((jid, text))

    def queue_depth(self):
        return 0

    def stop(self):
        self.stopped += 1


class BridgeTests(unittest.TestCase):
    def _bridge(self):
        sock = FakeSock()
        backend = FakeBackend()
        bridge = plug.Bridge(plug.load_config(base_cfg()), backend, sock)
        return bridge, backend, sock

    def test_inbound_muc_bridges_to_channel_endpoint(self):
        bridge, _b, sock = self._bridge()
        bridge.handle_event({"kind": "muc", "room": "townsquare@conference.example.com",
                             "sender": "dana", "text": "hello room"})
        frames = [f for f in sock.frames() if f["t"] == "inbound"]
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["endpoint"], "townsquare")
        self.assertEqual(frames[0]["sender"], "dana")
        self.assertEqual(frames[0]["body"], "hello room")

    def test_inbound_muc_from_unmapped_room_dropped(self):
        bridge, _b, sock = self._bridge()
        bridge.handle_event({"kind": "muc", "room": "other@conference.example.com",
                             "sender": "x", "text": "hi"})
        self.assertEqual([f for f in sock.frames() if f["t"] == "inbound"], [])

    def test_inbound_dm_uses_synthetic_direct_endpoint(self):
        bridge, _b, sock = self._bridge()
        bridge.handle_event({"kind": "chat", "from": "dana@example.com", "text": "psst"})
        frames = [f for f in sock.frames() if f["t"] == "inbound"]
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["endpoint"], "direct:dana@example.com")
        self.assertEqual(frames[0]["sender"], "dana@example.com")

    def test_send_delivers_to_room(self):
        bridge, backend, sock = self._bridge()
        bridge.handle_send({"t": "send", "corr": "c1", "endpoint": "ops", "body": "hi"})
        self.assertEqual(backend.muc_sends, [("ops@conference.example.com", "hi")])
        dr = [f for f in sock.frames() if f["t"] == "delivery_result"][0]
        self.assertTrue(dr["delivered"])

    def test_send_unknown_endpoint(self):
        bridge, backend, sock = self._bridge()
        bridge.handle_send({"t": "send", "corr": "c2", "endpoint": "nope", "body": "hi"})
        self.assertEqual(backend.muc_sends, [])
        dr = [f for f in sock.frames() if f["t"] == "delivery_result"][0]
        self.assertFalse(dr["delivered"])

    def test_echo_loop_guard(self):
        bridge, _b, sock = self._bridge()
        bridge.handle_send({"t": "send", "corr": "c3", "endpoint": "ops", "body": "echo me"})
        # the MUC reflects it back on the same room
        bridge.handle_event({"kind": "muc", "room": "ops@conference.example.com",
                             "sender": "someone", "text": "echo me"})
        self.assertEqual([f for f in sock.frames() if f["t"] == "inbound"], [])

    def test_send_direct_delivers_to_jid(self):
        bridge, backend, sock = self._bridge()
        bridge.handle_send_direct({"t": "send_direct", "corr": "d1",
                                   "native_ref": "dana@example.com", "body": "code 123456"})
        self.assertEqual(backend.chat_sends, [("dana@example.com", "code 123456")])
        dr = [f for f in sock.frames() if f["t"] == "delivery_result"][0]
        self.assertTrue(dr["delivered"])

    def test_send_direct_rejects_bad_jid(self):
        bridge, backend, sock = self._bridge()
        bridge.handle_send_direct({"t": "send_direct", "corr": "d2",
                                   "native_ref": "garbage", "body": "x"})
        self.assertEqual(backend.chat_sends, [])
        dr = [f for f in sock.frames() if f["t"] == "delivery_result"][0]
        self.assertFalse(dr["delivered"])
        self.assertEqual(dr["detail"], "invalid destination JID")

    def test_stop_releases_the_backend(self):
        bridge, backend, _sock = self._bridge()
        bridge.stop()
        self.assertEqual(backend.stopped, 1)

    def test_capabilities_advertise_groups_and_direct_messages(self):
        caps = plug._caps(base_cfg())
        self.assertTrue(caps["groups"])
        self.assertTrue(caps["direct_messages"])


class MucSenderTests(unittest.TestCase):
    """A MUC nick is attacker-chosen and may legally contain '@', so it must
    never be emitted as the sender: it would share the identity namespace
    (links, HMAC alias, rate-limit bucket, link-challenge match) with the
    bare JID of a DM sender."""

    def test_real_occupant_jid_is_preferred_and_bared(self):
        self.assertEqual(
            plug.muc_sender("ops@conference.example.com", "dana", "dana@example.com/phone"),
            "dana@example.com")

    def test_anonymous_room_uses_namespaced_occupant_id(self):
        self.assertEqual(plug.muc_sender("ops@conference.example.com", "dana", None),
                         "ops@conference.example.com/dana")

    def test_nick_impersonating_a_jid_cannot_collide_with_a_dm_sender(self):
        sender = plug.muc_sender("ops@conference.example.com", "victim@example.com", None)
        self.assertNotEqual(sender, "victim@example.com")
        self.assertIn("/", sender)  # a bare JID never carries a resource separator

    def test_empty_occupant_jid_falls_back_to_occupant_id(self):
        self.assertEqual(plug.muc_sender("ops@conference.example.com", "dana", ""),
                         "ops@conference.example.com/dana")


class _FakeMuc:
    def __init__(self, jids=None):
        self.jids = jids or {}
        self.joined = []

    def join_muc(self, room, nick):
        self.joined.append((room, nick))

    def get_jid_property(self, room, nick, jid_property):
        assert jid_property == "jid"
        return self.jids.get((room, nick))


class _FakeXmpp:
    def __init__(self, muc=None):
        self.plugin = {"xep_0045": muc or _FakeMuc()}
        self.presence_sent = 0

    def send_presence(self):
        self.presence_sent += 1

    def get_roster(self):
        pass

    def send_message(self, **kw):
        pass


class _FakeLoop:
    def __init__(self):
        self.scheduled = []

    def call_soon_threadsafe(self, fn):
        self.scheduled.append(fn)


def _muc_msg(room, nick, body):
    return {"from": types.SimpleNamespace(bare=room), "mucnick": nick, "body": body}


class BackendMucSenderTests(unittest.TestCase):
    ROOM = "townsquare@conference.example.com"

    def _backend(self, jids=None):
        backend = plug.XmppBackend(plug.load_config(base_cfg()))
        backend._xmpp = _FakeXmpp(_FakeMuc(jids))
        return backend

    def test_uses_occupant_jid_when_the_room_exposes_it(self):
        backend = self._backend({(self.ROOM, "dana"): "dana@example.com/laptop"})
        backend._on_muc_message(_muc_msg(self.ROOM, "dana", "hello"))
        ev = backend._queue.get_nowait()
        self.assertEqual(ev["sender"], "dana@example.com")
        self.assertEqual(ev["room"], self.ROOM)

    def test_never_emits_a_bare_nick(self):
        backend = self._backend()
        backend._on_muc_message(_muc_msg(self.ROOM, "victim@example.com", "hello"))
        ev = backend._queue.get_nowait()
        self.assertEqual(ev["sender"], f"{self.ROOM}/victim@example.com")

    def test_own_nick_still_dropped(self):
        backend = self._backend()
        backend._on_muc_message(_muc_msg(self.ROOM, "relayfabric", "echo"))
        self.assertTrue(backend._queue.empty())


class BackendSessionGateTests(unittest.TestCase):
    """slixmpp parks or discards a stanza sent while no session is up, so a
    send scheduled then must raise: the SDK then reports delivered:false and
    the daemon retries, instead of marking a silently lost message delivered."""

    ROOM = "townsquare@conference.example.com"

    def _backend(self):
        backend = plug.XmppBackend(plug.load_config(base_cfg()))
        backend._loop = _FakeLoop()
        backend._xmpp = _FakeXmpp()
        return backend

    def test_send_muc_raises_before_session_start(self):
        backend = self._backend()
        with self.assertRaises(RuntimeError):
            backend.send_muc(self.ROOM, "hi")
        self.assertEqual(backend._loop.scheduled, [])

    def test_send_chat_raises_before_session_start(self):
        backend = self._backend()
        with self.assertRaises(RuntimeError):
            backend.send_chat("dana@example.com", "hi")
        self.assertEqual(backend._loop.scheduled, [])

    def test_sends_schedule_once_session_is_up(self):
        backend = self._backend()
        backend._on_session_start(None)
        backend.send_muc(self.ROOM, "hi")
        backend.send_chat("dana@example.com", "hi")
        self.assertEqual(len(backend._loop.scheduled), 2)

    def test_sends_raise_again_after_disconnect(self):
        backend = self._backend()
        backend._on_session_start(None)
        backend._on_disconnected("connection reset")
        with self.assertRaises(RuntimeError):
            backend.send_muc(self.ROOM, "hi")
        with self.assertRaises(RuntimeError):
            backend.send_chat("dana@example.com", "hi")
        self.assertEqual(backend._loop.scheduled, [])


class BridgeDisconnectedSendTests(unittest.TestCase):
    def test_send_while_disconnected_reports_not_delivered(self):
        class _DownBackend(FakeBackend):
            def send_muc(self, room, text):
                raise RuntimeError("xmpp session not established")

            def send_chat(self, jid, text):
                raise RuntimeError("xmpp session not established")

        sock = FakeSock()
        bridge = plug.Bridge(plug.load_config(base_cfg()), _DownBackend(), sock)
        bridge.handle_send({"t": "send", "corr": "c9", "endpoint": "ops", "body": "hi"})
        bridge.handle_send_direct({"t": "send_direct", "corr": "d9",
                                   "native_ref": "dana@example.com", "body": "code"})
        results = {f["corr"]: f for f in sock.frames() if f["t"] == "delivery_result"}
        self.assertFalse(results["c9"]["delivered"])
        self.assertFalse(results["d9"]["delivered"])


if __name__ == "__main__":
    unittest.main()
