import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lxmf"))

import unittest

import relayfabric_signal as plug

OWN = "+15550001111"


def data_event(source="+15552223333", uuid="abc-uuid", group="GRP==", text="hi",
               ts=1755280000000):
    return {"envelope": {
        "source": source, "sourceNumber": source, "sourceUuid": uuid,
        "timestamp": ts,
        "dataMessage": {"message": text, "groupInfo": {"groupId": group}},
    }}


def sync_event(group="GRP==", text="hi", ts=1755280000000):
    return {"envelope": {
        "source": OWN, "sourceNumber": OWN, "sourceUuid": "own-uuid",
        "timestamp": ts,
        "syncMessage": {"sentMessage": {"message": text,
                                        "groupInfo": {"groupId": group}}},
    }}


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = plug.load_config({"account": OWN, "groups": {"pas": "GRP=="}})
        self.assertEqual(cfg["rpc_url"], "http://127.0.0.1:7583")
        self.assertIsNone(cfg["allowed_users"])

    def test_required_fields(self):
        with self.assertRaises(ValueError):
            plug.load_config({"groups": {"pas": "G"}})
        with self.assertRaises(ValueError):
            plug.load_config({"account": OWN})
        with self.assertRaises(ValueError):
            plug.load_config({"account": OWN, "groups": {}})


class ParserTests(unittest.TestCase):
    def test_data_message_parsed_uuid_preferred(self):
        source, group, text, ts = plug.parse_signal_event(data_event(), OWN)
        self.assertEqual(source, "abc-uuid")
        self.assertEqual(group, "GRP==")
        self.assertEqual(text, "hi")
        self.assertEqual(ts, 1755280000000)

    def test_sync_sent_message_parsed(self):
        _, group, text, _ = plug.parse_signal_event(sync_event(), OWN)
        self.assertEqual(group, "GRP==")
        self.assertEqual(text, "hi")

    def test_own_account_non_sync_dropped(self):
        ev = data_event(source=OWN, uuid="own-uuid")
        self.assertIsNone(plug.parse_signal_event(ev, OWN))

    def test_textless_and_sourceless_dropped(self):
        self.assertIsNone(plug.parse_signal_event(data_event(text=""), OWN))
        ev = data_event()
        for k in ("source", "sourceNumber", "sourceUuid"):
            ev["envelope"].pop(k)
        self.assertIsNone(plug.parse_signal_event(ev, OWN))

    def test_dm_yields_group_none(self):
        ev = data_event()
        del ev["envelope"]["dataMessage"]["groupInfo"]
        _, group, _, _ = plug.parse_signal_event(ev, OWN)
        self.assertIsNone(group)


class SentCacheTests(unittest.TestCase):
    def test_match_consumes(self):
        c = plug.SentCache(ttl_secs=60)
        c.record("G", "body")
        self.assertTrue(c.match("G", "body"))
        self.assertFalse(c.match("G", "body"))

    def test_expiry_and_group_scoping(self):
        c = plug.SentCache(ttl_secs=60)
        c.record("G", "body", now=1000.0)
        self.assertFalse(c.match("H", "body", now=1001.0))
        self.assertFalse(c.match("G", "body", now=1061.0))


class FakeBackend:
    def __init__(self):
        self.sent = []
        self.fail_with = None

    def send_group(self, group_id, text):
        if self.fail_with:
            raise self.fail_with
        self.sent.append((group_id, text))


class FakeSock:
    """Captures frames the bridge writes to the daemon."""
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
        self.cfg = plug.load_config(
            {"account": OWN, "groups": {"pas": "GRP=="}})
        self.backend = FakeBackend()
        self.sock = FakeSock()
        self.bridge = plug.Bridge(self.cfg, self.backend, self.sock)

    def test_inbound_mapped_group_bridges(self):
        self.bridge.handle_event(data_event())
        frames = self.sock.frames()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["t"], "inbound")
        self.assertEqual(frames[0]["endpoint"], "pas")
        self.assertEqual(frames[0]["sender"], "abc-uuid")
        self.assertEqual(frames[0]["body"], "hi")

    def test_unmapped_group_and_dm_dropped(self):
        self.bridge.handle_event(data_event(group="OTHER=="))
        ev = data_event()
        del ev["envelope"]["dataMessage"]["groupInfo"]
        self.bridge.handle_event(ev)
        self.assertEqual(self.sock.frames(), [])

    def test_allowed_users_acl(self):
        self.cfg["allowed_users"] = ["someone-else"]
        bridge = plug.Bridge(self.cfg, self.backend, self.sock)
        bridge.handle_event(data_event())
        self.assertEqual(self.sock.frames(), [])

    def test_allowed_users_empty_list_denies_all(self):
        self.cfg["allowed_users"] = []
        bridge = plug.Bridge(self.cfg, self.backend, self.sock)
        bridge.handle_event(data_event())
        self.assertEqual(self.sock.frames(), [])

    def test_send_success_records_loop_guard(self):
        self.bridge.handle_send({"corr": 5, "endpoint": "pas", "body": "out"})
        self.assertEqual(self.backend.sent, [("GRP==", "out")])
        frames = self.sock.frames()
        self.assertEqual(frames[-1],
                         {"t": "delivery_result", "corr": 5,
                          "delivered": True, "detail": None})
        # the sync echo of our own post is now dropped
        self.bridge.handle_event(sync_event(text="out"))
        self.assertEqual(len(self.sock.frames()), 1)  # still only the result

    def test_send_failure_reports_detail(self):
        self.backend.fail_with = RuntimeError("boom")
        self.bridge.handle_send({"corr": 6, "endpoint": "pas", "body": "x"})
        frames = self.sock.frames()
        self.assertFalse(frames[-1]["delivered"])
        self.assertIn("boom", frames[-1]["detail"])

    def test_send_unknown_endpoint(self):
        self.bridge.handle_send({"corr": 7, "endpoint": "nope", "body": "x"})
        self.assertFalse(self.sock.frames()[-1]["delivered"])
        self.assertEqual(self.backend.sent, [])


if __name__ == "__main__":
    unittest.main()
