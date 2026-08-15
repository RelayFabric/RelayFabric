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


if __name__ == "__main__":
    unittest.main()
