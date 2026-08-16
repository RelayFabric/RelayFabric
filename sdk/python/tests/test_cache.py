import unittest

from relayfabric_sdk import SentCache


class SentCacheTests(unittest.TestCase):
    def test_match_consumes(self):
        c = SentCache(ttl_secs=60)
        c.record("G", "body")
        self.assertTrue(c.match("G", "body"))
        self.assertFalse(c.match("G", "body"))

    def test_expiry_and_group_scoping(self):
        c = SentCache(ttl_secs=60)
        c.record("G", "body", now=1000.0)
        self.assertFalse(c.match("H", "body", now=1001.0))
        self.assertFalse(c.match("G", "body", now=1061.0))

    def test_default_ttl_is_one_day(self):
        c = SentCache()
        self.assertEqual(c.ttl, 86400)


if __name__ == "__main__":
    unittest.main()
