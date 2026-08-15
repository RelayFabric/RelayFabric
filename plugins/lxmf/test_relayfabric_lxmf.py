import os
import shutil
import stat
import tempfile
import unittest

import relayfabric_lxmf as plug

CFG = {
    "storage": "/tmp/rf-lxmf-test",
    "channels": [
        {"name": "pasadena", "members": ["A91D00AA"], "open": False},
        {"name": "lounge", "members": [], "open": True},
    ],
}


class ConfigTests(unittest.TestCase):
    def test_defaults_and_normalization(self):
        cfg = plug.load_config(CFG)
        self.assertEqual(cfg["announce_interval"], 3600)
        self.assertIsNone(cfg["stamp_cost"])
        self.assertEqual(cfg["channels"][0]["members"], ["a91d00aa"])
        self.assertFalse(cfg["channels"][0]["open"])

    def test_missing_storage_rejected(self):
        with self.assertRaises(ValueError):
            plug.load_config({"channels": []})

    def test_channel_without_name_rejected(self):
        with self.assertRaises(ValueError):
            plug.load_config({"storage": "/x", "channels": [{"members": []}]})


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.cfg = plug.load_config(CFG)

    def test_member_lookup_config_and_dynamic(self):
        self.assertEqual(
            plug.channel_for_member(self.cfg, "a91d00aa", {})["name"], "pasadena")
        self.assertIsNone(plug.channel_for_member(self.cfg, "ffff0000", {}))
        dyn = {"lounge": ["ffff0000"]}
        self.assertEqual(
            plug.channel_for_member(self.cfg, "ffff0000", dyn)["name"], "lounge")

    def test_channel_members_merges_without_dupes(self):
        ch = plug.channel_by_name(self.cfg, "pasadena")
        dyn = {"pasadena": ["a91d00aa", "bbbb1111"]}
        self.assertEqual(plug.channel_members(ch, dyn), ["a91d00aa", "bbbb1111"])


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.cfg = plug.load_config(CFG)
        self.dyn = {}

    def test_join_open_channel(self):
        reply, changed = plug.command_reply(self.cfg, self.dyn, "cccc2222", "/join lounge")
        self.assertIn("Joined", reply)
        self.assertTrue(changed)
        self.assertIn("cccc2222", self.dyn["lounge"])

    def test_join_closed_channel_denied(self):
        reply, changed = plug.command_reply(self.cfg, self.dyn, "cccc2222", "/join pasadena")
        self.assertIn("closed", reply)
        self.assertFalse(changed)

    def test_join_unknown_and_double_join(self):
        reply, _ = plug.command_reply(self.cfg, self.dyn, "c1", "/join nope")
        self.assertIn("No such channel", reply)
        plug.command_reply(self.cfg, self.dyn, "c1", "/join lounge")
        reply, changed = plug.command_reply(self.cfg, self.dyn, "c1", "/join lounge")
        self.assertIn("Already", reply)
        self.assertFalse(changed)

    def test_leave_paths(self):
        plug.command_reply(self.cfg, self.dyn, "c1", "/join lounge")
        reply, changed = plug.command_reply(self.cfg, self.dyn, "c1", "/leave lounge")
        self.assertIn("Left", reply)
        self.assertTrue(changed)
        reply, changed = plug.command_reply(self.cfg, self.dyn, "a91d00aa", "/leave pasadena")
        self.assertIn("operator", reply)
        self.assertFalse(changed)

    def test_channels_listing_and_usage(self):
        reply, _ = plug.command_reply(self.cfg, self.dyn, "a91d00aa", "/channels")
        self.assertIn("pasadena (member)", reply)
        self.assertIn("lounge (open)", reply)
        reply, _ = plug.command_reply(self.cfg, self.dyn, "a91d00aa", "/bogus")
        self.assertIn("/join", reply)


class FanoutTests(unittest.TestCase):
    def test_delivered_when_any_member_succeeds(self):
        t = plug.FanoutTracker(corr=7, members=["a", "b", "c"])
        self.assertIsNone(t.member_done("a", True))
        self.assertIsNone(t.member_done("b", False))
        result = t.member_done("c", False)
        self.assertEqual(result["corr"], 7)
        self.assertTrue(result["delivered"])
        self.assertIn("b", result["detail"])
        self.assertIn("c", result["detail"])

    def test_all_failures_reports_undelivered(self):
        t = plug.FanoutTracker(corr=8, members=["a"])
        result = t.member_done("a", False)
        self.assertFalse(result["delivered"])

    def test_double_fire_reports_result_exactly_once(self):
        t = plug.FanoutTracker(corr=9, members=["a"])
        result = t.member_done("a", True)
        self.assertIsNotNone(result)
        self.assertTrue(result["delivered"])
        # a buggy double-fired callback for the same (already-terminal)
        # member must not produce a second result frame
        self.assertIsNone(t.member_done("a", True))
        self.assertIsNone(t.member_done("a", False))


class HardenStorageTests(unittest.TestCase):
    def test_tightens_dir_and_identity_perms(self):
        storage = tempfile.mkdtemp()
        try:
            os.chmod(storage, 0o755)
            identity_path = os.path.join(storage, "identity")
            with open(identity_path, "w") as f:
                f.write("dummy-key-bytes")
            os.chmod(identity_path, 0o644)

            plug._harden_storage(storage, identity_path)

            self.assertEqual(stat.S_IMODE(os.stat(storage).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(identity_path).st_mode), 0o600)
        finally:
            shutil.rmtree(storage)

    def test_missing_identity_file_is_a_noop(self):
        storage = tempfile.mkdtemp()
        try:
            os.chmod(storage, 0o755)
            identity_path = os.path.join(storage, "identity")

            plug._harden_storage(storage, identity_path)  # must not raise

            self.assertEqual(stat.S_IMODE(os.stat(storage).st_mode), 0o700)
            self.assertFalse(os.path.exists(identity_path))
        finally:
            shutil.rmtree(storage)


if __name__ == "__main__":
    unittest.main()
