import copy
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sdk", "python"))

import relayfabric_bitchat as plug
from relayfabric_sdk import nip01

# Same "known nsec" golden vector as plugins/nostr/test_relayfabric_nostr.py
# and sdk/python/tests/test_nip01.py: nsec=1 is the best-known private key
# in secp256k1 (scalar 1), its x-only pubkey is the curve generator point G
# -- independently verifiable against any secp256k1 reference (e.g. SEC2).
# Used here only as a ready-made (privkey_hex, pubkey_hex) identity; the
# id/sig correctness itself is locked in sdk/python/tests/test_nip01.py.
GOLDEN_PRIVKEY_HEX = "0" * 63 + "1"
GOLDEN_PUBKEY_HEX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

VALID_GEOHASH = "9q5"  # SF Bay Area-ish, base32 chars only


def valid_bitchat_cfg(**overrides):
    cfg = {
        "relays": ["wss://relay.example.com"],
        "channels": {
            "regional": {"geohash": VALID_GEOHASH},
        },
    }
    cfg.update(overrides)
    return cfg


class IsGeohashTests(unittest.TestCase):
    def test_valid_geohash(self):
        self.assertTrue(plug.is_geohash("9q5ctr"))

    def test_full_alphabet_valid(self):
        self.assertTrue(plug.is_geohash("0123456789bcdefghjkmnpqrstuvwxyz"))

    def test_empty_string_invalid(self):
        self.assertFalse(plug.is_geohash(""))

    def test_uppercase_invalid(self):
        # base32 geohash alphabet is lowercase only (design conventions).
        self.assertFalse(plug.is_geohash("9Q5"))

    def test_excluded_letters_invalid(self):
        # 'a', 'i', 'l', 'o' are not in the Bitchat geohash alphabet.
        for bad_char in "ailo":
            with self.subTest(bad_char=bad_char):
                self.assertFalse(plug.is_geohash(bad_char))

    def test_non_alphabet_char_invalid(self):
        self.assertFalse(plug.is_geohash("9q5!"))

    def test_non_string_invalid(self):
        self.assertFalse(plug.is_geohash(12345))
        self.assertFalse(plug.is_geohash(None))
        self.assertFalse(plug.is_geohash(["9", "q", "5"]))


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = plug.load_config(valid_bitchat_cfg())
        self.assertEqual(cfg["max_text_bytes"], 280)
        self.assertIsNone(cfg["identity_file"])

    def test_relays_required_missing(self):
        with self.assertRaises(ValueError):
            plug.load_config({"channels": {"a": {"geohash": VALID_GEOHASH}}})

    def test_relays_required_empty(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_bitchat_cfg(relays=[]))

    def test_relays_must_be_list(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_bitchat_cfg(relays="wss://relay.example.com"))

    def test_relay_url_must_be_str(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_bitchat_cfg(relays=[123]))

    def test_relay_url_must_have_ws_scheme(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_bitchat_cfg(relays=["https://relay.example.com"]))

    def test_relay_ws_and_wss_both_accepted(self):
        cfg = plug.load_config(valid_bitchat_cfg(relays=["ws://a", "wss://b"]))
        self.assertEqual(cfg["relays"], ["ws://a", "wss://b"])

    def test_channels_required_missing(self):
        with self.assertRaises(ValueError):
            plug.load_config({"relays": ["wss://a"]})

    def test_channels_required_empty(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_bitchat_cfg(channels={}))

    def test_channels_must_be_dict(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_bitchat_cfg(channels=["regional"]))

    def test_channel_spec_must_be_dict(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_bitchat_cfg(channels={"regional": "not-a-dict"}))

    def test_channel_geohash_required(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_bitchat_cfg(channels={"regional": {}}))

    def test_channel_geohash_must_be_str(self):
        with self.assertRaises(TypeError):
            plug.load_config(
                valid_bitchat_cfg(channels={"regional": {"geohash": 12345}}))

    def test_channel_geohash_empty_rejected(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_bitchat_cfg(channels={"regional": {"geohash": ""}}))

    def test_channel_geohash_bad_charset_rejected(self):
        # 'a' is not in the base32 geohash alphabet.
        with self.assertRaises(ValueError):
            plug.load_config(
                valid_bitchat_cfg(channels={"regional": {"geohash": "9qa"}}))

    def test_channel_geohash_uppercase_rejected(self):
        with self.assertRaises(ValueError):
            plug.load_config(
                valid_bitchat_cfg(channels={"regional": {"geohash": "9Q5"}}))

    def test_channel_relays_optional_list(self):
        cfg = plug.load_config(valid_bitchat_cfg(channels={
            "regional": {"geohash": VALID_GEOHASH, "relays": ["wss://c"]},
        }))
        self.assertEqual(cfg["channels"]["regional"]["relays"], ["wss://c"])

    def test_channel_relays_must_be_list(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_bitchat_cfg(channels={
                "regional": {"geohash": VALID_GEOHASH, "relays": "wss://c"},
            }))

    def test_channel_nickname_optional_str(self):
        cfg = plug.load_config(valid_bitchat_cfg(channels={
            "regional": {"geohash": VALID_GEOHASH, "nickname": "relayfabric-bridge"},
        }))
        self.assertEqual(cfg["channels"]["regional"]["nickname"], "relayfabric-bridge")

    def test_channel_nickname_must_be_str(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_bitchat_cfg(channels={
                "regional": {"geohash": VALID_GEOHASH, "nickname": 42},
            }))

    def test_max_text_bytes_default(self):
        cfg = plug.load_config(valid_bitchat_cfg())
        self.assertEqual(cfg["max_text_bytes"], 280)

    def test_max_text_bytes_override(self):
        cfg = plug.load_config(valid_bitchat_cfg(max_text_bytes=140))
        self.assertEqual(cfg["max_text_bytes"], 140)

    def test_max_text_bytes_must_be_int(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_bitchat_cfg(max_text_bytes="280"))

    def test_identity_file_optional_default_none(self):
        cfg = plug.load_config(valid_bitchat_cfg())
        self.assertIsNone(cfg["identity_file"])

    def test_identity_file_override(self):
        cfg = plug.load_config(valid_bitchat_cfg(identity_file="/etc/bitchat.nsec"))
        self.assertEqual(cfg["identity_file"], "/etc/bitchat.nsec")

    def test_identity_file_must_be_str(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_bitchat_cfg(identity_file=42))

    def test_channels_are_copied_not_aliased(self):
        raw = valid_bitchat_cfg(channels={
            "regional": {"geohash": VALID_GEOHASH, "relays": ["wss://c"]},
        })
        cfg = plug.load_config(raw)
        cfg["channels"]["regional"]["relays"].append("wss://d")
        self.assertEqual(raw["channels"]["regional"]["relays"], ["wss://c"])

    def test_deny_by_default_only_configured_channels(self):
        # No hidden default channel: load_config never invents entries
        # beyond what was configured.
        cfg = plug.load_config(valid_bitchat_cfg())
        self.assertEqual(list(cfg["channels"].keys()), ["regional"])

    def test_load_config_does_not_mutate_raw(self):
        raw = valid_bitchat_cfg()
        raw_copy = copy.deepcopy(raw)
        plug.load_config(raw)
        self.assertEqual(raw, raw_copy)


class ReqFilterTests(unittest.TestCase):
    def test_shape(self):
        self.assertEqual(
            plug.req_filter({"geohash": VALID_GEOHASH}),
            {"kinds": [20000], "#g": [VALID_GEOHASH]})

    def test_ignores_other_spec_keys(self):
        spec = {"geohash": VALID_GEOHASH, "relays": ["wss://a"], "nickname": "n"}
        self.assertEqual(plug.req_filter(spec), {"kinds": [20000], "#g": [VALID_GEOHASH]})


class BuildBitchatEventTests(unittest.TestCase):
    def test_kind_and_content(self):
        event = plug.build_bitchat_event(
            GOLDEN_PRIVKEY_HEX, VALID_GEOHASH, None, "hello geohash", 1700000000)
        self.assertEqual(event["kind"], 20000)
        self.assertEqual(event["content"], "hello geohash")
        self.assertEqual(event["created_at"], 1700000000)
        self.assertEqual(event["pubkey"], GOLDEN_PUBKEY_HEX)

    def test_g_tag_present_without_nickname(self):
        event = plug.build_bitchat_event(
            GOLDEN_PRIVKEY_HEX, VALID_GEOHASH, None, "hi", 1700000000)
        self.assertEqual(event["tags"], [["g", VALID_GEOHASH]])

    def test_g_and_n_tags_present_with_nickname(self):
        event = plug.build_bitchat_event(
            GOLDEN_PRIVKEY_HEX, VALID_GEOHASH, "relayfabric-bridge", "hi", 1700000000)
        self.assertEqual(
            event["tags"], [["g", VALID_GEOHASH], ["n", "relayfabric-bridge"]])

    def test_empty_string_nickname_omits_n_tag(self):
        # falsy nickname ("" or None) -- no invented nickname tag.
        event = plug.build_bitchat_event(
            GOLDEN_PRIVKEY_HEX, VALID_GEOHASH, "", "hi", 1700000000)
        self.assertEqual(event["tags"], [["g", VALID_GEOHASH]])

    def test_round_trips_through_verify_event(self):
        event = plug.build_bitchat_event(
            GOLDEN_PRIVKEY_HEX, VALID_GEOHASH, "nym", "verify me", 1700000000)
        self.assertTrue(nip01.verify_event(event))

    def test_tampered_event_fails_verify(self):
        event = plug.build_bitchat_event(
            GOLDEN_PRIVKEY_HEX, VALID_GEOHASH, "nym", "verify me", 1700000000)
        event["content"] = "tampered"
        self.assertFalse(nip01.verify_event(event))


class NormalizeEventTests(unittest.TestCase):
    def setUp(self):
        self.subid_to_channel = {
            "sub-regional": {"name": "regional", "geohash": VALID_GEOHASH},
        }

    def _signed(self, **overrides):
        kwargs = {"geohash": VALID_GEOHASH, "nickname": None, "text": "hello channel",
                  "now": 1700000020}
        kwargs.update(overrides)
        return plug.build_bitchat_event(
            GOLDEN_PRIVKEY_HEX, kwargs["geohash"], kwargs["nickname"],
            kwargs["text"], kwargs["now"])

    def test_valid_event_normalizes(self):
        event = self._signed()
        result = plug.normalize_event(event, "sub-regional", self.subid_to_channel)
        self.assertIsNotNone(result)
        channel, sender, text, nym, ts = result
        self.assertEqual(channel, "regional")
        self.assertEqual(sender, f"bitchat:{GOLDEN_PUBKEY_HEX}")
        self.assertEqual(text, "hello channel")
        self.assertIsNone(nym)
        self.assertEqual(ts, 1700000020)

    def test_nym_passthrough_when_n_tag_present(self):
        event = self._signed(nickname="wanderer")
        result = plug.normalize_event(event, "sub-regional", self.subid_to_channel)
        self.assertIsNotNone(result)
        _channel, _sender, _text, nym, _ts = result
        self.assertEqual(nym, "wanderer")

    def test_bad_sig_dropped(self):
        # design Sec80: a relay is untrusted -- bad/wrong sig must never bridge.
        event = self._signed()
        event["sig"] = "0" * 128
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.subid_to_channel))

    def test_tampered_id_dropped(self):
        event = self._signed()
        event["id"] = "f" * 64
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.subid_to_channel))

    def test_kind_not_20000_dropped(self):
        # Isolate the kind check from verify_event's id check: rebuild a
        # validly-signed kind-1 event (not a tampered kind-20000 one).
        from relayfabric_sdk.nip01 import sign_event
        event = sign_event(GOLDEN_PRIVKEY_HEX, 1700000020, 1,
                           [["g", VALID_GEOHASH]], "hello channel")
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.subid_to_channel))

    def test_unmapped_subscription_dropped(self):
        event = self._signed()
        self.assertIsNone(
            plug.normalize_event(event, "sub-unknown", self.subid_to_channel))

    def test_wrong_geohash_dropped(self):
        # defense: a relay could send an event tagged with a different
        # geohash than the one this subscription is configured for.
        from relayfabric_sdk.nip01 import sign_event
        event = sign_event(GOLDEN_PRIVKEY_HEX, 1700000020, 20000,
                           [["g", "other geohash not matching"]], "hello channel")
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.subid_to_channel))

    def test_missing_g_tag_dropped(self):
        from relayfabric_sdk.nip01 import sign_event
        event = sign_event(GOLDEN_PRIVKEY_HEX, 1700000020, 20000, [], "hello channel")
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.subid_to_channel))

    def test_empty_content_dropped(self):
        event = self._signed(text="")
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.subid_to_channel))

    def test_malformed_event_dropped_not_raised(self):
        try:
            result = plug.normalize_event({"kind": 20000}, "sub-regional",
                                          self.subid_to_channel)
        except Exception as e:  # noqa: BLE001 - the property under test
            self.fail(f"normalize_event raised {e!r}")
        self.assertIsNone(result)

    def test_malformed_tags_do_not_raise(self):
        # A validly-signed event (tags included in the signature, unlike a
        # post-signing tamper) with junk tag shapes -- exercises the
        # tag-scan loop's tolerance for non-list/short entries without a
        # signature-valid path masking it via verify_event's own rejection.
        from relayfabric_sdk.nip01 import sign_event
        event = sign_event(
            GOLDEN_PRIVKEY_HEX, 1700000020, 20000,
            [["g"], ["n", "x", "extra"], ["z"], [], "not-a-list", 123],
            "hello channel")
        try:
            result = plug.normalize_event(event, "sub-regional", self.subid_to_channel)
        except Exception as e:  # noqa: BLE001 - the property under test
            self.fail(f"normalize_event raised {e!r}")
        self.assertIsNone(result)  # no valid ["g", <geohash>] tag present


class HelloMaxPayloadTests(unittest.TestCase):
    def test_default_cap(self):
        cfg = plug.load_config(valid_bitchat_cfg())
        self.assertEqual(plug.hello_max_payload(cfg), 280)

    def test_lower_max_text_bytes_tightens_cap(self):
        cfg = plug.load_config(valid_bitchat_cfg(max_text_bytes=100))
        self.assertEqual(plug.hello_max_payload(cfg), 100)

    def test_higher_max_text_bytes_capped_at_280(self):
        cfg = plug.load_config(valid_bitchat_cfg(max_text_bytes=5000))
        self.assertEqual(plug.hello_max_payload(cfg), 280)


class ImportCleanlinessTests(unittest.TestCase):
    """Module top level must be stdlib-only (coincurve/websockets/cbor2/
    relayfabric_sdk imported lazily inside functions) so config/geohash
    helpers stay importable without those deps. Run in a subprocess so
    modules other tests in this file already imported (e.g. coincurve, for
    the crypto-round-trip tests themselves) can't mask a leaked top-level
    import -- mirrors plugins/nostr/test_relayfabric_nostr.py's precedent.
    """

    def test_module_top_level_is_stdlib_only(self):
        plugin_dir = os.path.dirname(os.path.abspath(__file__))
        script = (
            "import sys\n"
            "import relayfabric_bitchat\n"
            "leaked = [m for m in "
            "('coincurve', 'websockets', 'cbor2', 'relayfabric_sdk') "
            "if m in sys.modules]\n"
            "assert not leaked, leaked\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=plugin_dir,
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
