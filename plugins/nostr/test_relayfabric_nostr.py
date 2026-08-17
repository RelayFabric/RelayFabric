import copy
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sdk", "python"))

import relayfabric_nostr as plug
from relayfabric_sdk import SentCache

# "Known nsec" golden vector (brief's explicit fallback: the NIP-01 spec
# itself has no fully-worked example event with concrete id/sig -- confirmed
# by fetching nostr-protocol/nips/01.md directly, and web search results for
# one returned internally-inconsistent hex lengths, i.e. fabricated). nsec=1
# is the best-known private key in secp256k1 (scalar 1): its x-only pubkey is
# the curve generator point G, independently verifiable against any
# secp256k1 reference (e.g. SEC2) -- 79be667ef9dcbbac...16f81798. The
# resulting id/sig below were computed once via coincurve + hashlib directly
# (not through plug.event_id) and locked here as regression constants: if a
# future change to the JSON serialization (separators, key order, escaping)
# shifts the id, this test catches it.
GOLDEN_PRIVKEY_HEX = "0" * 63 + "1"
GOLDEN_PUBKEY_HEX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
GOLDEN_CREATED_AT = 1700000000
GOLDEN_KIND = 1
GOLDEN_TAGS = []
GOLDEN_CONTENT = "Hello, Nostr!"
GOLDEN_SERIALIZATION = (
    '[0,"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",'
    '1700000000,1,[],"Hello, Nostr!"]'
)
GOLDEN_ID = "0ba639494d12d0de932b08f60d85d2843ab56dfdf0c7dd22985c24adbb61140f"
GOLDEN_SIG = (
    "021e899964ffe6390efc335c8d5166f37888c0b06f21286246abd519cd6052"
    "342b94b458ed3918a0f056b50d16484196f0f7dbd5c256d848217bded4501effba"
)


def valid_relay_cfg(**overrides):
    cfg = {
        "relays": ["wss://relay.example.com"],
        "channels": {
            "regional": {"filter": {"kinds": [1], "#t": ["pasadena"]}},
        },
    }
    cfg.update(overrides)
    return cfg


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = plug.load_config(valid_relay_cfg())
        self.assertEqual(cfg["max_text_bytes"], 280)
        self.assertIsNone(cfg["identity_file"])

    def test_relays_required_missing(self):
        with self.assertRaises(ValueError):
            plug.load_config({"channels": {"a": {"filter": {}}}})

    def test_relays_required_empty(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_relay_cfg(relays=[]))

    def test_relays_must_be_list(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(relays="wss://relay.example.com"))

    def test_relay_url_must_be_str(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(relays=[123]))

    def test_relay_url_must_have_ws_scheme(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_relay_cfg(relays=["https://relay.example.com"]))

    def test_relay_ws_and_wss_both_accepted(self):
        cfg = plug.load_config(valid_relay_cfg(relays=["ws://a", "wss://b"]))
        self.assertEqual(cfg["relays"], ["ws://a", "wss://b"])

    def test_channels_required_missing(self):
        with self.assertRaises(ValueError):
            plug.load_config({"relays": ["wss://a"]})

    def test_channels_required_empty(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_relay_cfg(channels={}))

    def test_channels_must_be_dict(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(channels=["regional"]))

    def test_channel_spec_must_be_dict(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(channels={"regional": "not-a-dict"}))

    def test_channel_filter_required(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_relay_cfg(channels={"regional": {}}))

    def test_channel_filter_must_be_dict(self):
        with self.assertRaises(TypeError):
            plug.load_config(
                valid_relay_cfg(channels={"regional": {"filter": ["kinds"]}}))

    def test_channel_relays_optional_list(self):
        cfg = plug.load_config(valid_relay_cfg(channels={
            "regional": {"filter": {"kinds": [1]}, "relays": ["wss://c"]},
        }))
        self.assertEqual(cfg["channels"]["regional"]["relays"], ["wss://c"])

    def test_channel_relays_must_be_list(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(channels={
                "regional": {"filter": {"kinds": [1]}, "relays": "wss://c"},
            }))

    def test_channel_publish_tags_optional_list(self):
        cfg = plug.load_config(valid_relay_cfg(channels={
            "regional": {"filter": {"kinds": [1]},
                        "publish_tags": [["t", "pasadena"]]},
        }))
        self.assertEqual(cfg["channels"]["regional"]["publish_tags"],
                         [["t", "pasadena"]])

    def test_channel_publish_tags_must_be_list(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(channels={
                "regional": {"filter": {"kinds": [1]}, "publish_tags": "t"},
            }))

    def test_max_text_bytes_default(self):
        cfg = plug.load_config(valid_relay_cfg())
        self.assertEqual(cfg["max_text_bytes"], 280)

    def test_max_text_bytes_override(self):
        cfg = plug.load_config(valid_relay_cfg(max_text_bytes=140))
        self.assertEqual(cfg["max_text_bytes"], 140)

    def test_max_text_bytes_must_be_int(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(max_text_bytes="280"))

    def test_identity_file_optional_default_none(self):
        cfg = plug.load_config(valid_relay_cfg())
        self.assertIsNone(cfg["identity_file"])

    def test_identity_file_override(self):
        cfg = plug.load_config(valid_relay_cfg(identity_file="/etc/nostr.nsec"))
        self.assertEqual(cfg["identity_file"], "/etc/nostr.nsec")

    def test_identity_file_must_be_str(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(identity_file=42))

    def test_channels_are_copied_not_aliased(self):
        raw = valid_relay_cfg()
        cfg = plug.load_config(raw)
        cfg["channels"]["regional"]["filter"]["kinds"] = [9999]
        self.assertEqual(raw["channels"]["regional"]["filter"]["kinds"], [1])

    def test_deny_by_default_only_configured_channels(self):
        # No hidden default channel: load_config never invents entries beyond
        # what was configured.
        cfg = plug.load_config(valid_relay_cfg())
        self.assertEqual(list(cfg["channels"].keys()), ["regional"])


class EventIdGoldenVectorTests(unittest.TestCase):
    """Locks the exact NIP-01 canonical serialization / sha256 event id."""

    def test_golden_vector_id(self):
        eid = plug.event_id(GOLDEN_PUBKEY_HEX, GOLDEN_CREATED_AT, GOLDEN_KIND,
                            GOLDEN_TAGS, GOLDEN_CONTENT)
        self.assertEqual(eid, GOLDEN_ID)

    def test_serialization_is_compact_no_whitespace(self):
        # id must change if separators/whitespace drift -- assert indirectly
        # via the locked id, and directly via a known tags/content case that
        # would break under default (", ", ": ") json separators.
        eid = plug.event_id("ab" * 32, 1, 1, [["t", "x"]], "hi")
        # Compact serialization with a non-empty tags array:
        # [0,"abab...","1","1",[["t","x"]],"hi"] must NOT contain any spaces.
        import hashlib
        import json
        expected_ser = json.dumps(
            [0, "ab" * 32, 1, 1, [["t", "x"]], "hi"],
            separators=(",", ":"), ensure_ascii=False)
        self.assertNotIn(" ", expected_ser)
        expected = hashlib.sha256(expected_ser.encode("utf-8")).hexdigest()
        self.assertEqual(eid, expected)

    def test_id_is_deterministic(self):
        eid1 = plug.event_id(GOLDEN_PUBKEY_HEX, GOLDEN_CREATED_AT, GOLDEN_KIND,
                             GOLDEN_TAGS, GOLDEN_CONTENT)
        eid2 = plug.event_id(GOLDEN_PUBKEY_HEX, GOLDEN_CREATED_AT, GOLDEN_KIND,
                             GOLDEN_TAGS, GOLDEN_CONTENT)
        self.assertEqual(eid1, eid2)


class SignVerifyRoundTripTests(unittest.TestCase):
    def test_golden_vector_sig_verifies(self):
        event = {
            "id": GOLDEN_ID, "pubkey": GOLDEN_PUBKEY_HEX,
            "created_at": GOLDEN_CREATED_AT, "kind": GOLDEN_KIND,
            "tags": GOLDEN_TAGS, "content": GOLDEN_CONTENT, "sig": GOLDEN_SIG,
        }
        self.assertTrue(plug.verify_event(event))

    def test_sign_event_round_trips(self):
        event = plug.sign_event(GOLDEN_PRIVKEY_HEX, 1700000001, 1, [], "round trip")
        self.assertTrue(plug.verify_event(event))
        self.assertEqual(event["pubkey"], GOLDEN_PUBKEY_HEX)
        self.assertEqual(len(event["sig"]), 128)
        self.assertEqual(len(event["id"]), 64)

    def test_sign_event_id_matches_event_id_helper(self):
        event = plug.sign_event(GOLDEN_PRIVKEY_HEX, 1700000002, 1, [["t", "x"]], "hi")
        recomputed = plug.event_id(event["pubkey"], event["created_at"],
                                   event["kind"], event["tags"], event["content"])
        self.assertEqual(event["id"], recomputed)

    def test_different_content_yields_different_sig(self):
        e1 = plug.sign_event(GOLDEN_PRIVKEY_HEX, 1700000003, 1, [], "a")
        e2 = plug.sign_event(GOLDEN_PRIVKEY_HEX, 1700000003, 1, [], "b")
        self.assertNotEqual(e1["id"], e2["id"])
        self.assertNotEqual(e1["sig"], e2["sig"])


class VerifyEventRejectsTests(unittest.TestCase):
    def _valid_event(self):
        return plug.sign_event(GOLDEN_PRIVKEY_HEX, 1700000010, 1, [], "tamper me")

    def test_tampered_id_rejected(self):
        event = self._valid_event()
        event["id"] = "0" * 64
        self.assertFalse(plug.verify_event(event))

    def test_tampered_content_rejected(self):
        # id no longer matches recomputed sha256 once content changes.
        event = self._valid_event()
        event["content"] = "different content"
        self.assertFalse(plug.verify_event(event))

    def test_tampered_sig_rejected(self):
        event = self._valid_event()
        good_sig = event["sig"]
        # flip the last hex nibble
        event["sig"] = good_sig[:-1] + ("0" if good_sig[-1] != "0" else "1")
        self.assertFalse(plug.verify_event(event))

    def test_wrong_pubkey_rejected(self):
        event = self._valid_event()
        event["pubkey"] = "ab" * 32
        self.assertFalse(plug.verify_event(event))

    def test_never_raises_on_malformed_dicts(self):
        malformed = [
            {},
            {"id": "not-hex"},
            {"id": 12345, "pubkey": None, "created_at": "x", "kind": "y",
             "tags": "z", "content": None, "sig": None},
            {"id": "0" * 64, "pubkey": "0" * 64, "created_at": 1, "kind": 1,
             "tags": [], "content": "hi", "sig": "short"},
            {"id": "0" * 64, "pubkey": "not-32-bytes", "created_at": 1,
             "kind": 1, "tags": [], "content": "hi", "sig": "0" * 128},
            {"pubkey": "0" * 64},
            {"id": "0" * 64, "pubkey": "0" * 64, "created_at": 1, "kind": 1,
             "tags": {"not": "a list"}, "content": "hi", "sig": "0" * 128},
        ]
        for ev in malformed:
            with self.subTest(ev=ev):
                try:
                    result = plug.verify_event(ev)
                except Exception as e:  # noqa: BLE001 - the property under test
                    self.fail(f"verify_event raised {e!r} on {ev!r}")
                self.assertFalse(result)

    def test_never_raises_on_non_dict_input(self):
        for ev in [None, "not a dict", [], 42, object()]:
            with self.subTest(ev=ev):
                try:
                    result = plug.verify_event(ev)
                except Exception as e:  # noqa: BLE001 - the property under test
                    self.fail(f"verify_event raised {e!r} on {ev!r}")
                self.assertFalse(result)


class NormalizeEventTests(unittest.TestCase):
    def setUp(self):
        self.channels_by_sub = {"sub-regional": "regional"}

    def _signed(self, **overrides):
        kwargs = {"privkey_hex": GOLDEN_PRIVKEY_HEX, "created_at": 1700000020,
                  "kind": 1, "tags": [], "content": "hello channel"}
        kwargs.update(overrides)
        return plug.sign_event(kwargs["privkey_hex"], kwargs["created_at"],
                               kwargs["kind"], kwargs["tags"], kwargs["content"])

    def test_valid_event_normalizes(self):
        event = self._signed()
        result = plug.normalize_event(event, "sub-regional", self.channels_by_sub)
        self.assertIsNotNone(result)
        channel, sender, text, ts = result
        self.assertEqual(channel, "regional")
        self.assertEqual(sender, f"nostr:{GOLDEN_PUBKEY_HEX}")
        self.assertEqual(text, "hello channel")
        self.assertEqual(ts, 1700000020)

    def test_kind_not_1_dropped(self):
        event = self._signed(kind=0)
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.channels_by_sub))

    def test_bad_sig_dropped(self):
        # design Sec80: a relay is untrusted -- bad/wrong sig must never bridge.
        event = self._signed()
        event["sig"] = "0" * 128
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.channels_by_sub))

    def test_tampered_id_dropped(self):
        event = self._signed()
        event["id"] = "f" * 64
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.channels_by_sub))

    def test_empty_content_dropped(self):
        event = self._signed(content="")
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.channels_by_sub))

    def test_unmapped_subscription_dropped(self):
        event = self._signed()
        self.assertIsNone(
            plug.normalize_event(event, "sub-unknown", self.channels_by_sub))

    def test_malformed_event_dropped_not_raised(self):
        try:
            result = plug.normalize_event({"kind": 1}, "sub-regional",
                                          self.channels_by_sub)
        except Exception as e:  # noqa: BLE001 - the property under test
            self.fail(f"normalize_event raised {e!r}")
        self.assertIsNone(result)


class HelloMaxPayloadTests(unittest.TestCase):
    def test_default_cap(self):
        cfg = plug.load_config(valid_relay_cfg())
        self.assertEqual(plug.hello_max_payload(cfg), 280)

    def test_lower_max_text_bytes_tightens_cap(self):
        cfg = plug.load_config(valid_relay_cfg(max_text_bytes=100))
        self.assertEqual(plug.hello_max_payload(cfg), 100)

    def test_higher_max_text_bytes_capped_at_280(self):
        cfg = plug.load_config(valid_relay_cfg(max_text_bytes=5000))
        self.assertEqual(plug.hello_max_payload(cfg), 280)


class SentCacheImportSmokeTests(unittest.TestCase):
    """Task 2's Bridge will use relayfabric_sdk.SentCache the same way
    meshcore/signal do; this just confirms the sys.path-inserted sdk import
    works from the nostr plugin directory."""

    def test_sentcache_record_and_match_round_trips(self):
        cache = SentCache(ttl_secs=3600)
        cache.record("regional", "hi")
        self.assertTrue(cache.match("regional", "hi"))
        self.assertFalse(cache.match("regional", "hi"))  # consumed on match


class ImportCleanlinessTests(unittest.TestCase):
    """Module top level must be stdlib-only (coincurve/websockets/cbor2/
    relayfabric_sdk imported lazily inside functions) so config/event
    helpers stay importable without those deps. Run in a subprocess so
    modules other tests in this file already imported (e.g. coincurve, for
    the crypto tests themselves) can't mask a leaked top-level import."""

    def test_module_top_level_is_stdlib_only(self):
        plugin_dir = os.path.dirname(os.path.abspath(__file__))
        script = (
            "import sys\n"
            "import relayfabric_nostr\n"
            "leaked = [m for m in "
            "('coincurve', 'websockets', 'cbor2', 'relayfabric_sdk') "
            "if m in sys.modules]\n"
            "assert not leaked, leaked\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=plugin_dir,
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


class DeepCopyRegressionTests(unittest.TestCase):
    def test_load_config_does_not_mutate_raw(self):
        raw = valid_relay_cfg()
        raw_copy = copy.deepcopy(raw)
        plug.load_config(raw)
        self.assertEqual(raw, raw_copy)


if __name__ == "__main__":
    unittest.main()
