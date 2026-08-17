import os
import tempfile
import unittest

from relayfabric_sdk import nip01

# "Known nsec" golden vector (brief's explicit fallback: the NIP-01 spec
# itself has no fully-worked example event with concrete id/sig -- confirmed
# by fetching nostr-protocol/nips/01.md directly, and web search results for
# one returned internally-inconsistent hex lengths, i.e. fabricated). nsec=1
# is the best-known private key in secp256k1 (scalar 1): its x-only pubkey is
# the curve generator point G, independently verifiable against any
# secp256k1 reference (e.g. SEC2) -- 79be667ef9dcbbac...16f81798. The
# resulting id/sig below were computed once via coincurve + hashlib directly
# (not through nip01.event_id) and locked here as regression constants: if a
# future change to the JSON serialization (separators, key order, escaping)
# shifts the id, this test catches it.
#
# Moved verbatim from plugins/nostr/test_relayfabric_nostr.py (cycle J,
# alongside the event_id/verify_event/sign_event promotion to
# relayfabric_sdk.nip01) -- same locked hex, same test bodies.
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


class EventIdGoldenVectorTests(unittest.TestCase):
    """Locks the exact NIP-01 canonical serialization / sha256 event id."""

    def test_golden_vector_id(self):
        eid = nip01.event_id(GOLDEN_PUBKEY_HEX, GOLDEN_CREATED_AT, GOLDEN_KIND,
                             GOLDEN_TAGS, GOLDEN_CONTENT)
        self.assertEqual(eid, GOLDEN_ID)

    def test_serialization_is_compact_no_whitespace(self):
        # id must change if separators/whitespace drift -- assert indirectly
        # via the locked id, and directly via a known tags/content case that
        # would break under default (", ", ": ") json separators.
        eid = nip01.event_id("ab" * 32, 1, 1, [["t", "x"]], "hi")
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
        eid1 = nip01.event_id(GOLDEN_PUBKEY_HEX, GOLDEN_CREATED_AT, GOLDEN_KIND,
                              GOLDEN_TAGS, GOLDEN_CONTENT)
        eid2 = nip01.event_id(GOLDEN_PUBKEY_HEX, GOLDEN_CREATED_AT, GOLDEN_KIND,
                              GOLDEN_TAGS, GOLDEN_CONTENT)
        self.assertEqual(eid1, eid2)


class SignVerifyRoundTripTests(unittest.TestCase):
    def test_golden_vector_sig_verifies(self):
        event = {
            "id": GOLDEN_ID, "pubkey": GOLDEN_PUBKEY_HEX,
            "created_at": GOLDEN_CREATED_AT, "kind": GOLDEN_KIND,
            "tags": GOLDEN_TAGS, "content": GOLDEN_CONTENT, "sig": GOLDEN_SIG,
        }
        self.assertTrue(nip01.verify_event(event))

    def test_sign_event_round_trips(self):
        event = nip01.sign_event(GOLDEN_PRIVKEY_HEX, 1700000001, 1, [], "round trip")
        self.assertTrue(nip01.verify_event(event))
        self.assertEqual(event["pubkey"], GOLDEN_PUBKEY_HEX)
        self.assertEqual(len(event["sig"]), 128)
        self.assertEqual(len(event["id"]), 64)

    def test_sign_event_id_matches_event_id_helper(self):
        event = nip01.sign_event(GOLDEN_PRIVKEY_HEX, 1700000002, 1, [["t", "x"]], "hi")
        recomputed = nip01.event_id(event["pubkey"], event["created_at"],
                                    event["kind"], event["tags"], event["content"])
        self.assertEqual(event["id"], recomputed)

    def test_different_content_yields_different_sig(self):
        e1 = nip01.sign_event(GOLDEN_PRIVKEY_HEX, 1700000003, 1, [], "a")
        e2 = nip01.sign_event(GOLDEN_PRIVKEY_HEX, 1700000003, 1, [], "b")
        self.assertNotEqual(e1["id"], e2["id"])
        self.assertNotEqual(e1["sig"], e2["sig"])


class VerifyEventRejectsTests(unittest.TestCase):
    def _valid_event(self):
        return nip01.sign_event(GOLDEN_PRIVKEY_HEX, 1700000010, 1, [], "tamper me")

    def test_tampered_id_rejected(self):
        event = self._valid_event()
        event["id"] = "0" * 64
        self.assertFalse(nip01.verify_event(event))

    def test_tampered_content_rejected(self):
        # id no longer matches recomputed sha256 once content changes.
        event = self._valid_event()
        event["content"] = "different content"
        self.assertFalse(nip01.verify_event(event))

    def test_tampered_sig_rejected(self):
        event = self._valid_event()
        good_sig = event["sig"]
        # flip the last hex nibble
        event["sig"] = good_sig[:-1] + ("0" if good_sig[-1] != "0" else "1")
        self.assertFalse(nip01.verify_event(event))

    def test_wrong_pubkey_rejected(self):
        event = self._valid_event()
        event["pubkey"] = "ab" * 32
        self.assertFalse(nip01.verify_event(event))

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
                    result = nip01.verify_event(ev)
                except Exception as e:  # noqa: BLE001 - the property under test
                    self.fail(f"verify_event raised {e!r} on {ev!r}")
                self.assertFalse(result)

    def test_never_raises_on_non_dict_input(self):
        for ev in [None, "not a dict", [], 42, object()]:
            with self.subTest(ev=ev):
                try:
                    result = nip01.verify_event(ev)
                except Exception as e:  # noqa: BLE001 - the property under test
                    self.fail(f"verify_event raised {e!r} on {ev!r}")
                self.assertFalse(result)


class LoadOrCreateIdentityTests(unittest.TestCase):
    """Moved verbatim from plugins/nostr/test_relayfabric_nostr.py (cycle J
    Task 4): load_or_create_identity is a NIP-01 identity primitive, not
    Nostr-plugin-specific, so its tests belong alongside the rest of
    relayfabric_sdk.nip01's suite, not stranded in a plugin's test file."""

    def test_generates_when_no_identity_file(self):
        privkey_hex, pubkey_hex = nip01.load_or_create_identity(None)
        self.assertEqual(len(privkey_hex), 64)
        self.assertEqual(len(pubkey_hex), 64)
        bytes.fromhex(privkey_hex)  # must be valid hex
        bytes.fromhex(pubkey_hex)

    def test_no_identity_file_is_ephemeral_across_calls(self):
        priv1, _pub1 = nip01.load_or_create_identity(None)
        priv2, _pub2 = nip01.load_or_create_identity(None)
        self.assertNotEqual(priv1, priv2)

    def test_generates_and_persists_when_file_absent(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nostr.nsec")
            self.assertFalse(os.path.exists(path))
            priv1, pub1 = nip01.load_or_create_identity(path)
            self.assertTrue(os.path.exists(path))
            priv2, pub2 = nip01.load_or_create_identity(path)
            self.assertEqual(priv1, priv2)
            self.assertEqual(pub1, pub2)

    def test_persisted_file_permissions_are_0600(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nostr.nsec")
            nip01.load_or_create_identity(path)
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_loads_existing_privkey_from_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nostr.nsec")
            with open(path, "w") as f:
                f.write(GOLDEN_PRIVKEY_HEX + "\n")
            priv, pub = nip01.load_or_create_identity(path)
            self.assertEqual(priv, GOLDEN_PRIVKEY_HEX)
            self.assertEqual(pub, GOLDEN_PUBKEY_HEX)

    def test_derived_pubkey_matches_sign_event(self):
        priv, pub = nip01.load_or_create_identity(None)
        event = nip01.sign_event(priv, 1700000000, 1, [], "hi")
        self.assertEqual(event["pubkey"], pub)

    def test_logs_pubkey_exactly_once(self):
        with self.assertLogs(nip01.log, level="INFO") as cm:
            _priv, pub = nip01.load_or_create_identity(None)
        self.assertEqual(len(cm.output), 1)
        self.assertIn(pub, cm.output[0])


if __name__ == "__main__":
    unittest.main()
