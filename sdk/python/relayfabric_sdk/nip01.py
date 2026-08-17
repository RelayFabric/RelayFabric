"""NIP-01 event primitives: canonical event id, schnorr sign/verify, and
identity load/generate.

Moved verbatim from plugins/nostr/relayfabric_nostr.py (cycle J): NIP-01
event id/sig are protocol-frozen (BIP-340 schnorr over the exact canonical
`[0, pubkey, created_at, kind, tags, content]` serialization), so this is a
shared primitive like ipc/cache/harness rather than nostr-plugin-specific
code -- the bitchat plugin imports the same functions so there is one
tested copy of the crypto, not two copies that can drift.

Module top level is stdlib-only (hashlib/json/logging/os); coincurve is
imported lazily inside verify_event/sign_event/load_or_create_identity (the
fleet's lazy-import convention) so this module stays importable without
coincurve installed.
"""

import hashlib
import json
import logging
import os

log = logging.getLogger(__name__)


def event_id(pubkey_hex, created_at, kind, tags, content):
    """NIP-01 event id: sha256 hex of the canonical serialization
    `[0, pubkey, created_at, kind, tags, content]` -- compact separators,
    UTF-8, no extra whitespace, exactly as NIP-01 specifies. See
    test_relayfabric_nostr.py's EventIdGoldenVectorTests for the locked
    known-answer vector (nsec=1, the secp256k1 generator scalar).
    """
    serialized = json.dumps(
        [0, pubkey_hex, created_at, kind, tags, content],
        separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def verify_event(event):
    """True iff event's id matches the recomputed NIP-01 sha256 AND its
    schnorr sig verifies (BIP-340) over that id, under event['pubkey'].

    MUST NOT raise: a relay sends arbitrary dicts (design Sec80 -- a relay
    is untrusted), so any KeyError/TypeError/ValueError from a malformed or
    adversarial event (missing keys, wrong types, non-hex/wrong-length
    id/pubkey/sig, non-dict input entirely) is caught and treated as an
    invalid event, never propagated.
    """
    try:
        pubkey_hex = event["pubkey"]
        created_at = event["created_at"]
        kind = event["kind"]
        tags = event["tags"]
        content = event["content"]
        claimed_id = event["id"]
        sig_hex = event["sig"]

        recomputed_id = event_id(pubkey_hex, created_at, kind, tags, content)
        if recomputed_id != claimed_id:
            return False

        from coincurve import PublicKeyXOnly

        pub = PublicKeyXOnly(bytes.fromhex(pubkey_hex))
        return pub.verify(bytes.fromhex(sig_hex), bytes.fromhex(recomputed_id))
    except Exception:  # noqa: BLE001 - malformed/adversarial input, never propagate
        return False


def sign_event(privkey_hex, created_at, kind, tags, content):
    """Build a full signed NIP-01 event {id, pubkey, created_at, kind, tags,
    content, sig} from a 32-byte hex private key ("nsec hex", design Sec1 --
    the raw hex form, not bech32). Round-trips through verify_event().
    """
    from coincurve import PrivateKey, PublicKeyXOnly

    priv = PrivateKey(bytes.fromhex(privkey_hex))
    pubkey_hex = PublicKeyXOnly.from_valid_secret(priv.secret).format().hex()
    eid = event_id(pubkey_hex, created_at, kind, tags, content)
    sig_hex = priv.sign_schnorr(bytes.fromhex(eid)).hex()
    return {
        "id": eid,
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig_hex,
    }


def load_or_create_identity(identity_file):
    """Load this plugin's Nostr keypair, generating one on first run.

    If `identity_file` is set and already holds a key (one line, 32-byte
    hex privkey -- the same "nsec hex" form sign_event takes), load it.
    Otherwise generate a fresh secp256k1 key via coincurve; if
    `identity_file` is set, persist the new key there with mode 0600
    (os.open O_CREAT so the restrictive mode is atomic with creation, no
    window where the key sits world-readable) so restarts reuse the same
    identity. A None `identity_file` means a fresh identity every start
    (no path to persist to) -- config-valid per load_config, but every
    restart then publishes under a new pubkey.

    Logs the public key (hex; loosely "npub", though this is the raw hex
    form, not bech32) exactly once. Never logs the private key.

    Returns (privkey_hex, pubkey_hex).
    """
    from coincurve import PrivateKey, PublicKeyXOnly

    if identity_file and os.path.exists(identity_file):
        with open(identity_file) as f:
            privkey_hex = f.read().strip()
    else:
        privkey_hex = PrivateKey().secret.hex()
        if identity_file:
            fd = os.open(identity_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(privkey_hex + "\n")

    pubkey_hex = PublicKeyXOnly.from_valid_secret(
        PrivateKey(bytes.fromhex(privkey_hex)).secret).format().hex()
    log.info(f"Nostr identity pubkey (npub, hex): {pubkey_hex}")
    return privkey_hex, pubkey_hex
