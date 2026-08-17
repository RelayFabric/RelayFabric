"""RelayFabric Nostr plugin: NIP-01 event helpers + config (helpers half;
the backend/bridge/main half lands in a follow-up task).

Module top level is stdlib-only (hashlib/json/logging) so config/event
helpers stay importable without coincurve, websockets, cbor2, or
relayfabric_sdk. Those are imported lazily inside the functions that need
them (verify_event/sign_event import coincurve; the bridge half to come
imports websockets/cbor2/relayfabric_sdk the same way meshcore/signal do).
Note bytes/content are never logged, only pubkeys/kinds/channel names.
"""

import copy
import hashlib
import json
import logging

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"

# Hard ceiling on advertised Hello capabilities.max_payload, independent of
# cfg["max_text_bytes"] (mirrors meshcore's MESHCORE_MAX_PAYLOAD precedent):
# a Nostr kind-1 note is conventionally short-form text (client UIs commonly
# treat ~280 chars as the practical note length), and this keeps the
# advertised cap from being loosened arbitrarily by a misconfigured
# max_text_bytes.
NOSTR_MAX_PAYLOAD = 280


def load_config(raw):
    """Load and validate Nostr plugin configuration (design Sec2).

    Required: 'relays' (non-empty list of ws:// or wss:// URLs); 'channels'
    (non-empty dict name -> {filter: dict (required), relays?: list,
    publish_tags?: list}). Optional: 'max_text_bytes' (default 280, int),
    'identity_file' (default None, str).

    Returns a copy of the config dict with 'channels' deep-copied (unlike
    meshcore's flat {index: int} channel specs, a Nostr channel spec nests
    a mutable filter dict and relays/publish_tags lists, so a shallow
    per-channel dict() copy would still alias those -- mutating the
    returned config's channel filter/relays/publish_tags must never mutate
    the caller's raw dict).

    Raises ValueError for missing/empty required fields, TypeError for type
    violations.
    """
    cfg = dict(raw)

    relays = cfg.get("relays")
    if relays is None:
        raise ValueError("config requires a non-empty 'relays' list")
    if not isinstance(relays, list):
        raise TypeError(f"relays must be a list, got {type(relays).__name__}")
    if not relays:
        raise ValueError("config requires a non-empty 'relays' list")
    for url in relays:
        if not isinstance(url, str):
            raise TypeError(f"relay URL must be str, got {type(url).__name__}")
        if not url.startswith(("ws://", "wss://")):
            raise ValueError(f"relay URL must be ws:// or wss://, got {url!r}")
    cfg["relays"] = list(relays)

    channels = cfg.get("channels")
    if channels is None:
        raise ValueError("config requires a non-empty 'channels' mapping")
    if not isinstance(channels, dict):
        raise TypeError(f"channels must be a dict, got {type(channels).__name__}")
    if not channels:
        raise ValueError("config requires a non-empty 'channels' mapping")

    channels_copy = {}
    for name, spec in channels.items():
        if not isinstance(spec, dict):
            raise TypeError(f"channel '{name}' must be a dict")
        filt = spec.get("filter")
        if filt is None:
            raise ValueError(f"channel '{name}' requires 'filter'")
        if not isinstance(filt, dict):
            raise TypeError(f"channel '{name}' filter must be a dict")
        if "relays" in spec and not isinstance(spec["relays"], list):
            raise TypeError(f"channel '{name}' relays must be a list")
        if "publish_tags" in spec and not isinstance(spec["publish_tags"], list):
            raise TypeError(f"channel '{name}' publish_tags must be a list")
        channels_copy[name] = copy.deepcopy(spec)
    cfg["channels"] = channels_copy

    cfg.setdefault("max_text_bytes", 280)
    if not isinstance(cfg["max_text_bytes"], int):
        raise TypeError(
            f"max_text_bytes must be int, got {type(cfg['max_text_bytes']).__name__}")

    cfg.setdefault("identity_file", None)
    if cfg["identity_file"] is not None and not isinstance(cfg["identity_file"], str):
        raise TypeError(
            f"identity_file must be str, got {type(cfg['identity_file']).__name__}")

    return cfg


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


def normalize_event(event, sub_id, channels_by_sub):
    """Parse a relay-delivered Nostr event into (channel, sender, text, ts)
    or None.

    `sub_id` is the REQ subscription id the relay tagged this event with
    (`["EVENT", sub_id, event]`, design Sec3); `channels_by_sub` maps that
    subscription id to a configured channel name -- how subscription ids
    are assigned (e.g. one per configured channel) is the backend's concern,
    not this helper's.

    Drops (returns None) for, in order:
    - event['kind'] != 1 (text notes only, this cycle)
    - verify_event(event) is False (design Sec80: a relay is untrusted: bad
      sig / wrong id must never bridge; also covers any malformed event
      dict, since verify_event never raises)
    - empty/missing content
    - sub_id not mapped to a configured channel (deny-by-default)

    On success: sender = "nostr:<pubkey hex>" (stable per-author identity,
    design Sec3); ts = event['created_at'].
    """
    if not isinstance(event, dict) or event.get("kind") != 1:
        return None
    if not verify_event(event):
        return None
    content = event.get("content")
    if not content:
        return None
    channel = channels_by_sub.get(sub_id)
    if channel is None:
        return None
    sender = f"nostr:{event['pubkey']}"
    return channel, sender, content, event["created_at"]


def hello_max_payload(cfg):
    """Advertised Hello capabilities.max_payload for this config: the
    smaller of NOSTR_MAX_PAYLOAD and the operator's max_text_bytes (mirrors
    meshcore's hello_max_payload -- a lower max_text_bytes tightens the
    advertised cap; a higher one can never loosen it past NOSTR_MAX_PAYLOAD).
    """
    return min(NOSTR_MAX_PAYLOAD, cfg["max_text_bytes"])
