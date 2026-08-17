"""RelayFabric Bitchat plugin: config + geohash/event helpers.

Bridges Bitchat's public geohash channels over Nostr (design
docs/superpowers/specs/2026-08-16-bitchat-plugin-design.md, "Bitchat-over-
Nostr conventions"): ephemeral kind-20000 events, channel = tag
["g", <geohash>], geohash is a base32 string over the alphabet
"0123456789bcdefghjkmnpqrstuvwxyz", optional ["n", <nickname>] tag, plaintext
UTF-8 content. This is a thin specialization of the Nostr plugin
(plugins/nostr/relayfabric_nostr.py) -- same config/normalize shape, Bitchat
wire conventions instead of arbitrary NIP-01 filters/tags.

This module holds Task 2's "helpers half" (load_config, is_geohash,
req_filter, build_bitchat_event, normalize_event, hello_max_payload); Task 3
appends the relay/websocket backend, Bridge, and main() that consume them
(mirroring plugins/nostr's Backend/Bridge/main shape).

Module top level is stdlib-only (copy) so config/geohash helpers stay
importable without coincurve or relayfabric_sdk. The NIP-01 event primitives
(sign_event/verify_event, promoted to relayfabric_sdk.nip01 in cycle J) are
imported lazily inside build_bitchat_event/normalize_event -- the same
lazy-import convention plugins/nostr/relayfabric_nostr.py uses (see its
module docstring); Task 3's backend/main() will do the same for
websockets/relayfabric_sdk. Note: content bytes are never logged, only
pubkeys/geohashes/channel names/kinds.
"""

import copy

# Nostr ephemeral-range kind reserved for Bitchat public geohash chat
# (design "Bitchat-over-Nostr conventions", HIGH confidence -- convergent
# across bitchat-in-browser's PROTOCOL.md, glub-chat, and NYM).
BITCHAT_KIND = 20000

# Bitchat geohash base32 alphabet (design "Bitchat-over-Nostr conventions").
GEOHASH_CHARSET = frozenset("0123456789bcdefghjkmnpqrstuvwxyz")

# Hard ceiling on advertised Hello capabilities.max_payload, independent of
# cfg["max_text_bytes"] (mirrors the Nostr plugin's NOSTR_MAX_PAYLOAD
# precedent): a Bitchat geohash message is conventionally short-form text,
# and this keeps the advertised cap from being loosened arbitrarily by a
# misconfigured max_text_bytes.
BITCHAT_MAX_PAYLOAD = 280


def is_geohash(s):
    """True iff `s` is a non-empty string containing only characters from
    the Bitchat geohash base32 alphabet (design "Bitchat-over-Nostr
    conventions": "0123456789bcdefghjkmnpqrstuvwxyz", lowercase)."""
    return isinstance(s, str) and bool(s) and all(c in GEOHASH_CHARSET for c in s)


def load_config(raw):
    """Load and validate Bitchat plugin configuration (design Sec2).

    Required: 'relays' (non-empty list of ws:// or wss:// URLs); 'channels'
    (non-empty dict name -> {geohash: base32 str (required, validated via
    is_geohash: non-empty, chars in the Bitchat geohash alphabet), relays?:
    list, nickname?: str}). Optional: 'max_text_bytes' (default 280, int),
    'identity_file' (default None, str).

    Returns a copy of the config dict with 'channels' deep-copied (mirrors
    the Nostr plugin's load_config: a channel spec's 'relays' list is
    mutable and must not alias the caller's raw dict -- a shallow per-channel
    dict() copy would still alias it).

    Raises ValueError for missing/empty/invalid-format required fields,
    TypeError for type violations.
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
        geohash = spec.get("geohash")
        if geohash is None:
            raise ValueError(f"channel '{name}' requires 'geohash'")
        if not isinstance(geohash, str):
            raise TypeError(
                f"channel '{name}' geohash must be str, got {type(geohash).__name__}")
        if not is_geohash(geohash):
            raise ValueError(
                f"channel '{name}' geohash {geohash!r} is not a valid base32 geohash")
        if "relays" in spec and not isinstance(spec["relays"], list):
            raise TypeError(f"channel '{name}' relays must be a list")
        if "nickname" in spec and spec["nickname"] is not None \
                and not isinstance(spec["nickname"], str):
            raise TypeError(f"channel '{name}' nickname must be str")
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


def req_filter(channel_spec):
    """Inbound Nostr REQ filter for a configured Bitchat channel spec
    (design "Bitchat-over-Nostr conventions"): subscribes to kind-20000
    events tagged with the channel's geohash."""
    return {"kinds": [BITCHAT_KIND], "#g": [channel_spec["geohash"]]}


def build_bitchat_event(privkey, geohash, nickname, text, now):
    """Build a signed kind-20000 Bitchat geohash-channel event.

    Tags: `["g", geohash]` always, plus `["n", nickname]` iff `nickname` is
    truthy (design: the nickname tag is optional -- passthrough only, no
    nickname is invented). Delegates id/signing to
    relayfabric_sdk.nip01.sign_event, so the result round-trips through
    nip01.verify_event.
    """
    from relayfabric_sdk.nip01 import sign_event

    tags = [["g", geohash]]
    if nickname:
        tags.append(["n", nickname])
    return sign_event(privkey, now, BITCHAT_KIND, tags, text)


def normalize_event(event, sub_id, subid_to_channel):
    """Parse a relay-delivered Bitchat event into (channel, sender, text,
    nym, ts) or None.

    `subid_to_channel` maps a REQ subscription id to
    `{"name": <channel name str>, "geohash": <configured geohash str>}` --
    how subscription ids are assigned per channel is the backend's concern
    (Task 3), not this helper's. Unlike the Nostr plugin's name-only
    `channels_by_sub`, the geohash is carried here too because this
    function must defend against a relay sending a wrong-geohash event on
    our subscription (design "Bitchat-over-Nostr conventions" + Sec80).

    Drops (returns None) for, in order:
    - verify_event(event) is False (design Sec80: a relay is untrusted --
      bad sig / wrong id must never bridge; also covers any malformed event
      dict, since verify_event never raises)
    - event['kind'] != 20000
    - sub_id not mapped to a configured channel (deny-by-default)
    - the event has no `["g", ...]` tag, or its value doesn't equal the
      mapped channel's configured geohash (defense: don't bridge a
      mismatched-geohash event a relay sent on our subscription)
    - empty/missing content

    On success: sender = "bitchat:<pubkey hex>" (stable per-author
    identity); nym = the event's `["n", ...]` tag value if present, else
    None; ts = event['created_at'].
    """
    from relayfabric_sdk.nip01 import verify_event

    if not verify_event(event):
        return None
    if event.get("kind") != BITCHAT_KIND:
        return None
    entry = subid_to_channel.get(sub_id)
    if entry is None:
        return None

    g_value = None
    nym = None
    for tag in event.get("tags") or []:
        if not isinstance(tag, list) or len(tag) < 2:
            continue
        if tag[0] == "g" and g_value is None:
            g_value = tag[1]
        elif tag[0] == "n" and nym is None:
            nym = tag[1]
    if g_value != entry["geohash"]:
        return None

    content = event.get("content")
    if not content:
        return None

    sender = f"bitchat:{event['pubkey']}"
    return entry["name"], sender, content, nym, event["created_at"]


def hello_max_payload(cfg):
    """Advertised Hello capabilities.max_payload for this config: the
    smaller of BITCHAT_MAX_PAYLOAD and the operator's max_text_bytes
    (mirrors the Nostr plugin's hello_max_payload -- a lower max_text_bytes
    tightens the advertised cap; a higher one can never loosen it past
    BITCHAT_MAX_PAYLOAD).
    """
    return min(BITCHAT_MAX_PAYLOAD, cfg["max_text_bytes"])
