"""RelayFabric Bitchat plugin: config + geohash/event helpers + relay
backend, bridge, and entry point.

Bridges Bitchat's public geohash channels over Nostr (design
docs/superpowers/specs/2026-08-16-bitchat-plugin-design.md, "Bitchat-over-
Nostr conventions"): ephemeral kind-20000 events, channel = tag
["g", <geohash>], geohash is a base32 string over the alphabet
"0123456789bcdefghjkmnpqrstuvwxyz", optional ["n", <nickname>] tag, plaintext
UTF-8 content. This is a thin specialization of the Nostr plugin
(plugins/nostr/relayfabric_nostr.py) -- same config/normalize/Backend/
Bridge/main shape, Bitchat wire conventions instead of arbitrary NIP-01
filters/tags.

Module top level is stdlib-only (asyncio/copy/json/logging/os/queue/socket/
sys/threading/time) so config/geohash helpers stay importable without
coincurve, websockets, cbor2, or relayfabric_sdk. The NIP-01 event
primitives (sign_event/verify_event/load_or_create_identity, promoted to
relayfabric_sdk.nip01 in cycle J) are imported lazily inside
build_bitchat_event/normalize_event/BitchatBackend.publish/main() --
the same lazy-import convention plugins/nostr/relayfabric_nostr.py uses (see
its module docstring); BitchatBackend.start() imports websockets; Bridge and
main() import the rest of relayfabric_sdk. Note: content bytes are never
logged, only pubkeys/geohashes/channel names/kinds.
"""

import asyncio
import copy
import json
import logging
import os
import queue
import socket
import sys
import threading
import time

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"

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
        if "relays" in spec:
            if not isinstance(spec["relays"], list):
                raise TypeError(f"channel '{name}' relays must be a list")
            for url in spec["relays"]:
                if not isinstance(url, str):
                    raise TypeError(
                        f"channel '{name}' relay URL must be str, "
                        f"got {type(url).__name__}")
                if not url.startswith(("ws://", "wss://")):
                    raise ValueError(
                        f"channel '{name}' relay URL must be ws:// or wss://, "
                        f"got {url!r}")
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


class BitchatBackend:
    """websockets-library transport for Bitchat geohash channels -- the
    backend seam Bridge depends on (swappable for a FakeBackend in Bridge
    tests; exercised directly via a fake `websockets` module injected into
    sys.modules for backend-level tests, per the fleet's meshcore/nostr
    precedent).

    Near-clone of plugins/nostr's NostrBackend (same asyncio-loop-daemon-
    thread, one-ws-per-unique-relay, REQ-per-channel, bounded-queue,
    exponential-backoff-reconnect shape); differs only in the Bitchat wire
    conventions: the REQ filter is `req_filter(spec)` (kind-20000 + `#g`
    geohash) rather than an arbitrary NIP-01 filter, the subid->channel map
    carries `{"name":..., "geohash":...}` (not a bare name -- normalize_event
    needs the geohash to defend against a relay sending a wrong-geohash
    event on our subscription, design Sec80), and publish() builds a
    kind-20000 event via build_bitchat_event.

    One WebSocket connection per UNIQUE relay across the union of all
    configured channels' relay sets (a relay used by two channels gets one
    connection, two REQ subscriptions). Each connection runs as an
    independent asyncio task on a private event-loop daemon thread
    (asyncio.new_event_loop() + run_forever()) and reconnects with
    exponential backoff on drop/error -- one relay being down never blocks
    another, and start() does not block waiting for any relay to actually
    connect.

    Inbound: on each (re)connect, sends `["REQ", subid, req_filter(spec)]`
    for every channel whose relay set includes that relay (subid =
    "rf-<channel>", a stable per-channel id -- see __init__); the read loop
    parses each incoming frame via _handle_message, which normalizes
    `["EVENT", subid, event]` frames (verifying the event's schnorr sig and
    geohash tag -- design Sec80, a relay is untrusted) into a bounded
    queue.Queue(256), drop-newest with a debug log on Full; `["OK"|"EOSE"|
    "NOTICE", ...]` are logged at debug and otherwise ignored. events()
    yields the normalized (channel, sender, text, nym, ts) tuples forever.

    Outbound: publish(channel, text) builds a signed kind-20000 event
    (channel's geohash + nickname) and best-effort sends it to every relay
    in the channel's relay set that currently has a live connection, via
    run_coroutine_threadsafe(...).result(timeout=30); success is "sent to
    at least one relay" (delivered = accepted by this backend, not a
    relay-level OK ack), and RuntimeError only when every relay send
    failed/there was no live connection to any of them.
    """

    def __init__(self, relays, channels, identity):
        self.relays = list(relays)
        self.channels = channels
        self.privkey_hex, self.pubkey_hex = identity
        self._queue = queue.Queue(maxsize=256)
        self._loop = None
        # relay url -> live websocket connection; populated/cleared only
        # from the backend's own loop thread (_relay_loop), read from
        # publish()'s coroutine (also loop-thread, via run_coroutine_threadsafe).
        self._connections = {}
        self._subid_to_channel = {
            f"rf-{name}": {"name": name, "geohash": spec["geohash"]}
            for name, spec in self.channels.items()
        }
        self._channel_to_subid = {name: f"rf-{name}" for name in self.channels}
        self._relay_channels = {}
        for name, spec in self.channels.items():
            for relay_url in (spec.get("relays") or self.relays):
                self._relay_channels.setdefault(relay_url, []).append(name)

    def start(self):
        import websockets  # lazy: keeps module import stdlib-only (see module docstring)

        self._loop = asyncio.new_event_loop()
        ready = threading.Event()

        def _run():
            asyncio.set_event_loop(self._loop)
            ready.set()
            self._loop.run_forever()

        threading.Thread(target=_run, daemon=True).start()
        ready.wait(timeout=5)
        for relay_url in self._relay_channels:
            asyncio.run_coroutine_threadsafe(
                self._relay_loop(relay_url, websockets), self._loop)

    async def _relay_loop(self, relay_url, websockets_mod):
        """Connect to one relay forever, resubscribing on every (re)connect
        and reconnecting with exponential backoff (capped at 60s) on drop
        or error -- runs as an independent task per relay so one dead relay
        never blocks another's connection or resubscription.
        """
        backoff = 1
        while True:
            try:
                async with websockets_mod.connect(relay_url) as ws:
                    self._connections[relay_url] = ws
                    backoff = 1
                    for name in self._relay_channels[relay_url]:
                        subid = self._channel_to_subid[name]
                        filt = req_filter(self.channels[name])
                        await ws.send(json.dumps(["REQ", subid, filt]))
                    async for raw in ws:
                        self._handle_message(raw)
            except Exception as e:  # noqa: BLE001 - a relay drop must not kill the task
                log.debug(f"bitchat relay {relay_url} connection error: {e}")
            finally:
                self._connections.pop(relay_url, None)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)

    def _handle_message(self, raw):
        """Parse and route one relay-delivered frame. Never raises: a relay
        is untrusted (design Sec80) and this runs inside _relay_loop's
        per-relay task, so a malformed/adversarial frame must not kill that
        relay's connection.
        """
        try:
            msg = json.loads(raw)
        except (TypeError, ValueError):
            return
        if not isinstance(msg, list) or not msg:
            return
        kind = msg[0]
        if kind == "EVENT":
            if len(msg) < 3:
                return
            sub_id, event = msg[1], msg[2]
            try:
                parsed = normalize_event(event, sub_id, self._subid_to_channel)
            except TypeError:
                # e.g. an unhashable sub_id (a list/dict) from a malformed
                # frame -- normalize_event's dict.get(sub_id) would raise.
                return
            if parsed is None:
                return
            try:
                self._queue.put_nowait(parsed)
            except queue.Full:
                log.debug("Dropping bitchat event: queue full")
        elif kind == "OK":
            log.debug(f"bitchat OK: {msg[1:]}")
        elif kind == "EOSE":
            log.debug(f"bitchat EOSE: {msg[1:]}")
        elif kind == "NOTICE":
            log.debug(f"bitchat NOTICE: {msg[1:]}")
        # unknown message kind: ignore

    def events(self):
        """Yield normalized (channel, sender, text, nym, ts) tuples from the
        queue forever."""
        while True:
            yield self._queue.get()

    def publish(self, channel, text):
        if self._loop is None:
            raise RuntimeError("bitchat backend not started")
        spec = self.channels.get(channel)
        if spec is None:
            raise RuntimeError(f"unknown channel {channel!r}")
        relays = spec.get("relays") or self.relays
        event = build_bitchat_event(
            self.privkey_hex, spec["geohash"], spec.get("nickname"), text,
            int(time.time()))
        fut = asyncio.run_coroutine_threadsafe(
            self._publish_to_relays(event, relays), self._loop)
        try:
            any_ok = fut.result(timeout=30)
        except Exception as e:
            raise RuntimeError(f"bitchat publish to '{channel}' failed: {e}") from e
        if not any_ok:
            raise RuntimeError(
                f"bitchat publish to '{channel}' failed: no reachable relay "
                f"among {relays}")

    async def _publish_to_relays(self, event, relays):
        msg = json.dumps(["EVENT", event])
        any_ok = False
        for relay_url in relays:
            ws = self._connections.get(relay_url)
            if ws is None:
                continue  # not currently connected to this relay
            try:
                await ws.send(msg)
                any_ok = True
            except Exception as e:  # noqa: BLE001 - try the remaining relays
                log.debug(f"bitchat publish to {relay_url} failed: {e}")
        return any_ok


class Bridge:
    """Bridges normalized Bitchat events <-> Plugin Protocol frames. Mirrors
    plugins/nostr's Bridge shape (write lock, _send_frame, SentCache loop
    guard, deny-by-default, oversize defensive drop) with one difference:
    BitchatBackend.events() yields a `nym` element too (`(channel, sender,
    text, nym, ts)`, unlike the Nostr plugin's `(channel, sender, text,
    ts)`) -- handle_event ignores it for this cycle (design "OUT": nickname
    beyond passthrough for the render tag is not built out here) but keeps
    the tuple shape aligned with what BitchatBackend actually produces.
    Verification/normalization happens backend-side before the queue (see
    BitchatBackend), so handle_event has no "normalize returned None" case
    of its own to handle.

    handle_event runs on the backend's reader thread; handle_send runs on
    the main thread; all daemon-socket writes go through _send_frame,
    serialized by one lock.
    """

    def __init__(self, cfg, backend, sock_file):
        from relayfabric_sdk import SentCache

        self.cfg = cfg
        self.backend = backend
        self.sock_file = sock_file
        self.write_lock = threading.Lock()
        # 1h, not SentCache's 86400s default: mirrors meshcore/nostr's echo
        # loop-guard window (bounds how long a lost echo/ack can leave a
        # stale entry able to swallow one genuine identical-text message).
        self.sent_cache = SentCache(ttl_secs=3600)

    def _send_frame(self, obj):
        from relayfabric_sdk import ipc as relay_ipc

        with self.write_lock:
            relay_ipc.write_frame(self.sock_file, obj)

    # ----- inbound (Bitchat -> daemon); called from the backend's reader thread -----

    def handle_event(self, parsed):
        channel, sender, text, _nym, ts = parsed

        if self.sent_cache.match(channel, text):
            return  # loop guard: our own published event came back on the subscription

        from relayfabric_sdk import ipc as relay_ipc

        self._send_frame(relay_ipc.inbound(channel, sender, text, ts))
        log.info(f"Bridged Bitchat event from {sender} to '{channel}' "
                 f"({len(text)} chars)")

    # ----- egress (daemon -> Bitchat); called from the main thread -----

    def handle_send(self, frame):
        from relayfabric_sdk import ipc as relay_ipc

        corr = frame["corr"]
        endpoint = frame["endpoint"]
        body = frame["body"]
        channel_spec = self.cfg["channels"].get(endpoint)
        if channel_spec is None:
            log.warning(f"Bitchat send to unknown endpoint {endpoint!r}")
            self._send_frame(relay_ipc.delivery_result(corr, False, "unknown endpoint"))
            return

        body_bytes = len(body.encode("utf-8"))
        max_bytes = self.cfg["max_text_bytes"]
        if body_bytes > max_bytes:
            # defensive: the daemon should have already truncated to our
            # advertised capabilities.max_payload before it ever sends us
            # this frame.
            detail = f"body {body_bytes} B exceeds max_text_bytes {max_bytes} B"
            log.warning(f"Bitchat send to '{endpoint}' dropped: {detail}")
            self._send_frame(relay_ipc.delivery_result(corr, False, detail))
            return

        try:
            self.backend.publish(endpoint, body)
        except Exception as e:  # noqa: BLE001 - report the failure, don't crash
            log.warning(f"Bitchat send to '{endpoint}' failed: {e}")
            self._send_frame(relay_ipc.delivery_result(corr, False, str(e)))
            return
        # delivered = send accepted by the backend (spec Sec70), not a
        # relay-level OK acknowledgement.
        self.sent_cache.record(endpoint, body)
        self._send_frame(relay_ipc.delivery_result(corr, True))
        log.info(f"Sent Bitchat event to '{endpoint}' ({body_bytes} B)")


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    sock_path = os.environ["RELAYFABRIC_SOCKET"]
    plugin_name = os.environ.get("RELAYFABRIC_PLUGIN_NAME", "bitchat")
    raw_cfg = json.loads(os.environ.get("RELAYFABRIC_PLUGIN_CONFIG", "{}"))
    # Scrub the resolved config (may carry secrets substituted by the daemon
    # from a ${env:}/${file:} reference) out of our own environment so any
    # child process this plugin spawns doesn't inherit it.
    os.environ.pop("RELAYFABRIC_PLUGIN_CONFIG", None)
    try:
        cfg = load_config(raw_cfg)
    except (ValueError, TypeError) as e:
        print(f"relayfabric-bitchat: invalid config: {e}", file=sys.stderr)
        sys.exit(1)

    from relayfabric_sdk import ipc as relay_ipc

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    rfile = sock.makefile("rb")
    wfile = sock.makefile("wb")

    caps = relay_ipc.capabilities(text=True, max_payload=hello_max_payload(cfg))
    relay_ipc.write_frame(wfile, relay_ipc.hello(plugin_name, PLUGIN_VERSION, caps))
    ack = relay_ipc.read_frame(rfile)
    if ack.get("t") != "hello_ack" or ack.get("error"):
        print(f"relayfabric-bitchat: hello rejected: {ack.get('error')}",
             file=sys.stderr)
        sys.exit(1)

    from relayfabric_sdk.nip01 import load_or_create_identity

    identity = load_or_create_identity(cfg["identity_file"])
    backend = BitchatBackend(cfg["relays"], cfg["channels"], identity)
    bridge = Bridge(cfg, backend, wfile)
    backend.start()

    def reader_loop():
        for ev in backend.events():
            try:
                bridge.handle_event(ev)
            except Exception as e:  # noqa: BLE001 - one bad event must not kill the reader
                log.error(f"Bitchat event handler error: {e}")

    threading.Thread(target=reader_loop, daemon=True).start()

    while True:
        try:
            frame = relay_ipc.read_frame(rfile)
        except (EOFError, OSError, ValueError) as e:
            # ValueError: oversize/corrupt frame (relay_ipc.read_frame's own
            # MAX_FRAME check). The stream is desynced at that point, so exit
            # rather than continue -- there is no way to resume mid-frame.
            log.error(f"Daemon connection lost, exiting: {e}")
            sys.exit(1)
        kind = frame.get("t")
        if kind == "send":
            bridge.handle_send(frame)
        elif kind == "shutdown":
            sys.exit(0)
