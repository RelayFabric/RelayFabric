"""RelayFabric Nostr plugin: bridges Nostr relays (NIP-01 kind-1 notes) over
Plugin Protocol v1 (relayfabric_sdk).

Module top level imports only stdlib plus the stdlib-only
relayfabric_sdk.bridge, so config helpers stay importable without coincurve,
websockets, or cbor2. Those are imported lazily inside the functions/methods
that need them: the NIP-01 event primitives (event id, schnorr sign/verify,
identity load/generate) live in relayfabric_sdk.nip01 (promoted there in
cycle J so the bitchat plugin can share the same tested crypto) and are
imported where normalize_event/NostrBackend.publish/_make_bridge call them;
NostrBackend.start() imports websockets -- the same lazy-import shape
meshcore/signal use. Note bytes/content are never logged, only
pubkeys/kinds/channel names.
"""

import asyncio
import copy
import json
import logging
import os
import queue
import threading
import time

from relayfabric_sdk.bridge import FrameWriter, capped_text_send

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
    from relayfabric_sdk.nip01 import verify_event

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


class NostrBackend:
    """websockets-library transport -- the backend seam Bridge depends on
    (swappable for a FakeBackend in Bridge tests; exercised directly via a
    fake `websockets` module injected into sys.modules for backend-level
    tests, per the fleet's meshcore precedent).

    One WebSocket connection per UNIQUE relay across the union of all
    configured channels' relay sets (a relay used by two channels gets one
    connection, two REQ subscriptions). Each connection runs as an
    independent asyncio task on a private event-loop daemon thread
    (asyncio.new_event_loop() + run_forever(), meshcore precedent) and
    reconnects with exponential backoff on drop/error -- one relay being
    down never blocks another, and start() does not block waiting for any
    relay to actually connect (unlike meshcore's single-transport
    ready.wait(), there is no single "connected" state to gate on here).

    Inbound: on each (re)connect, sends `["REQ", subid, filter]` for every
    channel whose relay set includes that relay (subid = "rf-<channel>", a
    stable per-channel id -- see __init__); the read loop parses each
    incoming frame via _handle_message, which normalizes `["EVENT", subid,
    event]` frames (verifying the event's schnorr sig -- design Sec80, a
    relay is untrusted) into a bounded queue.Queue(256), drop-newest with a
    debug log on Full; `["OK"|"EOSE"|"NOTICE", ...]` are logged at debug and
    otherwise ignored. events() yields the normalized (channel, sender,
    text, ts) tuples forever.

    Outbound: publish(channel, text) signs a kind-1 event (channel's
    publish_tags) and best-effort sends it to every relay in the channel's
    relay set that currently has a live connection, via
    run_coroutine_threadsafe(...).result(timeout=30); success is "sent to
    at least one relay" (delivered = accepted by this backend, not a
    relay-level OK ack -- same posture as meshcore's send_channel), and
    RuntimeError only when every relay send failed/there was no live
    connection to any of them.
    """

    def __init__(self, relays, channels, identity):
        self.relays = list(relays)
        self.channels = channels
        self.privkey_hex, _ = identity
        self._queue = queue.Queue(maxsize=256)
        self._loop = None
        # relay url -> live websocket connection; populated/cleared only
        # from the backend's own loop thread (_relay_loop), read from
        # publish()'s coroutine (also loop-thread, via run_coroutine_threadsafe).
        self._connections = {}
        self._subid_to_channel = {f"rf-{name}": name for name in self.channels}
        self._channel_to_subid = {name: subid for subid, name in
                                   self._subid_to_channel.items()}
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
                        filt = self.channels[name]["filter"]
                        await ws.send(json.dumps(["REQ", subid, filt]))
                    async for raw in ws:
                        self._handle_message(raw)
            except Exception as e:  # noqa: BLE001 - a relay drop must not kill the task
                log.debug(f"nostr relay {relay_url} connection error: {e}")
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
                log.debug("Dropping nostr event: queue full")
        elif kind == "OK":
            log.debug(f"nostr OK: {msg[1:]}")
        elif kind == "EOSE":
            log.debug(f"nostr EOSE: {msg[1:]}")
        elif kind == "NOTICE":
            log.debug(f"nostr NOTICE: {msg[1:]}")
        # unknown message kind: ignore

    def events(self):
        """Yield normalized (channel, sender, text, ts) tuples from the
        queue forever."""
        while True:
            yield self._queue.get()

    def publish(self, channel, text):
        from relayfabric_sdk.nip01 import sign_event

        if self._loop is None:
            raise RuntimeError("nostr backend not started")
        spec = self.channels.get(channel)
        if spec is None:
            raise RuntimeError(f"unknown channel {channel!r}")
        tags = spec.get("publish_tags") or []
        relays = spec.get("relays") or self.relays
        event = sign_event(self.privkey_hex, int(time.time()), 1, tags, text)
        fut = asyncio.run_coroutine_threadsafe(
            self._publish_to_relays(event, relays), self._loop)
        try:
            any_ok = fut.result(timeout=30)
        except Exception as e:
            raise RuntimeError(f"nostr publish to '{channel}' failed: {e}") from e
        if not any_ok:
            raise RuntimeError(
                f"nostr publish to '{channel}' failed: no reachable relay "
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
                log.debug(f"nostr publish to {relay_url} failed: {e}")
        return any_ok


class Bridge(FrameWriter):
    """Bridges normalized Nostr events <-> Plugin Protocol frames. Mirrors
    plugins/meshcore's Bridge shape (write lock, _send_frame, SentCache loop
    guard, deny-by-default, oversize defensive drop) with one difference:
    NostrBackend.events() already yields fully normalized (channel, sender,
    text, ts) tuples (normalize_event needs the sub_id -> channel map, which
    only the backend holds, so verification/normalization happens
    backend-side before the queue -- see NostrBackend), so handle_event has
    no "normalize returned None" case of its own to handle.

    handle_event runs on the backend's reader thread; handle_send runs on
    the main thread; all daemon-socket writes go through _send_frame,
    serialized by one lock.
    """

    def __init__(self, cfg, backend, sock_file):
        from relayfabric_sdk import SentCache

        super().__init__(sock_file)
        self.cfg = cfg
        self.backend = backend
        # 1h, not SentCache's 86400s default: mirrors meshcore/meshtastic's
        # echo loop-guard window (bounds how long a lost echo/ack can leave
        # a stale entry able to swallow one genuine identical-text message).
        self.sent_cache = SentCache(ttl_secs=3600)

    def start(self):
        self.backend.start()
        threading.Thread(target=self._reader_loop, daemon=True).start()

    def _reader_loop(self):
        for ev in self.backend.events():
            try:
                self.handle_event(ev)
            except Exception as e:  # noqa: BLE001 - one bad event must not kill the reader
                log.error(f"Nostr event handler error: {e}")

    # ----- inbound (Nostr -> daemon); called from the backend's reader thread -----

    def handle_event(self, parsed):
        channel, sender, text, ts = parsed

        if self.sent_cache.match(channel, text):
            return  # loop guard: our own published note came back on the subscription

        from relayfabric_sdk import ipc as relay_ipc

        self._send_frame(relay_ipc.inbound(channel, sender, text, ts))
        log.info(f"Bridged Nostr event from {sender} to '{channel}' "
                 f"({len(text)} chars)")

    # ----- egress (daemon -> Nostr); called from the main thread -----

    def handle_send(self, frame):
        capped_text_send(self, frame, "Nostr", "Nostr event",
                         lambda spec, endpoint, body: self.backend.publish(endpoint, body))


def _caps(raw_cfg):
    from relayfabric_sdk import ipc as relay_ipc

    return relay_ipc.capabilities(text=True,
                                  max_payload=hello_max_payload(load_config(raw_cfg)))


def _make_bridge(raw_cfg, sock):
    from relayfabric_sdk.nip01 import load_or_create_identity

    cfg = load_config(raw_cfg)
    identity = load_or_create_identity(cfg["identity_file"])
    return Bridge(cfg, NostrBackend(cfg["relays"], cfg["channels"], identity), sock)


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    from relayfabric_sdk import run_plugin

    run_plugin(os.environ.get("RELAYFABRIC_PLUGIN_NAME", "nostr"),
               PLUGIN_VERSION, _make_bridge, _caps)
