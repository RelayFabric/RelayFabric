"""RelayFabric XMPP plugin: bridges XMPP MUC rooms and 1:1 chats over Plugin
Protocol v1.

v1 scope: text only. Multi-user chat (MUC) rooms map to RelayFabric channel
endpoints; inbound 1:1 direct messages are presented on a synthetic
`direct:<jid>` endpoint (the `direct_messages` capability, same pattern as the
meshtastic-direct plugin) so identity-link challenges can flow and a
non-challenge DM is dropped by deny-by-default rather than leaking onto a
channel. Attachments (XEP-0363 HTTP Upload), presence, and OMEMO E2EE are out
of scope this cycle -- plain XMPP is TLS-to-server but SERVER-READABLE, a
gateway (not end-to-end) trust posture.

Licensing: the plugin runs on `slixmpp` (MIT), so it stays Apache-2.0
IN-TREE -- no out-of-process GPL isolation like the signal-cli or
meshtastic-direct plugins.

Module top level imports only stdlib plus the stdlib-only
relayfabric_sdk.bridge, so config/parser/normalize helpers stay importable
without slixmpp installed. slixmpp and the rest of relayfabric_sdk are
imported lazily inside the methods that need them (see XmppBackend.start()
and _make_bridge). Message bodies are never logged, only ids/room/lengths.
"""

import asyncio
import logging
import os
import queue
import threading

from relayfabric_sdk.bridge import FrameWriter, capped_text_send

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"

# Practical ceiling on advertised max_payload regardless of cfg. XMPP itself
# has no small hard limit, but a large body is rude to a mixed fabric; the
# same two-layer safety rationale as the other plugins' *_MAX_PAYLOAD.
XMPP_MAX_PAYLOAD = 8000


def load_config(raw):
    """Load and validate XMPP config.

    Required: jid (str), password (str), channels (non-empty dict; each a
    dict with a str 'muc' room JID). Defaults: nick "relayfabric",
    max_text_bytes 4000. Channels deep-copied.
    """
    cfg = dict(raw)

    if not cfg.get("jid"):
        raise ValueError("config requires 'jid'")
    if not isinstance(cfg["jid"], str):
        raise TypeError("jid must be str")
    if not cfg.get("password"):
        raise ValueError("config requires 'password'")
    if not isinstance(cfg["password"], str):
        raise TypeError("password must be str")
    if not cfg.get("channels"):
        raise ValueError("config requires a non-empty 'channels' mapping")
    if not isinstance(cfg["channels"], dict):
        raise TypeError("channels must be a dict")

    channels_copy = {}
    for name, spec in cfg["channels"].items():
        if not isinstance(spec, dict):
            raise TypeError(f"channel '{name}' must be a dict")
        if not spec.get("muc"):
            raise ValueError(f"channel '{name}' requires 'muc' (a room JID like room@conference.host)")
        if not isinstance(spec["muc"], str):
            raise TypeError(f"channel '{name}' muc must be str")
        channels_copy[name] = dict(spec)
    cfg["channels"] = channels_copy

    cfg.setdefault("nick", "relayfabric")
    if not isinstance(cfg["nick"], str):
        raise TypeError("nick must be str")
    cfg.setdefault("max_text_bytes", 4000)
    if not isinstance(cfg["max_text_bytes"], int):
        raise TypeError(
            f"max_text_bytes must be int, got {type(cfg['max_text_bytes']).__name__}")

    return cfg


def rooms_by_jid(cfg):
    """room JID -> channel name."""
    return {spec["muc"]: name for name, spec in cfg["channels"].items()}


def looks_like_jid(ref):
    """Plausible bare JID for a SendDirect native_ref: `local@domain`, both
    parts non-empty and no whitespace. Loose on purpose -- slixmpp's own send
    is what ultimately proves it routes; this just rejects garbage before a
    scheduled send."""
    if not isinstance(ref, str) or ref.count("@") != 1:
        return False
    local, domain = ref.split("@")
    return bool(local) and bool(domain) and not any(c.isspace() for c in ref)


class XmppBackend:
    """slixmpp transport on a private asyncio loop thread.

    slixmpp is asyncio-native (like meshcore), and none of it composes with
    the synchronous Bridge/main() threads, so this backend owns a private
    event loop on a dedicated daemon thread and crosses threads two ways:
      - inbound: slixmpp event handlers (on the loop thread) normalize the
        stanza to a dict and `queue.Queue.put_nowait()` it, dropping on Full
        with a debug log; events() (the bridge reader thread) blocks on get().
      - outbound: send_muc/send_chat (called from main()'s read loop) schedule
        the (synchronous) `send_message` onto the loop via
        `call_soon_threadsafe`.
    slixmpp auto-reconnects a dropped link on its own; a hard auth failure is
    unrecoverable, so it exits the process for the supervisor to restart.
    """

    def __init__(self, cfg):
        self._jid = cfg["jid"]
        self._password = cfg["password"]
        self._nick = cfg["nick"]
        self._rooms = [spec["muc"] for spec in cfg["channels"].values()]
        self._queue = queue.Queue(maxsize=256)
        self._loop = None
        self._xmpp = None
        self._start_error = None

    def start(self):
        import slixmpp  # lazy: keeps module import stdlib-only (see module docstring)

        self._loop = asyncio.new_event_loop()
        ready = threading.Event()

        def _run():
            asyncio.set_event_loop(self._loop)
            try:
                xmpp = slixmpp.ClientXMPP(self._jid, self._password)
                xmpp.register_plugin("xep_0030")  # service discovery
                xmpp.register_plugin("xep_0045")  # multi-user chat
                xmpp.register_plugin("xep_0199")  # ping (keepalive)
                xmpp.add_event_handler("session_start", self._on_session_start)
                xmpp.add_event_handler("groupchat_message", self._on_muc_message)
                xmpp.add_event_handler("message", self._on_message)
                xmpp.add_event_handler("failed_auth", self._on_failed_auth)
                self._xmpp = xmpp
                xmpp.connect()
            except Exception as e:  # noqa: BLE001 - surfaced to start() via _start_error
                self._start_error = e
            finally:
                ready.set()
            if self._start_error is None:
                self._loop.run_forever()

        threading.Thread(target=_run, daemon=True).start()
        if not ready.wait(timeout=30):
            raise RuntimeError("xmpp connect timed out after 30s")
        if self._start_error is not None:
            raise RuntimeError(f"xmpp start failed: {self._start_error}") from self._start_error

    def _on_session_start(self, _event):
        self._xmpp.send_presence()
        self._xmpp.get_roster()
        muc = self._xmpp.plugin["xep_0045"]
        for room in self._rooms:
            muc.join_muc(room, self._nick)
        log.info(f"XMPP session started; joined {len(self._rooms)} room(s)")

    def _on_muc_message(self, msg):
        # Drop our own reflected messages; the bridge's SentCache is a second
        # echo guard on (channel, text).
        if msg["mucnick"] == self._nick:
            return
        body = msg["body"]
        if not body:
            return
        self._enqueue({
            "kind": "muc",
            "room": msg["from"].bare,
            "sender": msg["mucnick"],
            "text": body,
        })

    def _on_message(self, msg):
        # 'message' fires for everything, including MUC -- skip groupchat here
        # (handled by _on_muc_message) so a room message isn't bridged twice.
        if msg["type"] not in ("chat", "normal"):
            return
        body = msg["body"]
        if not body:
            return
        self._enqueue({"kind": "chat", "from": msg["from"].bare, "text": body})

    def _on_failed_auth(self, _event):
        # Bad credentials never self-heal via reconnect. This runs on the loop
        # thread while main() blocks reading the daemon socket, so os._exit
        # (not sys.exit) terminates the whole process for the supervisor to
        # restart -- same posture as the meshcore/meshtastic-direct backends.
        log.error("XMPP authentication failed; exiting for supervisor restart")
        os._exit(1)

    def _enqueue(self, ev):
        try:
            self._queue.put_nowait(ev)
        except queue.Full:
            log.debug("Dropping XMPP event: queue full")

    def events(self):
        while True:
            yield self._queue.get()

    def queue_depth(self):
        return self._queue.qsize()

    def send_muc(self, room, text):
        if self._loop is None or self._xmpp is None:
            raise RuntimeError("xmpp backend not started")
        self._loop.call_soon_threadsafe(
            lambda: self._xmpp.send_message(mto=room, mbody=text, mtype="groupchat"))

    def send_chat(self, jid, text):
        if self._loop is None or self._xmpp is None:
            raise RuntimeError("xmpp backend not started")
        self._loop.call_soon_threadsafe(
            lambda: self._xmpp.send_message(mto=jid, mbody=text, mtype="chat"))

    def stop(self):
        """Disconnect and stop the loop cleanly on daemon shutdown."""
        loop, xmpp = self._loop, self._xmpp
        if loop is None:
            return
        if xmpp is not None:
            loop.call_soon_threadsafe(xmpp.disconnect)
        loop.call_soon_threadsafe(loop.stop)
        self._xmpp = None


class Bridge(FrameWriter):
    """Bridges normalized XMPP events <-> Plugin Protocol frames.

    Mirrors the MeshCore/Meshtastic Bridge (write lock, SentCache echo guard,
    deny-by-default). handle_event runs on the reader thread; handle_send and
    handle_send_direct on the main thread.
    """

    def __init__(self, cfg, backend, sock_file):
        from relayfabric_sdk import SentCache

        super().__init__(sock_file)
        self.cfg = cfg
        self.backend = backend
        # 1h echo-guard window, as the sibling plugins use: a MUC reflects our
        # own message back; any inbound matching a recent (channel, text) we
        # sent is dropped (own-nick check in the backend is the first guard).
        self.sent_cache = SentCache(ttl_secs=3600)
        self.by_room = rooms_by_jid(cfg)

    def start(self):
        self.backend.start()
        threading.Thread(target=self._reader_loop, daemon=True).start()

    def stop(self):
        # run_plugin calls this on "shutdown"; release the connection cleanly.
        self.backend.stop()

    def _reader_loop(self):
        for ev in self.backend.events():
            try:
                self.handle_event(ev)
            except Exception as e:  # noqa: BLE001 - one bad event must not kill the reader
                log.error(f"XMPP event handler error: {e}")

    # ----- inbound (XMPP -> daemon); reader thread -----

    def handle_event(self, ev):
        from relayfabric_sdk import ipc as relay_ipc

        if ev["kind"] == "muc":
            name = self.by_room.get(ev["room"])
            if name is None:
                return  # unmapped room, drop
            if self.sent_cache.match(name, ev["text"]):
                return  # loop guard: our own reflected message
            self._send_frame(relay_ipc.inbound(name, ev["sender"], ev["text"], None))
            log.info(f"Bridged XMPP MUC message from {ev['sender']} to '{name}' "
                     f"({len(ev['text'])} chars)")
        elif ev["kind"] == "chat":
            # A 1:1 DM on a synthetic per-sender endpoint. The daemon's
            # identity-link challenge matcher keys on (plugin, sender, body)
            # and runs before routing, so a challenge reply is consumed; a
            # non-challenge DM matches no route and is dropped by
            # deny-by-default (a private DM never leaks onto a channel).
            self._send_frame(relay_ipc.inbound(f"direct:{ev['from']}", ev["from"], ev["text"], None))
            log.info(f"Bridged XMPP DM from {ev['from']} ({len(ev['text'])} chars)")

    # ----- egress (daemon -> XMPP); main thread -----

    def handle_send(self, frame):
        capped_text_send(self, frame, "XMPP", "XMPP message",
                         lambda spec, endpoint, body: self.backend.send_muc(spec["muc"], body))

    def handle_send_direct(self, frame):
        """One-shot direct message to a native JID (identity-link challenge
        delivery today; gated by the direct_messages capability)."""
        from relayfabric_sdk import ipc as relay_ipc

        corr, native_ref, body = frame["corr"], frame["native_ref"], frame["body"]
        if not looks_like_jid(native_ref):
            self._send_frame(relay_ipc.delivery_result(corr, False, "invalid destination JID"))
            return
        try:
            self.backend.send_chat(native_ref, body)
        except Exception as e:  # noqa: BLE001 - report, don't crash
            log.warning(f"XMPP DM to {native_ref} failed: {e}")
            self._send_frame(relay_ipc.delivery_result(corr, False, str(e)))
            return
        self._send_frame(relay_ipc.delivery_result(corr, True))
        log.info(f"Sent XMPP DM to {native_ref} ({len(body)} B)")


def hello_max_payload(cfg):
    """min(XMPP_MAX_PAYLOAD, max_text_bytes) -- a lower operator cap tightens
    the advertised max_payload, a higher one never loosens it past the
    practical ceiling."""
    return min(XMPP_MAX_PAYLOAD, cfg["max_text_bytes"])


def _caps(raw_cfg):
    from relayfabric_sdk import ipc as relay_ipc

    # groups: MUC rooms. direct_messages: 1:1 chats (enables identity-linking).
    return relay_ipc.capabilities(groups=True, direct_messages=True,
                                  max_payload=hello_max_payload(load_config(raw_cfg)))


def _make_bridge(raw_cfg, sock):
    cfg = load_config(raw_cfg)
    return Bridge(cfg, XmppBackend(cfg), sock)


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    from relayfabric_sdk import run_plugin

    run_plugin(os.environ.get("RELAYFABRIC_PLUGIN_NAME", "xmpp"),
               PLUGIN_VERSION, _make_bridge, _caps)
