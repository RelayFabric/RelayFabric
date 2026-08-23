# SPDX-License-Identifier: GPL-3.0-or-later
#
# RelayFabric Meshtastic (direct) plugin.
# Copyright (C) 2026 Jascha Wanger / RelayFabric contributors.
#
# UNLIKE THE REST OF RELAYFABRIC (Apache-2.0), THIS PLUGIN IS GPL-3.0-or-later,
# because it imports the official `meshtastic` Python library, which is
# GPL-3.0 (the whole Meshtastic library ecosystem is GPL, derived from the
# GPL-licensed protobuf definitions). The GPL is isolated to THIS PLUGIN'S
# PROCESS: it is a separate process that talks to the daemon only over the
# Apache-licensed CBOR Unix-socket IPC and depends on the Apache-licensed
# relayfabric_sdk (permissive -> GPL is one-way compatible), so switchyardd
# and every other crate stay Apache-2.0. See README.md and LICENSE.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version. Full text: https://www.gnu.org/licenses/gpl-3.0.html
#
# ---------------------------------------------------------------------------
#
# Direct Meshtastic bridge over serial/TCP/BLE via the meshtastic protobuf
# API — the GPL-accepting alternative to the permissive, MQTT-JSON-gateway
# `meshtastic` plugin (both ship; an operator runs one). The direct path
# needs no MQTT broker, sends downlinks as the connected node's OWN identity
# (so the MQTT plugin's `from: 0` firmware-rejection risk does not exist
# here), and surfaces real per-node sender ids (`fromId`).
#
# Module top level imports only stdlib plus the stdlib-only
# relayfabric_sdk.bridge, so config/parser/normalize helpers stay importable
# without the meshtastic/pubsub/cbor2 packages. meshtastic + pubsub and the
# rest of relayfabric_sdk are imported lazily inside the methods that need
# them (see MeshtasticDirectBackend.start() and _make_bridge). Text bytes are
# never logged, only ids/channel names.

import logging
import os
import queue
import threading
import time
import urllib.parse

from relayfabric_sdk.bridge import FrameWriter, capped_text_send

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"

GAUGES_INTERVAL_SECS = 30

# Hard ceiling on advertised max_payload regardless of cfg["max_text_bytes"]:
# 237 is Meshtastic's practical text payload limit. Same two-layer-safety
# rationale as the MQTT plugin's MESHTASTIC_MAX_PAYLOAD.
MESHTASTIC_MAX_PAYLOAD = 237

# Meshtastic broadcast address / default TCP API port.
BROADCAST_ADDR = "^all"
DEFAULT_TCP_PORT = 4403

# Bound the (blocking) interface construction. A BLE connect to a node that is
# out of range, powered off, or already held by another central (e.g. a phone
# running the Meshtastic app) blocks forever, leaving a plugin that is
# IPC-connected but radio-dead and un-restartable by the supervisor. On
# timeout start() raises, so run_plugin's start-failure exits the process for
# the supervisor to restart -- mirroring the MeshCore backend's 30s posture.
CONNECT_TIMEOUT_SECS = 30


def _build_with_timeout(builder, timeout):
    """Run blocking `builder()` on a worker thread, returning its result.

    Raises RuntimeError if it doesn't finish within `timeout` seconds, or
    re-raises whatever the builder raised. The worker is a daemon thread, so a
    builder still stuck at timeout does not keep the process alive.
    """
    box = {}

    def _run():
        try:
            box["result"] = builder()
        except BaseException as e:  # noqa: BLE001 - surfaced to caller below
            box["error"] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise RuntimeError(
            f"meshtastic connect timed out after {timeout:g}s "
            "(node out of range, powered off, or held by another BLE central?)")
    if "error" in box:
        raise box["error"]
    return box["result"]


def load_config(raw):
    """Load and validate direct-Meshtastic config.

    Required: connection (str), channels (non-empty dict; each a dict with
    an int 'index'). Default: max_text_bytes 200. Channels deep-copied.
    """
    cfg = dict(raw)

    if not cfg.get("connection"):
        raise ValueError("config requires 'connection'")
    if not isinstance(cfg["connection"], str):
        raise TypeError("connection must be str")
    if not cfg.get("channels"):
        raise ValueError("config requires a non-empty 'channels' mapping")
    if not isinstance(cfg["channels"], dict):
        raise TypeError("channels must be a dict")

    channels_copy = {}
    for name, spec in cfg["channels"].items():
        if not isinstance(spec, dict):
            raise TypeError(f"channel '{name}' must be a dict")
        if "index" not in spec:
            raise ValueError(f"channel '{name}' requires 'index'")
        if not isinstance(spec["index"], int):
            raise TypeError(
                f"channel '{name}' index must be int, got {type(spec['index']).__name__}")
        channels_copy[name] = dict(spec)
    cfg["channels"] = channels_copy

    cfg.setdefault("max_text_bytes", 200)
    if not isinstance(cfg["max_text_bytes"], int):
        raise TypeError(
            f"max_text_bytes must be int, got {type(cfg['max_text_bytes']).__name__}")

    return cfg


def parse_connection(url):
    """Parse a connection URL into (kind, target, opts).

    - serial://<path> -> ("serial", path, {})
    - tcp://host[:port] -> ("tcp", (host, port), {}) (port defaults to 4403)
    - ble://<addr> -> ("ble", addr, {})
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "serial":
        path = parsed.netloc + parsed.path
        if not path:
            raise ValueError("serial:// requires a path")
        return "serial", path, {}
    if parsed.scheme == "tcp":
        if not parsed.hostname:
            raise ValueError("tcp:// requires a host")
        return "tcp", (parsed.hostname, parsed.port or DEFAULT_TCP_PORT), {}
    if parsed.scheme == "ble":
        addr = parsed.netloc + parsed.path
        if not addr:
            raise ValueError("ble:// requires an address")
        return "ble", addr, {}
    raise ValueError(
        f"unsupported connection scheme: {parsed.scheme!r}; "
        "supported: serial://, tcp://, ble://")


def channels_by_index(cfg):
    """index -> channel name."""
    return {spec["index"]: name for name, spec in cfg["channels"].items()}


BROADCAST_NUM = 0xFFFFFFFF


def _text_fields(pkt):
    """(sender, text, ts) from a Meshtastic text packet, or None if it isn't
    a usable text message. Sender is the real per-node id `fromId` ("!hex"),
    falling back to the numeric `from`; `rxTime` is the receive timestamp."""
    decoded = pkt.get("decoded") or {}
    if decoded.get("portnum") != "TEXT_MESSAGE_APP":
        return None
    text = decoded.get("text")
    if not text or not isinstance(text, str):
        return None
    sender = pkt.get("fromId")
    if sender is None:
        from_num = pkt.get("from")
        if isinstance(from_num, int):
            sender = f"!{from_num & 0xFFFFFFFF:08x}"
        else:
            return None
    return sender, text, pkt.get("rxTime")


def normalize_packet(pkt, by_index):
    """Parse a channel-broadcast text packet into (name, sender, text, ts)
    or None. The channel index is `channel` (absent = primary/0); an
    unmapped index is dropped. Direct messages (to a specific node) are
    handled separately in the bridge, not here."""
    fields = _text_fields(pkt)
    if fields is None:
        return None
    sender, text, ts = fields
    channel_idx = pkt.get("channel", 0)
    if channel_idx not in by_index:
        return None
    return by_index[channel_idx], sender, text, ts


def looks_like_node_ref(ref):
    """Plausible Meshtastic destination: a `!` + 8 hex-digit node id, or a
    bare numeric node number. Gate on a SendDirect native_ref before handing
    it to the radio (mirrors the LXMF plugin's looks_like_hex_ref)."""
    if not isinstance(ref, str) or not ref:
        return False
    if ref.startswith("!"):
        h = ref[1:]
        return len(h) == 8 and all(c in "0123456789abcdefABCDEF" for c in h)
    return ref.isdigit()


class MeshtasticDirectBackend:
    """meshtastic-library transport over the protobuf API (serial/TCP/BLE).

    The meshtastic library (GPL-3.0) is synchronous: the interface object
    owns its own reader thread and delivers inbound packets through pypubsub
    topics. This backend subscribes to `meshtastic.receive.text`, normalizes
    each packet, and puts it on a bounded queue the bridge's reader thread
    drains; sending is a direct, thread-safe `interface.sendText`. A dropped
    link (`meshtastic.connection.lost`) exits the process for the daemon's
    supervisor to restart, matching the MeshCore backend's posture.
    """

    def __init__(self, connection_url):
        self._kind, self._target, self._opts = parse_connection(connection_url)
        self._queue = queue.Queue(maxsize=256)
        self._iface = None
        # Our own node number, captured at connect — used to tell a direct
        # message (to == us) from a channel broadcast.
        self.my_node_num = None

    def start(self):
        # lazy imports keep the module top-level free of the GPL lib + pubsub
        import meshtastic.ble_interface
        import meshtastic.serial_interface
        import meshtastic.tcp_interface
        from pubsub import pub

        pub.subscribe(self._on_receive, "meshtastic.receive.text")
        pub.subscribe(self._on_lost, "meshtastic.connection.lost")

        if self._kind == "serial":
            build = lambda: meshtastic.serial_interface.SerialInterface(devPath=self._target)
        elif self._kind == "tcp":
            host, port = self._target
            build = lambda: meshtastic.tcp_interface.TCPInterface(hostname=host, portNumber=port)
        elif self._kind == "ble":
            build = lambda: meshtastic.ble_interface.BLEInterface(address=self._target)
        else:
            raise ValueError(f"unsupported connection kind: {self._kind!r}")

        # Bounded connect: a hung BLE/TCP connect raises instead of blocking
        # forever, so the supervisor restarts a radio-dead plugin (see
        # CONNECT_TIMEOUT_SECS).
        self._iface = _build_with_timeout(build, CONNECT_TIMEOUT_SECS)

        # Capture our own node number so inbound DMs (to == us) can be told
        # from channel broadcasts. Best-effort: if the lib layout differs,
        # DM detection simply stays off and channel bridging is unaffected.
        try:
            self.my_node_num = self._iface.myInfo.my_node_num
        except AttributeError:
            log.warning("meshtastic: could not read my_node_num; DMs won't be distinguished")

    def _on_receive(self, packet, interface):  # noqa: ARG002 - pubsub signature
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            log.debug("Dropping meshtastic packet: event queue full")

    def _on_lost(self, interface):  # noqa: ARG002 - pubsub signature
        # Runs on the interface's own thread; main() is blocked reading the
        # daemon socket, so os._exit(1) (not sys.exit) terminates the whole
        # process for the supervisor to restart -- same rationale as the
        # MeshCore backend's DISCONNECTED handler.
        log.error("meshtastic: connection lost, exiting for supervisor restart")
        os._exit(1)

    def events(self):
        while True:
            yield self._queue.get()

    def queue_depth(self):
        return self._queue.qsize()

    def send_channel(self, idx, text):
        if self._iface is None:
            raise RuntimeError("meshtastic backend not started")
        # Sends as THIS node's own identity (not from:0), on the given
        # channel, broadcast to the channel. Raises on transport failure.
        self._iface.sendText(text, destinationId=BROADCAST_ADDR, channelIndex=idx)

    def send_direct(self, node_ref, text):
        """A direct message to a specific node (identity-link challenge
        delivery). Sent as this node's own identity; the library selects the
        channel/PKI for the destination."""
        if self._iface is None:
            raise RuntimeError("meshtastic backend not started")
        self._iface.sendText(text, destinationId=node_ref)

    def stop(self):
        """Close the radio interface so a BLE link isn't left
        connected-not-advertising (which blocks the next connect). Best-effort
        and idempotent: a close error must not derail daemon shutdown."""
        iface = self._iface
        self._iface = None
        if iface is None:
            return
        try:
            iface.close()
        except Exception as e:  # noqa: BLE001 - shutdown must not crash on a bad close
            log.warning(f"meshtastic: error closing interface on stop: {e}")


class Bridge(FrameWriter):
    """Bridges normalized Meshtastic packets <-> Plugin Protocol frames.

    Mirrors the MeshCore/MQTT-Meshtastic Bridge (write lock, SentCache echo
    guard, deny-by-default, gauges). handle_event runs on the reader thread;
    handle_send on the main thread.
    """

    def __init__(self, cfg, backend, sock_file):
        from relayfabric_sdk import SentCache

        super().__init__(sock_file)
        self.cfg = cfg
        self.backend = backend
        # 1h echo-guard window, as the sibling plugins use: the node
        # re-broadcasts our own downlink, so any uplink matching a recent
        # (channel, text) we sent is dropped.
        self.sent_cache = SentCache(ttl_secs=3600)
        self.by_index = channels_by_index(cfg)
        self._last_gauges_at = time.monotonic()

    def start(self):
        self.backend.start()
        threading.Thread(target=self._reader_loop, daemon=True).start()

    def stop(self):
        # run_plugin calls this on "shutdown"; release the radio cleanly.
        self.backend.stop()

    def _reader_loop(self):
        for pkt in self.backend.events():
            try:
                self.handle_event(pkt)
            except Exception as e:  # noqa: BLE001 - one bad packet must not kill the reader
                log.error(f"Meshtastic (direct) event handler error: {e}")

    def _maybe_emit_gauges(self, pkt):
        import math

        now = time.monotonic()
        if now - self._last_gauges_at < GAUGES_INTERVAL_SECS:
            return
        self._last_gauges_at = now
        values = {}
        for src, key in (("rxSnr", "snr"), ("rxRssi", "rssi")):
            v = pkt.get(src)
            if isinstance(v, (int, float)) and math.isfinite(v):
                values[key] = v
        if not values:
            values["queue_depth"] = self.backend.queue_depth()
        from relayfabric_sdk import ipc as relay_ipc

        self._send_frame(relay_ipc.gauges(values))

    # ----- inbound (Meshtastic -> daemon); reader thread -----

    def handle_event(self, pkt):
        self._maybe_emit_gauges(pkt)
        from relayfabric_sdk import ipc as relay_ipc

        # Direct message to us (to == our own node) vs. channel broadcast.
        my = self.backend.my_node_num
        to = pkt.get("to")
        if my is not None and to == my and to != BROADCAST_NUM:
            fields = _text_fields(pkt)
            if fields is None:
                return
            sender, text, ts = fields
            # Present on a synthetic per-sender endpoint. The daemon's
            # identity-link challenge matcher keys on (plugin, sender, body)
            # and runs before routing, so a challenge reply is consumed;
            # a non-challenge DM matches no route and is dropped by
            # deny-by-default (a private DM never leaks onto a channel).
            # No echo guard: a DM to us is never our own re-broadcast.
            self._send_frame(relay_ipc.inbound(f"direct:{sender}", sender, text, ts))
            log.info(f"Bridged Meshtastic DM from {sender} ({len(text)} chars)")
            return

        parsed = normalize_packet(pkt, self.by_index)
        if parsed is None:
            return
        name, sender, text, ts = parsed
        if self.sent_cache.match(name, text):
            return  # loop guard: node re-broadcast our own downlink
        self._send_frame(relay_ipc.inbound(name, sender, text, ts))
        log.info(f"Bridged Meshtastic message from {sender} to '{name}' ({len(text)} chars)")

    # ----- egress (daemon -> Meshtastic); main thread -----

    def handle_send(self, frame):
        capped_text_send(self, frame, "Meshtastic", "Meshtastic message",
                         lambda spec, endpoint, body: self.backend.send_channel(spec["index"], body))

    def handle_send_direct(self, frame):
        """One-shot direct message to a native node ref (identity-link
        challenge delivery today; gated by the direct_messages capability)."""
        from relayfabric_sdk import ipc as relay_ipc

        corr, native_ref, body = frame["corr"], frame["native_ref"], frame["body"]
        if not looks_like_node_ref(native_ref):
            self._send_frame(relay_ipc.delivery_result(corr, False, "invalid destination ref"))
            return
        try:
            self.backend.send_direct(native_ref, body)
        except Exception as e:  # noqa: BLE001 - report, don't crash
            log.warning(f"Meshtastic DM to {native_ref} failed: {e}")
            self._send_frame(relay_ipc.delivery_result(corr, False, str(e)))
            return
        self._send_frame(relay_ipc.delivery_result(corr, True))
        log.info(f"Sent Meshtastic DM to {native_ref} ({len(body)} B)")


def hello_max_payload(cfg):
    """min(237, max_text_bytes) — a lower operator cap tightens the advertised
    max_payload, a higher one never loosens it past the practical ceiling."""
    return min(MESHTASTIC_MAX_PAYLOAD, cfg["max_text_bytes"])


def _caps(raw_cfg):
    from relayfabric_sdk import ipc as relay_ipc

    # direct_messages: the direct API can deliver a DM to a node's own
    # identity (identity-link challenge delivery), unlike the MQTT-JSON
    # plugin which advertises channel-only.
    return relay_ipc.capabilities(groups=True, direct_messages=True,
                                  max_payload=hello_max_payload(load_config(raw_cfg)))


def _make_bridge(raw_cfg, sock):
    cfg = load_config(raw_cfg)
    return Bridge(cfg, MeshtasticDirectBackend(cfg["connection"]), sock)


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    from relayfabric_sdk import run_plugin

    run_plugin(os.environ.get("RELAYFABRIC_PLUGIN_NAME", "meshtastic-direct"),
               PLUGIN_VERSION, _make_bridge, _caps)
