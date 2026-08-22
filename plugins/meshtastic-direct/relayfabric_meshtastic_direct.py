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


def normalize_packet(pkt, by_index):
    """Parse a meshtastic receive packet into (name, sender, text, ts) or None.

    A meshtastic text packet has `decoded.portnum == "TEXT_MESSAGE_APP"` and
    `decoded.text`. The channel index is `channel` (absent = primary/0). The
    sender is the real per-node id `fromId` ("!hex"), falling back to the
    numeric `from`. `rxTime` is the receive timestamp (may be absent).
    """
    decoded = pkt.get("decoded") or {}
    if decoded.get("portnum") != "TEXT_MESSAGE_APP":
        return None
    text = decoded.get("text")
    if not text or not isinstance(text, str):
        return None

    channel_idx = pkt.get("channel", 0)
    if channel_idx not in by_index:
        return None
    name = by_index[channel_idx]

    sender = pkt.get("fromId")
    if sender is None:
        from_num = pkt.get("from")
        if isinstance(from_num, int):
            sender = f"!{from_num & 0xFFFFFFFF:08x}"
        else:
            return None

    return name, sender, text, pkt.get("rxTime")


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

    def start(self):
        # lazy imports keep the module top-level free of the GPL lib + pubsub
        import meshtastic.ble_interface
        import meshtastic.serial_interface
        import meshtastic.tcp_interface
        from pubsub import pub

        pub.subscribe(self._on_receive, "meshtastic.receive.text")
        pub.subscribe(self._on_lost, "meshtastic.connection.lost")

        if self._kind == "serial":
            self._iface = meshtastic.serial_interface.SerialInterface(devPath=self._target)
        elif self._kind == "tcp":
            host, port = self._target
            self._iface = meshtastic.tcp_interface.TCPInterface(hostname=host, portNumber=port)
        elif self._kind == "ble":
            self._iface = meshtastic.ble_interface.BLEInterface(address=self._target)
        else:
            raise ValueError(f"unsupported connection kind: {self._kind!r}")

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
        parsed = normalize_packet(pkt, self.by_index)
        if parsed is None:
            return
        name, sender, text, ts = parsed
        if self.sent_cache.match(name, text):
            return  # loop guard: node re-broadcast our own downlink
        from relayfabric_sdk import ipc as relay_ipc

        self._send_frame(relay_ipc.inbound(name, sender, text, ts))
        log.info(f"Bridged Meshtastic message from {sender} to '{name}' ({len(text)} chars)")

    # ----- egress (daemon -> Meshtastic); main thread -----

    def handle_send(self, frame):
        capped_text_send(self, frame, "Meshtastic", "Meshtastic message",
                         lambda spec, endpoint, body: self.backend.send_channel(spec["index"], body))


def hello_max_payload(cfg):
    """min(237, max_text_bytes) — a lower operator cap tightens the advertised
    max_payload, a higher one never loosens it past the practical ceiling."""
    return min(MESHTASTIC_MAX_PAYLOAD, cfg["max_text_bytes"])


def _caps(raw_cfg):
    from relayfabric_sdk import ipc as relay_ipc

    return relay_ipc.capabilities(groups=True,
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
