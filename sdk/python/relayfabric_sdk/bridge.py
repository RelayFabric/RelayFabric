"""Shared Bridge plumbing for the plugin fleet.

Module top level is stdlib-only (the package __init__ is lazy, so importing
this from a plugin's module top level pulls no cbor2/paho/etc.); ipc is
imported inside the functions that write frames, mirroring the plugins'
own lazy-import convention.
"""

import logging
import threading

log = logging.getLogger(__name__)


class FrameWriter:
    """Owns the daemon socket file and the write lock every Bridge
    re-declared: all daemon-socket writes go through _send_frame, serialized
    by one lock (handle_event runs on a backend reader thread, handle_send
    on the main thread).
    """

    def __init__(self, sock_file):
        self.sock_file = sock_file
        self.write_lock = threading.Lock()

    def _send_frame(self, obj):
        from . import ipc

        with self.write_lock:
            ipc.write_frame(self.sock_file, obj)


def capped_text_send(bridge, frame, label, sent_what, publish):
    """The endpoint-lookup -> size-cap -> publish -> delivery_result dance
    four plugins carried verbatim (differing only in label and publish call).

    `bridge` needs: cfg["channels"], cfg["max_text_bytes"], _send_frame,
    sent_cache. `publish(channel_spec, endpoint, body)` raises on failure.
    """
    from . import ipc

    corr = frame["corr"]
    endpoint = frame["endpoint"]
    body = frame["body"]
    channel_spec = bridge.cfg["channels"].get(endpoint)
    if channel_spec is None:
        log.warning(f"{label} send to unknown endpoint {endpoint!r}")
        bridge._send_frame(ipc.delivery_result(corr, False, "unknown endpoint"))
        return

    body_bytes = len(body.encode("utf-8"))
    max_bytes = bridge.cfg["max_text_bytes"]
    if body_bytes > max_bytes:
        # defensive: the daemon should have already truncated to the
        # advertised capabilities.max_payload before sending this frame.
        detail = f"body {body_bytes} B exceeds max_text_bytes {max_bytes} B"
        log.warning(f"{label} send to '{endpoint}' dropped: {detail}")
        bridge._send_frame(ipc.delivery_result(corr, False, detail))
        return

    try:
        publish(channel_spec, endpoint, body)
    except Exception as e:  # noqa: BLE001 - report the failure, don't crash
        log.warning(f"{label} send to '{endpoint}' failed: {e}")
        bridge._send_frame(ipc.delivery_result(corr, False, str(e)))
        return
    # delivered = send accepted by the backend (spec Sec70), not an
    # end-to-end delivery acknowledgement.
    bridge.sent_cache.record(endpoint, body)
    bridge._send_frame(ipc.delivery_result(corr, True))
    log.info(f"Sent {sent_what} to '{endpoint}' ({body_bytes} B)")
