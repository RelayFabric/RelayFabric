"""run_plugin: shared main-loop scaffold for the plugin fleet.

Consolidates the env contract -> Hello/HelloAck handshake -> dispatch-table
read loop that lxmf/signal/meshtastic/meshcore each hand-rolled identically
in their main() functions. A plugin adopts it by building a `bridge_factory`
(cfg_dict, sock) -> object with a `handle_send(frame)` method, and calling
`run_plugin(name, version, bridge_factory, capabilities)`.

`connect` is a dependency-injection seam for tests only: it defaults to a
real AF_UNIX connect + a single duplex `sock.makefile("rwb")` (one object
used for both read_frame and write_frame, exactly like FakeSock), and every
real caller leaves it at the default.

Send handling runs on a dedicated worker thread, NOT the read loop: a
plugin's `handle_send` can block up to ~30s on a slow/unreachable backend
(capped_text_send's publish timeout), and doing that inline would stall the
read loop -- ping/pong liveness (the daemon restarts a plugin that stops
answering) and shutdown must keep flowing regardless. One worker preserves
send ordering and single-threaded backend access; a plugin that wants
concurrent sends (LXMF) still does its own internal fan-out.
"""

import json
import os
import queue
import socket
import sys
import threading

from .ipc import delivery_result, hello, pong, read_frame, write_frame

# Bound on queued (not yet started) sends; see the module docstring.
SEND_QUEUE_MAX = 256


class _SendQueue:
    """Bounded FIFO of (kind, frame) send work with corr dedup.

    `offer` returns "queued", "duplicate" (a send for that corr is already
    queued or in flight) or "full". A frame with no (or an unhashable)
    corr is never deduped. `release(corr)` after the send reaches its
    result lets a later re-dispatch of the same corr through again.
    """

    def __init__(self, maxsize=SEND_QUEUE_MAX):
        self._q = queue.Queue(maxsize=maxsize)
        self._pending = set()
        self._lock = threading.Lock()

    @staticmethod
    def _key(frame):
        corr = frame.get("corr") if isinstance(frame, dict) else None
        try:
            hash(corr)
        except TypeError:
            return None
        return corr

    def offer(self, kind, frame):
        corr = self._key(frame)
        with self._lock:
            if corr is not None and corr in self._pending:
                return "duplicate"
            try:
                self._q.put_nowait((kind, frame))
            except queue.Full:
                return "full"
            if corr is not None:
                self._pending.add(corr)
            return "queued"

    def release(self, corr):
        try:
            hash(corr)
        except TypeError:
            return
        with self._lock:
            self._pending.discard(corr)

    def get(self):
        return self._q.get()

    def close(self):
        # Shutdown sentinel; bypasses the bound so shutdown can never block.
        self._q.put(None)


def _connect_socket(sock_path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    return sock.makefile("rwb")


def run_plugin(plugin_name, version, bridge_factory, capabilities, *,
                socket_env="RELAYFABRIC_SOCKET", config_env="RELAYFABRIC_PLUGIN_CONFIG",
                connect=_connect_socket):
    """Run a plugin's main loop until shutdown or an unrecoverable error.

    - Missing `socket_env` -> stderr line + exit 2.
    - Connects, sends Hello(plugin_name, version, capabilities), reads
      HelloAck; a non-"hello_ack" frame or a truthy "error" -> stderr line +
      exit 1. `capabilities` may be a callable taking the parsed config dict
      and returning the caps dict, for plugins whose advertised caps depend
      on config (e.g. a config-derived max_payload).
    - Calls `bridge_factory(cfg_dict, sock)`; if the returned object has a
      `start()`, calls it before entering the read loop.
    - A ValueError/TypeError from the capabilities callable or
      bridge_factory (the plugins' load_config validation errors) -> clean
      "invalid config" stderr line + exit 1.
    - Read loop: "send" -> bridge.handle_send(frame); "send_direct" ->
      bridge.handle_send_direct(frame) if present, else ignored; "shutdown"
      -> bridge.stop() if present, then exit 0; unknown "t" -> ignored;
      (EOFError, OSError, ValueError) while reading -> stderr line + exit 1.
    - Sends queue on a bounded, corr-deduped worker queue (SEND_QUEUE_MAX):
      a re-dispatch of a queued/in-flight corr is dropped, and an overflow
      is answered with delivery_result(corr, False, "plugin busy").
    """
    try:
        sock_path = os.environ[socket_env]
    except KeyError:
        print(f"{plugin_name}: missing required env var {socket_env}", file=sys.stderr)
        sys.exit(2)

    raw_cfg = json.loads(os.environ.get(config_env, "{}"))
    # Scrub the resolved config (may carry secrets substituted by the daemon
    # from a ${env:}/${file:} reference) out of our own environment so any
    # child process this plugin spawns (e.g. lxmf's media.py running ffmpeg
    # over attacker-supplied audio) doesn't inherit it.
    os.environ.pop(config_env, None)
    sock = connect(sock_path)

    try:
        caps = capabilities(raw_cfg) if callable(capabilities) else capabilities
    except (ValueError, TypeError) as e:
        print(f"{plugin_name}: invalid config: {e}", file=sys.stderr)
        sys.exit(1)

    write_frame(sock, hello(plugin_name, version, caps))
    ack = read_frame(sock)
    if ack.get("t") != "hello_ack" or ack.get("error"):
        print(f"{plugin_name}: hello rejected: {ack.get('error')}", file=sys.stderr)
        sys.exit(1)

    try:
        bridge = bridge_factory(raw_cfg, sock)
    except (ValueError, TypeError) as e:
        print(f"{plugin_name}: invalid config: {e}", file=sys.stderr)
        sys.exit(1)
    start = getattr(bridge, "start", None)
    if start is not None:
        start()

    # Send/send_direct run on this worker, off the read loop (see module
    # docstring). One worker => sends stay ordered and the backend is touched
    # from a single thread, exactly as when they ran inline.
    send_q = _SendQueue(maxsize=SEND_QUEUE_MAX)

    def _send_frame(obj):
        # Through the bridge's locked writer when it has one (never
        # interleave with a frame its reader thread is writing); else direct.
        send_frame = getattr(bridge, "_send_frame", None)
        if send_frame is not None:
            send_frame(obj)
        else:
            write_frame(sock, obj)

    def _enqueue(kind, frame):
        outcome = send_q.offer(kind, frame)
        if outcome == "duplicate":
            print(f"{plugin_name}: ignoring re-dispatched {kind} for in-flight corr "
                  f"{frame.get('corr')!r}", file=sys.stderr)
        elif outcome == "full":
            corr = frame.get("corr")
            print(f"{plugin_name}: send queue full ({SEND_QUEUE_MAX}), refusing corr "
                  f"{corr!r}", file=sys.stderr)
            if corr is not None:
                _send_frame(delivery_result(corr, False, "plugin busy"))

    def _dispatch(kind, frame):
        # A malformed frame (missing corr/endpoint/body) must not kill the
        # worker; the read path is already hardened, keep dispatch symmetric.
        try:
            if kind == "send":
                bridge.handle_send(frame)
            else:  # "send_direct"
                handle_send_direct = getattr(bridge, "handle_send_direct", None)
                if handle_send_direct is not None:
                    handle_send_direct(frame)
        except Exception as e:  # noqa: BLE001 - one bad frame must not kill the worker
            print(f"{plugin_name}: error handling {kind} frame: {e}", file=sys.stderr)

    def _sender_loop():
        while True:
            item = send_q.get()
            if item is None:  # shutdown sentinel
                return
            kind, frame = item
            try:
                _dispatch(kind, frame)
            finally:
                send_q.release(frame.get("corr") if isinstance(frame, dict) else None)

    sender = threading.Thread(target=_sender_loop, name=f"{plugin_name}-sender", daemon=True)
    sender.start()

    while True:
        try:
            frame = read_frame(sock)
        except (EOFError, OSError, ValueError) as e:
            # ValueError: oversize/corrupt frame (read_frame's own MAX_FRAME
            # check). The stream is desynced at that point, so exit rather
            # than continue -- there is no way to resume mid-frame.
            print(f"{plugin_name}: daemon connection lost, exiting: {e}", file=sys.stderr)
            sys.exit(1)

        kind = frame.get("t")
        if kind == "ping":
            # Liveness probe: answered ON the read loop (never queued behind a
            # slow send) or the daemon would restart us as wedged. Go through
            # the bridge's locked writer so this never interleaves with a frame
            # the bridge's reader thread or the sender worker is writing; fall
            # back to a direct write for a bridge that isn't a FrameWriter.
            _send_frame(pong())
        elif kind == "send":
            _enqueue("send", frame)
        elif kind == "send_direct":
            _enqueue("send_direct", frame)
        elif kind == "shutdown":
            # Let already-queued sends drain (bounded) before tearing down, so
            # a send accepted just before shutdown still goes out; a wedged
            # send is abandoned at the join timeout rather than hanging exit.
            send_q.close()
            sender.join(timeout=2.0)
            stop = getattr(bridge, "stop", None)
            if stop is not None:
                stop()
            sys.exit(0)
        # unknown t: ignore, keep looping
