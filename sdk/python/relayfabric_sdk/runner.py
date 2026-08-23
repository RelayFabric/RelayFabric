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
"""

import json
import os
import socket
import sys

from .ipc import hello, pong, read_frame, write_frame


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
            # Liveness probe: answer promptly or the daemon restarts us. Go
            # through the bridge's locked writer so this never interleaves
            # with a frame the bridge's reader thread is writing; fall back to
            # a direct write for a bridge that isn't a FrameWriter.
            send_frame = getattr(bridge, "_send_frame", None)
            if send_frame is not None:
                send_frame(pong())
            else:
                write_frame(sock, pong())
        elif kind == "send":
            # Guard dispatch: a malformed "send" frame (missing corr/endpoint/
            # body) would otherwise raise out of the loop and kill the plugin.
            # The inbound-read path is already hardened; make the dispatch path
            # symmetric so one bad frame can't take the plugin down.
            try:
                bridge.handle_send(frame)
            except Exception as e:  # noqa: BLE001 - one bad frame must not kill the plugin
                print(f"{plugin_name}: error handling send frame: {e}", file=sys.stderr)
        elif kind == "send_direct":
            handle_send_direct = getattr(bridge, "handle_send_direct", None)
            if handle_send_direct is not None:
                try:
                    handle_send_direct(frame)
                except Exception as e:  # noqa: BLE001 - one bad frame must not kill the plugin
                    print(f"{plugin_name}: error handling send_direct frame: {e}",
                          file=sys.stderr)
        elif kind == "shutdown":
            stop = getattr(bridge, "stop", None)
            if stop is not None:
                stop()
            sys.exit(0)
        # unknown t: ignore, keep looping
