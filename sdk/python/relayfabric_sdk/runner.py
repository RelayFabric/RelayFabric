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

from .ipc import hello, read_frame, write_frame


def _connect_socket(sock_path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    return sock.makefile("rwb")


def run_plugin(plugin_name, version, bridge_factory, capabilities, *,
                socket_env="RELAYFABRIC_SOCKET", config_env="RELAYFABRIC_CONFIG",
                connect=_connect_socket):
    """Run a plugin's main loop until shutdown or an unrecoverable error.

    - Missing `socket_env` -> stderr line + exit 2.
    - Connects, sends Hello(plugin_name, version, capabilities), reads
      HelloAck; a non-"hello_ack" frame or a truthy "error" -> stderr line +
      exit 1.
    - Calls `bridge_factory(cfg_dict, sock)`; if the returned object has a
      `start()`, calls it before entering the read loop.
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
    sock = connect(sock_path)

    write_frame(sock, hello(plugin_name, version, capabilities))
    ack = read_frame(sock)
    if ack.get("t") != "hello_ack" or ack.get("error"):
        print(f"{plugin_name}: hello rejected: {ack.get('error')}", file=sys.stderr)
        sys.exit(1)

    bridge = bridge_factory(raw_cfg, sock)
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
        if kind == "send":
            bridge.handle_send(frame)
        elif kind == "send_direct":
            handle_send_direct = getattr(bridge, "handle_send_direct", None)
            if handle_send_direct is not None:
                handle_send_direct(frame)
        elif kind == "shutdown":
            stop = getattr(bridge, "stop", None)
            if stop is not None:
                stop()
            sys.exit(0)
        # unknown t: ignore, keep looping
