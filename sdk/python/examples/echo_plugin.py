"""The 30-line RelayFabric plugin: echoes every routed send back into the
fabric as an inbound message. Run it under the daemon with

    plugins:
      echo:
        enabled: true
        command: python /path/to/sdk/python/examples/echo_plugin.py

or prove it against the conformance runner:

    switchyardctl plugin test "python sdk/python/examples/echo_plugin.py"
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from relayfabric_sdk import ipc as relay_ipc
from relayfabric_sdk import run_plugin
from relayfabric_sdk.bridge import FrameWriter


class EchoBridge(FrameWriter):
    def handle_send(self, frame):
        self._send_frame(relay_ipc.inbound(frame["endpoint"], "echo", frame["body"]))
        self._send_frame(relay_ipc.delivery_result(frame["corr"], True))


def main():
    run_plugin(
        os.environ.get("RELAYFABRIC_PLUGIN_NAME", "echo"),
        "0.1.0",
        lambda cfg, sock: EchoBridge(sock),
        relay_ipc.capabilities(),
    )


if __name__ == "__main__":
    main()
