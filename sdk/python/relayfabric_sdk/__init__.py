"""RelayFabric Python plugin SDK.

Consolidates what the plugin fleet (lxmf, signal, meshtastic, meshcore)
already shared via fragile cross-plugin sys.path inserts: the Plugin
Protocol v1 frame codec (ipc), the sent-message loop-guard cache (cache),
and the scripted-socket test double (harness).

Plugins typically import the ipc submodule directly to keep existing
`relay_ipc.foo(...)` call sites unchanged:

    from relayfabric_sdk import ipc as relay_ipc

The names below are the flat re-export surface for everything else.
"""

from .cache import SentCache
from .harness import FakeSock
from .ipc import PROTOCOL_VERSION, read_frame, write_frame

__all__ = ["PROTOCOL_VERSION", "FakeSock", "SentCache", "read_frame", "write_frame"]
