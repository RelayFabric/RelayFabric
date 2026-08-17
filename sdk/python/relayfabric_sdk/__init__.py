"""RelayFabric Python plugin SDK.

Consolidates what the plugin fleet (lxmf, signal, meshtastic, meshcore)
already shared via fragile cross-plugin sys.path inserts: the Plugin
Protocol v1 frame codec (ipc), the sent-message loop-guard cache (cache),
the scripted-socket test double (harness), and the NIP-01 event primitives
(nip01, promoted from the nostr plugin in cycle J -- shared with bitchat).

Plugins typically import the ipc submodule directly to keep existing
`relay_ipc.foo(...)` call sites unchanged:

    from relayfabric_sdk import ipc as relay_ipc

The names below are the flat re-export surface for everything else.
"""

from .cache import SentCache
from .harness import FakeSock
from .ipc import PROTOCOL_VERSION, read_frame, write_frame
from .nip01 import event_id, load_or_create_identity, sign_event, verify_event
from .runner import run_plugin

__all__ = ["PROTOCOL_VERSION", "FakeSock", "SentCache", "event_id",
           "load_or_create_identity", "read_frame", "run_plugin", "sign_event",
           "verify_event", "write_frame"]
