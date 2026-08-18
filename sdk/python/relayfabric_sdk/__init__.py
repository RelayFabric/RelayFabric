"""RelayFabric Python plugin SDK.

Consolidates what the plugin fleet shares: the Plugin Protocol v1 frame
codec (ipc), the sent-message loop-guard cache (cache), shared Bridge
plumbing (bridge), the main-loop scaffold (runner), the scripted-socket
test double (harness), and the NIP-01 event primitives (nip01).

Plugins import submodules directly (`from relayfabric_sdk import ipc as
relay_ipc`). The flat names below resolve lazily (PEP 562), so a bare
`import relayfabric_sdk` — or importing the stdlib-only `bridge`
submodule — pulls in no third-party dependency.
"""

_FLAT = {"FakeSock": "harness", "SentCache": "cache", "run_plugin": "runner"}

__all__ = list(_FLAT)


def __getattr__(name):
    submodule = _FLAT.get(name)
    if submodule is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    return getattr(import_module(f".{submodule}", __name__), name)
