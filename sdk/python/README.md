# relayfabric-sdk

The Python side of RelayFabric's Plugin Protocol v1: the CBOR frame codec
(`relayfabric_sdk.ipc`, golden-locked byte-for-byte against the Rust
implementation), the `run_plugin` main-loop scaffold, shared Bridge plumbing
(`relayfabric_sdk.bridge`), the sent-message loop-guard cache, and the
`FakeSock` test harness.

A complete plugin is ~30 lines — see `examples/echo_plugin.py`. Prove any
plugin against the daemon-side contract with:

    switchyardctl plugin test "python my_plugin.py"

Docs: https://docs.relayfabric.org/plugin-authors/
