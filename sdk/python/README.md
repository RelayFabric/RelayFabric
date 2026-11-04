# relayfabric-sdk

The Python side of RelayFabric's Plugin Protocol v1: the CBOR frame codec
(`relayfabric_sdk.ipc`, golden-locked byte-for-byte against the Rust
implementation), the `run_plugin` main-loop scaffold, shared Bridge plumbing
(`relayfabric_sdk.bridge`), the sent-message loop-guard cache, and the
`FakeSock` test harness.

A complete plugin is ~30 lines — see `examples/echo_plugin.py`. Prove any
plugin against the daemon-side contract with:

    switchyardctl plugin test "python my_plugin.py"

Types at the trust boundary: the daemon decodes an `inbound` frame into
typed structs, and a wrong-typed field (an int `sender`, a str attachment
`data`) fails that decode, drops the plugin connection and restarts the
plugin — a crash loop if the triggering event is retained or stored.
`ipc.inbound()` therefore raises `ValueError` on a mistyped field; treat
that as "drop this message". `run_plugin` dedups re-dispatched sends by
`corr` and bounds its send queue (`runner.SEND_QUEUE_MAX`), answering an
overflow with `delivery_result(corr, false, "plugin busy")`.

Docs: https://docs.relayfabric.org/plugin-authors/
