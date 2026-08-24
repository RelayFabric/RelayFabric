# Writing a RelayFabric plugin

A plugin is a subprocess the daemon spawns and speaks Plugin Protocol v1 to
over a Unix domain socket (spec §9, §84): a 4-byte big-endian length prefix
plus a CBOR body. This doc names the SDKs and walks the wire lifecycle so
you can write a new plugin (in Python, Rust, or any other language) without
reverse-engineering the fleet.

## Rust SDK: `relay-core` + `relay-ipc`

Spec §92 asks for an SDK containing message types, endpoint types, an IPC
client, and capability definitions. In this repo, `crates/relay-core` and
`crates/relay-ipc` already **are** that SDK: `relay-core` owns
`Capabilities` and the shared message/endpoint types, `relay-ipc` owns the
frame codec (`PluginToDaemon`/`DaemonToPlugin`, `read_frame`/`write_frame`)
and is what `plugins/mqtt` (the one in-tree Rust plugin) links against
directly. There is no separate facade crate to wrap them in. A Rust plugin
just depends on both crates from the workspace.

## Python SDK: `relayfabric_sdk`

`sdk/python/relayfabric_sdk/` is the Python equivalent: `ipc.py` (frame
codec + frame builders), `cache.py` (`SentCache`, a loop-guard for
echoed-back sends), `harness.py` (`FakeSock`, a scripted duplex socket for
tests), and `runner.py` (`run_plugin`, the shared main-loop scaffold below).
Consume it via a `sys.path` insert to `../../sdk/python`, exactly like the
in-tree Python plugins (lxmf, signal, meshtastic, meshcore) do. No install
required. `pip install -e sdk/python` also works if you prefer that.

## Lifecycle

### 1. Env contract

The daemon spawns your process with:

- `RELAYFABRIC_SOCKET`: path to the Unix domain socket to connect to.
- `RELAYFABRIC_PLUGIN_NAME`: the name this plugin is configured under.
- `RELAYFABRIC_PLUGIN_CONFIG`: the plugin's `config:` block, as JSON.

Missing `RELAYFABRIC_SOCKET` is a startup misconfiguration; a Python plugin
using `run_plugin` exits 2 for it (see below).

### 2. Hello / HelloAck

Connect, then send `Hello { plugin, version, protocol_version, capabilities }`
and read one `HelloAck { protocol_version, error }` frame before doing
anything else. A non-null `error` (or any other frame type) means the
daemon rejected you. Log it and exit; do not proceed to the read loop.

### 3. Frames (the `t` tag)

| `t`               | Direction        | Purpose                                   |
|--------------------|-------------------|--------------------------------------------|
| `hello`             | plugin → daemon   | capability announcement, once at startup   |
| `hello_ack`         | daemon → plugin   | accept/reject the hello                    |
| `inbound`           | plugin → daemon   | a message received from the native network |
| `send`              | daemon → plugin   | deliver to a configured endpoint           |
| `send_direct`       | daemon → plugin   | deliver to a native ref, no endpoint mapping (requires `direct_messages`) |
| `delivery_result`   | plugin → daemon   | outcome of a `send`/`send_direct`, correlated by `corr` |
| `shutdown`          | daemon → plugin   | clean-exit request                         |

An unrecognized `t` in either direction MUST be ignored, not treated as an
error. This is how new frame variants can be added later without breaking
plugins/daemons that don't know about them yet.

### 4. DeliveryResult semantics

`delivered: true` is terminal. The daemon marks the delivery done and never
retries it. `delivered: false` goes back into the retry/backoff path;
`detail` is a free-text diagnostic string for logs/tracing, never parsed.
For a fan-out send (e.g. lxmf's channel members), report **at-least-one**
semantics: `delivered: true` as soon as any recipient succeeds, with the
failures named in `detail`. Always echo the `corr` from the triggering
`send`/`send_direct` frame unchanged.

### 5. Capability flags

`text`, `direct_messages`, `groups`, `attachments`, `location`, `reactions`,
`receipts`, `presence`, `max_payload` (spec §16). Advertise only what you
actually implement. The daemon uses these to route and to gate features,
not just to display them. `direct_messages` in particular gates
`send_direct`: only plugins that advertise it ever receive that frame (used
today for identity-link challenge delivery, a single one-shot send to a
native ref outside any channel/endpoint mapping). `max_payload` (bytes, or
null for unbounded) lets the daemon truncate before it ever reaches you.

## The Python runner: `relayfabric_sdk.run_plugin`

`run_plugin(plugin_name, version, bridge_factory, capabilities, *,
socket_env="RELAYFABRIC_SOCKET", config_env="RELAYFABRIC_PLUGIN_CONFIG")` implements
steps 1–3 above so a plugin's `main()` doesn't hand-roll them: it reads the
env contract, does the Hello/HelloAck handshake, calls
`bridge_factory(cfg_dict, sock) -> bridge`, calls `bridge.start()` if
present, then dispatches `send`/`send_direct`/`shutdown` to
`bridge.handle_send(frame)` / `bridge.handle_send_direct(frame)` (skipped
if absent) / `bridge.stop()` + exit 0. An IO error mid-loop exits 1.

`capabilities` may be a plain dict, or a callable taking the parsed config
dict and returning the caps dict, for plugins whose advertised caps depend
on config (e.g. a `max_payload` derived from a validated config field). A
`ValueError`/`TypeError` raised by the callable or by `bridge_factory`
(the plugins' `load_config` validation errors) exits 1 with a clean
"invalid config" line. Every shipped Python plugin runs on this scaffold;
`relayfabric_sdk.bridge` additionally provides the shared `FrameWriter`
write-lock base and the `capped_text_send` egress dance.

## The 30-line plugin, and proving it

`sdk/python/examples/echo_plugin.py` is a complete plugin: a `FrameWriter`
subclass with one `handle_send`, run by `run_plugin`. Prove any plugin
(any language) against the daemon-side contract with the conformance
runner:

```text
switchyardctl plugin test [--config '<json>'] [--endpoint NAME] "<command>"
PASS HELLO
PASS SEND
PASS SHUTDOWN
conformant: Plugin Protocol v1
```

It plays the daemon's side on a scratch socket: Hello shape + protocol
version + name binding, a routed `send` answered by a `delivery_result`
with the right corr, and clean exit 0 on `shutdown`.

## Published packages

- **Python:** `pip install relayfabric-sdk` (PyPI): the codec,
  `run_plugin`, `bridge`, cache, and `FakeSock` harness.
- **Rust:** `relayfabric-ipc` on crates.io (with `relayfabric-core` for the
  model types). The bare `relay-core` crate name on crates.io is an
  unrelated project. RelayFabric publishes under `relayfabric-*` only.

## Golden frames, for new-language authors

The wire format is locked byte-for-byte across implementations. Before
trusting a new codec, reproduce these exact hex vectors:

See [Golden Wire Vectors](golden-vectors.md) for the full byte-exact
vectors inline. In-repo sources:

- Rust: `crates/relay-ipc/src/lib.rs`:
  `canonical_hello_frame_bytes_are_stable`,
  `canonical_inbound_attachment_frame_bytes_are_stable`.
- Python: `sdk/python/tests/test_ipc.py`: `CANONICAL_HELLO_HEX`,
  `CANONICAL_INBOUND_ATTACHMENT_HEX`.

Dict/struct key order matters for the byte-lock (CBOR maps are encoded in
field-declaration order, not sorted). Match the field order in
`relay-ipc`'s `PluginToDaemon`/`DaemonToPlugin` enums exactly.
