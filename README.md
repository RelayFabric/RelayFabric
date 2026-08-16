# RelayFabric

RelayFabric is an open communications routing fabric for interconnecting
otherwise incompatible messaging, mesh, radio, and Internet communications
systems. It provides a common routing, policy, identity, security, and
message-processing layer while delegating protocol-specific behavior to
plugins. MeshCore uses the native MIT Companion Radio Protocol (spec §8's
preferred style), while Meshtastic uses MQTT (licensing favors it). Initial
target networks: Reticulum/LXMF, Signal, Meshtastic, MeshCore, Bitchat, Nostr.

**Status:** v0.2 complete; WebUI-ready admin API (config apply/reload, SSE events).

## Components

- `switchyardd` — the core daemon: routing, deduplication, policy
  enforcement, persistence, and an admin API, all headless.
- `switchyardctl` — CLI client for the admin API (status, plugins, routes,
  queue, trace).
- Plugins — separate processes speaking a small CBOR-over-Unix-socket IPC
  protocol to the daemon. MQTT, LXMF, Signal, Meshtastic, and MeshCore plugins
  available; see [LXMF](plugins/lxmf/README.md), [Signal](plugins/signal/README.md),
  [Meshtastic](plugins/meshtastic/README.md), or [MeshCore](plugins/meshcore/README.md)
  docs for configuration.

## Build

```
cargo build -j2 --release
```

Binaries in `target/release/`.

## Quick start

Commands assume `target/release/` is on your `PATH`.

1. Copy `docs/relayfabric.example.yaml` and adjust `node.data_dir`, then
   validate it:

   ```
   switchyardd --config docs/relayfabric.example.yaml --check-config
   ```

2. Try the MQTT demo end to end (requires a local `mosquitto` broker):

   ```
   mosquitto -p 1883 &
   switchyardd --config docs/relayfabric.example.yaml &
   mosquitto_sub -t chat/b &
   mosquitto_pub -t chat/a -m "ping"
   ```

   The message published on `chat/a` is routed through `switchyardd` and
   delivered on `chat/b` (and vice versa) per the example config's `demo`
   route. MQTT v5 "No Local" is set on the plugin's subscriptions, so the
   broker never echoes a plugin's own publishes back to it.

3. Inspect the running daemon:

   ```
   switchyardctl status
   switchyardctl routes
   switchyardctl queue
   switchyardctl trace <message-id>
   ```

## Design

The routing, policy, and security model — including deny-by-default
routing, route-scoped pseudonyms, TTL/dedup/retry semantics, and the plugin
IPC protocol — is specified in [`docs/SPEC.md`](docs/SPEC.md). Notes on the
(not-yet-built) administrative web UI are in
[`docs/webui-notes.md`](docs/webui-notes.md).

## License

Apache-2.0. Dependencies are chosen under a permissive-only policy — no
AGPL or other copyleft licenses.
