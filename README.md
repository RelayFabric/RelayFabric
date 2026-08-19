# RelayFabric

[![CI](https://github.com/RelayFabric/RelayFabric/actions/workflows/ci.yml/badge.svg)](https://github.com/RelayFabric/RelayFabric/actions/workflows/ci.yml)
[![Docker](https://github.com/RelayFabric/RelayFabric/actions/workflows/docker.yml/badge.svg)](https://github.com/RelayFabric/RelayFabric/actions/workflows/docker.yml)

RelayFabric is an open communications routing fabric for interconnecting
otherwise incompatible messaging, mesh, radio, and Internet communications
systems. It provides a common routing, policy, identity, security, and
message-processing layer while delegating protocol-specific behavior to
plugins. MeshCore uses the native MIT Companion Radio Protocol (spec §8's
preferred style), while Meshtastic uses MQTT (licensing favors it). Initial
target networks: Reticulum/LXMF, Signal, Meshtastic, MeshCore, Bitchat, Nostr.

**Status:** [v0.3.0 released](https://github.com/RelayFabric/RelayFabric/releases/tag/v0.3.0)
— core fabric, eight plugins, federation + RFDP, sealed routing phase 1,
transport-class-aware egress, admin API + web UI. **v0.4 in progress** — the
hardening/proving/packaging release ([roadmap](docs/proposals/v0.4-roadmap.md)).
The [feature-status table](https://docs.relayfabric.org/#feature-status) is
the single source of truth for what is shipped, validated, or pending.

## Components

- `switchyardd` — the core daemon: routing, deduplication, policy
  enforcement, persistence, and an admin API, all headless.
- `switchyardctl` — CLI client for the admin API (status, plugins, routes, queue, trace).
- `relayfabric-ui` — web admin UI plus a thin reverse-proxy that fronts the
  daemon's Unix-socket admin API for the browser; see
  [`relayfabric-ui/README.md`](relayfabric-ui/README.md).
- Plugins — separate processes speaking a small CBOR-over-Unix-socket IPC
  protocol to the daemon. MQTT, LXMF, Signal, Meshtastic, MeshCore, Nostr,
  Bitchat, and PotatoMesh plugins available; see [LXMF](plugins/lxmf/README.md), [Signal](plugins/signal/README.md),
  [Meshtastic](plugins/meshtastic/README.md), [MeshCore](plugins/meshcore/README.md),
  [Nostr](plugins/nostr/README.md), [Bitchat](plugins/bitchat/README.md), or
  [PotatoMesh](plugins/potatomesh/README.md) docs.

## Build

```
cargo build -j2 --release
```

Binaries in `target/release/`. This builds the minimal set — the daemon,
CLI, and MQTT plugin. The web admin UI is **optional** and excluded from the
default build; add it explicitly when you want it:

```
cargo build -j2 --release -p relayfabric-ui
```

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
IPC protocol — is specified in [`docs/SPEC.md`](docs/SPEC.md). The
administrative web UI (`relayfabric-ui`) and its reverse-proxy are documented
in [`relayfabric-ui/README.md`](relayfabric-ui/README.md); the architecture and
the still-deferred auth/RBAC work are in
[`docs/webui-notes.md`](docs/webui-notes.md).

## License

Apache-2.0, Copyright © 2026 Jascha Wanger / Tarnover, LLC. Dependencies are
chosen under a permissive-only policy — no AGPL or other copyleft licenses.

Sponsored by [Tarnover](https://tarnover.com).
