# Proposal: Transport-Class Phase 2 — Core Extraction & the Android Edge Node

**Status:** proposed, v0.4 · **Scope:** restructuring — a reusable core crate,
a platform-transport seam, and the first non-daemon RelayFabric node ·
**Date:** 2026-08-18

> Regenerated 2026-08-18: the original Phase-2 design section (written
> 2026-08-17 alongside the Phase-1 spec) lived in an untracked working
> directory and was lost when that worktree was removed. This document
> reconstructs it from the project's design notes and the shipped Phase-1
> code, and lives in `docs/proposals/` so it is versioned with the repo.

## Context: what Phase 1 shipped

Phase 1 (merged to main 2026-08-17) made the *link* a plugin rides a
first-class model, separate from the plugin's protocol:

- `relay-core`: `TransportClass` (terrestrial_internet, satellite_internet,
  reticulum, meshtastic, mesh_core, bluetooth, local_network) and
  `TransportPolicy { max_payload_bytes, allow_images, allow_video, compress,
  batch_telemetry }` with built-in per-class defaults
  (`TransportPolicy::for_class`). Deserialize-only — never embedded in
  `Envelope`, never on the relay-ipc wire.
- config: the `transports:` block maps a plugin to a class plus optional
  per-field overrides; `Config::transport_policy(plugin)` resolves
  config-class+overrides → per-protocol default
  (`default_transport_class_for`) → the terrestrial anchor. Live-reloadable,
  validated like `transport_budgets`.
- engine egress: effective payload cap = min(plugin
  `Capabilities::max_payload`, transport `max_payload_bytes`); image/video
  attachments demote to a note when the transport disallows media
  (`relayfabric_transport_demoted_total`). SEALED routes are exempt
  (SPEC §113.4) — structural, not a shared call site.
- **Key invariant (must survive Phase 2):** backward-compat is provably
  non-constraining. `TERRESTRIAL_MAX_PAYLOAD_BYTES == relay_ipc::MAX_FRAME`
  (16 MiB), so `min()` is a no-op for every existing internet route, and a
  config with no `transports:` block behaves byte-identically to v0.3.
  Locked by a SHA-verified regression e2e.

Phase 1 keys everything statically: one class per plugin, chosen by config
at load time. `compress` and `batch_telemetry` are parsed and carried but
not yet acted on — they are Phase-2/Phase-3 consumers.

## Motivation

Two operator realities drove the transport-class model, and both point at
the same next step:

1. **T-Satellite is a transport, not a protocol.** A phone that drifts from
   Wi-Fi to cellular to satellite is the *same* node running the *same*
   protocols over links whose class changes at runtime. Static
   plugin→class mapping can't express that; the policy engine needs to
   re-derive when the link changes.
2. **The Android edge node.** The most useful place for a
   transport-adaptive RelayFabric node is a handset: BLE and Wi-Fi Aware
   nearby, cellular normally, satellite when off-grid. `switchyardd` is a
   bin-only crate — nothing today is linkable from an app.

Priority call (2026-08-17): Android edge node ranks above further WebUI
work. This proposal is the Android prerequisite.

## Design

### 1. Extract `relayfabric-core`

Pull the protocol-independent heart of `switchyardd` into a reusable
library crate consumed by both the daemon and the Android node:

| Moves to `relayfabric-core` | Stays in `switchyardd` |
|---|---|
| routing decision + fan-out logic (engine's pure parts) | tokio runtime, supervision, admin API/socket |
| policy evaluation (`policy.rs`) | plugin process management (`plugins.rs`) |
| transform/truncation (`transform.rs`) | SQLite storage backend (`storage.rs`) |
| envelope + transport model (already `relay-core` — folds in or is re-exported) | federation listener/dialer (`fed/conn.rs`) |
| fed crypto primitives (sign/seal/keyfile) | metrics endpoint, config file loading |

Constraints:

- `relay-ipc` golden frames stay exactly where they are; the wire format is
  the compatibility contract and does not move or change.
- The daemon's behavior is byte-identical after extraction — this is a
  `cargo` re-layering, not a rewrite. The existing e2e suite is the gate.
- No `tokio` (or any runtime) dependency in the core crate's API surface:
  the Android side drives it from its own executor/bindings.

### 2. The `PlatformTransport` trait

The seam that makes transport class *dynamic*:

```rust
pub trait PlatformTransport {
    /// The class of the link currently carrying this transport's traffic.
    fn current_class(&self) -> TransportClass;
    /// Fires when the platform detects a link transition (Wi-Fi -> cell ->
    /// satellite, BLE joins/leaves). The core re-derives TransportPolicy
    /// and re-applies egress caps/demotion on the next dispatch.
    fn subscribe_transitions(&self, cb: Box<dyn Fn(TransportClass) + Send>);
}
```

- **Daemon implementation:** Python-plugins-over-IPC, class fixed by the
  existing `transports:` config — Phase 1 behavior, now expressed as one
  `PlatformTransport` impl whose `current_class` never changes. Zero
  operator-visible difference.
- **Android implementation:** native transports (BLE, Wi-Fi Aware/LAN,
  cellular, satellite) with `current_class` derived from
  `ConnectivityManager`/`NetworkCapabilities` (satellite detection is
  API 35+). A transition re-derives the policy: the same message that
  carries an image over Wi-Fi demotes it over satellite, with no restart
  and no config change.
- Policy re-derivation reuses `Config::transport_policy`'s precedence
  (overrides > class default > terrestrial anchor); only the class input
  becomes live instead of load-time. This is where Phase 1's carried-but-
  unread `compress`/`batch_telemetry` flags gain their first consumer
  (satellite/mesh classes want both).

### 3. The Android edge node

- **Rust core via UniFFI**, Compose UI. The app links `relayfabric-core`;
  no daemon, no Unix sockets, no Python.
- **Reticulum via Prns** (Rust, transport-only, permissive license) —
  Python RNS won't run in-app, and the richer Rust alternatives are
  license-excluded (LXMF-rs is EPL-2.0; project policy is permissive-only,
  clean-room if needed). Scope Reticulum support to what Prns provides;
  LXMF message semantics stay daemon-side until a permissive path exists.
- Reach expectations: mesh/BLE/Wi-Fi features are broadly available;
  satellite is API 35+/US-carrier near-term. The app must degrade to
  "no satellite class detectable" cleanly on older devices.

## Non-goals

- No new wire protocol, no relay-ipc changes, no Envelope changes.
- No sealed-routing changes: the §113.4 exemption structure carries over.
- Not a daemon rewrite — `switchyardd` keeps its exact behavior and tests.
- iOS is out of scope for this phase.

## Open questions

- T-Mobile SatelliteApps program outreach (async, in flight as of
  2026-08-17) may shape what satellite-class detection/entitlement looks
  like in practice.
- Phase 1's characteristics table was folded into `for_class` (2026-08-18
  simplification pass) since policy was its only consumer. If dynamic
  transitions need richer link inputs (measured bandwidth, metering
  signals from `NetworkCapabilities`), reintroduce a characteristics type
  *at the `PlatformTransport` boundary* — fed by the platform, not by a
  static table.
- Storage on Android: `storage.rs` stays daemon-side this phase; the app
  needs a minimal queue/dedup story (likely the same SQLite schema behind
  a platform path) — to be specced with the app's first delivery task.

## Phasing

1. **Core extraction** — move the table above into `relayfabric-core`;
   daemon e2e suite green, byte-identical behavior.
2. **`PlatformTransport` seam** — daemon impl (static class), engine egress
   reads the class through the trait; regression e2e still SHA-identical.
3. **Android skeleton** — UniFFI bindings over the core, Compose shell,
   BLE/Wi-Fi classes with live transitions.
4. **Satellite + Prns** — API-35 satellite detection, Reticulum transport
   via Prns, field test against the live RNS backbone.
