# RelayFabric v0.1 Slice — Design

**Date:** 2026-08-15
**Status:** Approved
**Parent spec:** `docs/SPEC.md` (RelayFabric Technical Specification 0.1)

## Scope

First implementation increment of RelayFabric. Builds the complete core
(`switchyardd`, `switchyardctl`, plugin IPC, routing, policy, queues) proven
end-to-end with a mock plugin (integration tests) and a real MQTT plugin.
The LXMF, Signal, and Meshtastic plugins from the spec's v0.1 MVP are
follow-on cycles — they need external systems (RNS stack, signal-cli, radio
hardware) and slot into the plugin interface this slice defines.

Out of scope for this slice: identity linking/verification, federation,
SIGNED/OPAQUE security modes (TRANSLATE only), attachments storage, plugin
SDK crates, WebUI. All are later spec milestones (v0.2+).

## Workspace layout

Trimmed from spec §91 — split further only when the plugin SDK cycle needs it:

```
crates/relay-core/     canonical envelope, message types, capabilities, endpoint types
crates/relay-ipc/      plugin wire protocol v1: CBOR frames over Unix socket
switchyardd/           daemon: routing, policy, aliases, dedup, loop prevention,
                       SQLite persistence/queues, admin API, plugin supervision
switchyardctl/         CLI speaking JSON to the admin API over the admin Unix socket
plugins/mqtt/          relayfabric-mqtt: real network plugin (rumqttc)
plugins/mock/          test plugin binary used by integration tests
```

Policy, storage, and queue logic live as modules inside `switchyardd` for
now; they get extracted into `relay-policy` / `relay-storage` crates when the
v0.2 SDK work needs them externally.

## Technology choices

| Concern | Choice | Spec ref |
|---|---|---|
| Async runtime | tokio | — |
| Plugin IPC encoding | CBOR (ciborium) over Unix domain socket, length-prefixed frames, protocol v1 | §9 |
| Persistence | SQLite via rusqlite (bundled) | §50 |
| Message IDs | UUIDv7 (`uuid` crate) | §13 |
| Config | YAML (serde_yaml) at the spec §58 schema | §58 |
| Pseudonyms | HMAC-SHA256 (hmac + sha2), route/scope-keyed | §20 |
| Logging | tracing, content-free by default, HMAC'd native identifiers | §52–53 |
| Admin API + metrics | axum over Unix socket; JSON endpoints per §57 plus Prometheus text at `/metrics` | §55, §57 |

One admin API from day one: `switchyardctl` and any future WebUI are both
clients of it. The daemon never exposes TCP by default.

## Data flow

```
plugin process ── connect plugin UDS ──► switchyardd
   Hello + PluginDescriptor (§11)
   Inbound frame
        │
        ▼
  normalize → canonical envelope (§12)
        │
  dedup (canonical ID / content hash, TTL'd cache) (§28)
        │
  loop / hop-limit check (fabric_hop_count vs fabric_hop_limit, route history) (§27, §29)
        │
  route match (sources → destinations, ingress excluded from echo) (§24)
        │
  policy eval: allow / deny / truncate / strip location / max_payload (§36–37)
        │
  transform for destination capabilities ([attachment omitted], sender tag) (§17, §83)
        │
  persistent queue row (§40–41)
        │
  egress Send frame → plugin → DeliveryResult
        │
  queue state machine: pending → attempting → delivered | failed → retry
  (exponential backoff §42) | expired (TTL §43) | dead-letter (reason codes §44)
```

Plugin supervision: `switchyardd` spawns plugin executables from config,
restarts on crash with bounded backoff (1s/5s/30s/2m), marks repeat-crashers
unhealthy (§69). Bounded ingress channels per plugin prevent memory
exhaustion (§45).

## Testing

- **Unit:** routing match, policy actions, alias derivation (differs across
  scopes), dedup, TTL expiry, queue state transitions, retry backoff.
- **Integration:** boot `switchyardd` + two mock plugin processes; prove
  A→B delivery, ingress echo suppression, and A→B→A loop prevention;
  daemon restart recovers queued messages.
- **MQTT:** smoke test against a local broker when one is reachable,
  otherwise skipped.

## Follow-on cycles (from parent spec)

1. LXMF plugin, 2. Signal plugin (signal-cli backend), 3. Meshtastic plugin,
then v0.2+ items (MeshCore, SDK, identity linking, federation, WebUI).
