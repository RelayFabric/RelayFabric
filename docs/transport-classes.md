# Transport Classes

A plugin's protocol and the physical link its traffic actually rides are different things. RelayFabric's egress policy accounts for both: a plugin's `Capabilities` (what the protocol itself can carry) and a `TransportClass` (what the *link* underneath it can carry) compose, most-restrictive-wins, when a message is sent.

!!! info "Phase status"
    This page documents **Phase 1**, which is implemented and shipped: a static `TransportClass` per plugin, built-in per-class defaults, and egress-time payload capping / media demotion. **Phase 2** (a `relayfabric-core` extraction, a `PlatformTransport` trait, and dynamic runtime class transitions for an Android edge node) is specced but **not built**. See [Phase 2](#phase-2-specced-not-built) below.

## Motivation

RelayFabric conflates two different questions when it decides what to send to a destination:

1. **What can this protocol carry?** A plugin's `Capabilities` (attachments, `max_payload`, etc).
2. **What can this link carry, right now?** Bandwidth, latency, intermittency, cost.

The same protocol can ride very different links: an MQTT-based plugin bridged over a LoRa radio is still "MQTT" at the protocol layer, but the link underneath behaves nothing like MQTT over broadband. Historically, degradation decisions in RelayFabric were driven only by the plugin's protocol capabilities. The `TransportClass` model gives the router a second, independent axis to key routing and degradation decisions on: the *link*, not just the *protocol*.

This also means a constrained transport (satellite direct-to-cell, Iridium, LoRa mesh, BLE) falls out as "just a transport with certain characteristics" rather than a bespoke integration, and is the foundation a future Android edge node needs (Phase 2).

## The model

Three types, defined in `relay-core` (`crates/relay-core/src/transport.rs`). They are additive: never embedded in `Envelope` or any other struct that crosses the relay-ipc wire, so the golden frame tests are unaffected by this module.

### `TransportClass`

The class of link a plugin's traffic actually rides:

```rust
pub enum TransportClass {
    TerrestrialInternet,   // MQTT/Signal/Nostr/Bitchat over broadband or cellular IP
    SatelliteInternet,     // T-Satellite / Starlink Direct-to-Cell / Iridium — constrained IP
    Reticulum,              // LXMF/RNS
    Meshtastic,             // LoRa (Meshtastic firmware)
    MeshCore,               // LoRa (MeshCore firmware)
    Bluetooth,              // BLE nearby
    LocalNetwork,           // Wi-Fi Direct / Aware / LAN
}
```

Config and `Display` both use `snake_case` names (`terrestrial_internet`, `satellite_internet`, `reticulum`, `meshtastic`, `mesh_core`, `bluetooth`, `local_network`).

### `TransportCharacteristics`

Coarse-grained inputs to policy derivation, not policy itself:

```rust
pub struct TransportCharacteristics {
    pub bandwidth: Bandwidth,      // High | Medium | Low | VeryLow
    pub latency: Latency,          // Low | Medium | High
    pub intermittent: bool,        // gaps/timeouts expected in normal operation
    pub metered: bool,             // meaningful per-byte or per-connection cost
    pub store_and_forward: bool,   // undeliverable traffic should queue, not drop
}
```

Every `TransportClass` has a built-in default via `TransportClass::characteristics()`.

### `TransportPolicy`

The *effective* egress rules, derived from characteristics via `TransportPolicy::for_class(class)`:

```rust
pub struct TransportPolicy {
    pub max_payload_bytes: u64,   // hard cap the link imposes
    pub allow_images: bool,       // else images demoted to an attachment-note
    pub allow_video: bool,        // else video demoted to an attachment-note
    pub compress: bool,           // hint: compress the body on egress (flag only, Phase 1)
    pub batch_telemetry: bool,    // hint for future telemetry aggregation (flag only, Phase 1)
}
```

`compress` and `batch_telemetry` are resolved and available for plugins/metrics to read, but Phase 1 does not wire actual zstd compression or telemetry batching: those touch the plugin wire contract and are their own follow-on.

## Default characteristics and policy per class

| Class | Bandwidth | Latency | Intermittent | Metered | `max_payload_bytes` | Images/video | `compress` | `batch_telemetry` |
|---|---|---|---|---|---|---|---|---|
| `TerrestrialInternet` | High | Low | no | no | 16,777,216 (16 MiB, `MAX_FRAME`) | allowed | no | no |
| `SatelliteInternet` | VeryLow | High | yes | yes | 32,768 (32 KiB) | **demoted** | yes | yes |
| `Reticulum` | Low | High | yes | no | 32,768 (32 KiB) | allowed | no | yes |
| `Meshtastic` | VeryLow | High | yes | no | 237 | **demoted** | yes | yes |
| `MeshCore` | VeryLow | High | yes | no | 237 | **demoted** | yes | yes |
| `Bluetooth` | Medium | Low | yes | no | 65,536 (64 KiB) | allowed | no | yes |
| `LocalNetwork` | Medium | Low | no | no | 16,777,216 (16 MiB, `MAX_FRAME`) | allowed | no | no |

All classes have `store_and_forward: true`. RelayFabric queues undeliverable traffic regardless of transport.

`compress` is `true` when a class is `metered` or has `VeryLow` bandwidth; `batch_telemetry` is `true` when a class is `intermittent` or has `VeryLow` bandwidth. Both are derived, not independently configured per class.

`max_payload_bytes` values above are representative defaults for the class, not protocol mandates. An operator can override them per plugin (see [Config](#config)). `Meshtastic`/`MeshCore`'s 237-byte default mirrors Meshtastic's own advertised max payload; `SatelliteInternet`/`Reticulum`'s 32 KiB reflects constrained-IP and LXMF/RNS packet-size ballparks respectively; `Bluetooth`'s 64 KiB is a practical BLE GATT ceiling.

!!! note "Backward-compatibility anchor"
    `TerrestrialInternet` and `LocalNetwork` both use `TERRESTRIAL_MAX_PAYLOAD_BYTES` (16 MiB), which mirrors the daemon's own `MAX_FRAME` cap. Since every plugin defaults to `TerrestrialInternet` absent config, this guarantees the transport cap can never newly constrain a route that has no transport-level cap today: the effective cap is `min(plugin cap, transport cap)`, and 16 MiB is at least as large as anything a plugin has ever been able to advertise. A v0.3 config with no `transports:` block behaves identically to before this feature existed.

## Config

A top-level `transports:` block, sibling to `plugins` and `transport_budgets`, maps a **plugin name** to a class plus optional per-field policy overrides:

```yaml
transports:
  meshtastic: { class: meshtastic }                       # class -> its built-in default policy
  fieldsat:   { class: satellite_internet, max_payload_bytes: 32768, allow_images: false }
```

Each entry:

```yaml
transports:
  <plugin-name>:
    class: <transport_class>          # required
    max_payload_bytes: <u64>          # optional override
    allow_images: <bool>              # optional override
    allow_video: <bool>               # optional override
    compress: <bool>                  # optional override
    batch_telemetry: <bool>           # optional override
```

Omitted override fields fall back to the class's built-in default. `class` itself is validated by the config parser (an unknown class name is a deserialize error). `--check-config` additionally rejects:

- a `transports:` key that names a disabled or unknown plugin,
- a `max_payload_bytes` override below the floor (64 bytes: chosen to still admit `Meshtastic`/`MeshCore`'s 237-byte default while rejecting an override that would make a route unusable).

!!! example "A field-node config: LXMF over Reticulum, a LoRa mesh, and a satellite fallback"
    ```yaml
    plugins:
      lxmf:       { enabled: true }
      meshtastic: { enabled: true }
      fieldsat:   { enabled: true }   # some future MQTT-shaped satellite plugin

    transports:
      # meshtastic already defaults to `meshtastic`; listed here only to
      # show an override — halve the default payload cap for a noisier link.
      meshtastic: { class: meshtastic, max_payload_bytes: 120 }
      # lxmf needs no entry at all: it already defaults to `reticulum`.
      # fieldsat isn't a recognized protocol name, so without an entry it
      # would default to TerrestrialInternet — wrong for a metered,
      # constrained satellite uplink, so it's classified explicitly.
      fieldsat:   { class: satellite_internet, max_payload_bytes: 32768, allow_images: false }
    ```
    A message routed toward `fieldsat` gets images demoted to notes and a payload cap of `min(fieldsat's own Capabilities.max_payload, 32768)`; a message toward `meshtastic` is capped at 120 bytes instead of the class default of 237, with images already demoted by the `Meshtastic` class default regardless of the override (only `max_payload_bytes` was overridden here). `lxmf` gets `Reticulum`'s built-in policy (32 KiB cap, images/video allowed) with no config at all.

### Per-protocol default class

A plugin with no matching `transports:` entry gets a default class from its name:

| Plugin name | Default `TransportClass` |
|---|---|
| `mqtt`, `signal`, `nostr`, `bitchat` | `TerrestrialInternet` |
| `meshtastic` | `Meshtastic` |
| `meshcore` | `MeshCore` |
| `lxmf` | `Reticulum` |
| any other name (including unknown plugins) | `TerrestrialInternet` |

The **absence** of a `transports:` block entirely (true of every pre-transport-class config) means every plugin resolves its class from this table alone, and `TerrestrialInternet`'s non-constraining policy means such a config behaves identically to before the feature existed.

Resolution order (`Config::transport_policy(plugin)`): a `transports[plugin]` entry's class + overrides win when present; otherwise the per-protocol default class's built-in policy applies. Like `routes`/`render`/`identity_mode`, `transports` is read live per delivery: a `--check-config`-validated edit takes effect on the very next send, with no daemon restart.

## Egress: how the policy is applied

At egress, `switchyardd` resolves the destination plugin's `TransportPolicy` and applies it in the transform stage alongside the plugin's own protocol `Capabilities`. The two compose, most-restrictive-wins:

**Effective payload cap** = `min(plugin Capabilities.max_payload, transport_policy.max_payload_bytes)`. This combined cap feeds the existing `transform::render(..., max_payload)` truncation: no separate truncation stage. For the `TerrestrialInternet` default this is a no-op: the transport cap (16 MiB) is at least as large as anything a plugin has ever advertised.

**Media policy**: if the resolved policy disallows images (`!allow_images`) or video (`!allow_video`), matching attachments are demoted: stripped from the outgoing attachment list and replaced with a note, reusing the same drop-to-note path already used for capability-missing or oversize attachments:

```
[image 'photo.jpg' omitted — constrained transport]
```

Demotion is checked first (a cheap MIME-prefix test), ahead of the per-attachment byte cap and the cumulative frame-budget guard, so a media attachment that's disallowed outright never even touches the CAS. Non-media attachments, and media the transport allows, fall through to the existing size/CAS rules unchanged.

**Metric**: `relayfabric_transport_demoted_total` increments once per attachment demoted for a media-policy reason (not for ordinary capability/oversize/CAS-miss drops, which have their own note wording and don't touch this counter). It carries no labels in this implementation: a bare count is enough signal for v0.1, and it keeps the "no message content in metrics or logs" invariant trivially true: no filename, plugin name, or MIME type is ever attached to the counter.

**Compress / batch_telemetry**: resolved as flags on the policy but not yet wired to any behavior: no body compression, no telemetry aggregation, in Phase 1.

### SEALED routes are exempt

Sealed routes (SPEC §113) never apply a transport transform. `switchyardd`'s dispatch sends a sealed delivery to `process_due_fed_sealed`, which forwards the message exactly as sealed (never touching truncation, media demotion, or `Config::transport_policy` at all) *before* the code path that resolves and applies transport policy is ever reached. The exemption holds structurally, by dispatch order, not by an in-line guard: there is no shared code path between sealed egress and transport-policy resolution to guard in the first place.

An oversize sealed message is rejected at origin (`SEALED_OVERSIZE`) rather than silently transformed in transit: sealed means no in-transit transformation, full stop.

!!! warning "Verified even under an adversarial config"
    A regression test configures a `transports:` entry keyed on the federation protocol itself, with a tiny payload cap and both media flags off, then routes a sealed message over it. The delivered body and attachments at the far end are the original, untouched ones, proving the exemption isn't something a misconfiguration can accidentally bypass.

## Phase 2 (specced, not built)

Recorded so Phase 1's boundaries are drawn with it in mind. None of the following exists in the codebase today:

- **`relayfabric-core` extraction**: carving the transport-agnostic engine (routing, policy, transform, crypto/sign/seal, envelope, the transport-class model itself) out of the `switchyardd` binary into a reusable library crate. `switchyardd` would become a thin shell over the core, the same shape a future desktop or Android client would use.
- **`PlatformTransport` trait**: the seam that lets the core ask the platform "what transports exist and what are they like right now," so a link's class can change at runtime. The daemon would keep static per-plugin classes (a LoRa link is always constrained); an Android network monitor could flip a live link to `SatelliteInternet` and the same Phase 1 policy code would react, without daemon-side changes.
- **Android edge node**: a Rust core exposed via UniFFI/JNI, native BLE/Wi-Fi/cellular/satellite transports supplied through the trait above, and Reticulum support via a Rust RNS implementation (Python RNS cannot run in-app).

Phase 1 lands the abstraction and the highest-value degradation behavior first specifically to de-risk this later extraction: the transport boundary is explicit before any code has to move.

## See also

- [Configuration](configuration.md): the full `transports:` block in context with the rest of the config file.
- [Routing & Policy](routing.md): how transport policy fits into the broader egress transform pipeline alongside routes, render, and identity mode.
