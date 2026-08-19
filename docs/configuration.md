# Configuration

`switchyardd` reads a single YAML file at startup (`--config <path>`,
default `/etc/relayfabric/relayfabric.yaml`). The file is deny-by-default:
nothing is bridged between plugins unless a `routes` entry says so. This
page documents every top-level block, exactly as `switchyardd/src/config.rs`
parses and validates it, and which parts of a running daemon pick up an
edited file live versus need a restart.

The canonical, fully annotated reference is
[`docs/relayfabric.example.yaml`](relayfabric.example.yaml) — every field on
this page appears there with the same defaults and commentary. Copy it as a
starting point rather than writing a config from scratch.

## `node`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | *required* | This node's identifier. Signed into RFDP adverts, so it's capped at 64 characters and rejects control characters, newlines, and Unicode bidi/spoofing codepoints. |
| `data_dir` | path | *required* | Directory for the plugin/admin Unix sockets, storage (CAS, delivery queue), and node identity keys. |
| `public` | bool | `false` | When `true`, every route's source/destination protocols must be covered by `public_services` ingress/egress lists (see below); `--check-config` rejects an uncovered route. |

!!! warning "Restart required"
    Any change to `node` — including `data_dir` — requires a daemon
    restart. The plugin and admin socket paths are derived from `data_dir`
    once at startup and never re-bound.

## `plugins`

A map of plugin name → configuration. The name is also the protocol prefix
used in route endpoints (`mqtt:chat/a`, `lxmf:pasadena`, ...).

| Field | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | *required* | Whether the daemon treats this plugin as active. Routes referencing a disabled or unknown plugin fail `--check-config`. |
| `command` | string \| null | `null` | Shell command `switchyardd` spawns (via `sh -c`) and supervises. Omit to run the plugin yourself (e.g. under the hardened systemd template) — it connects to `<data_dir>/plugins.d/<name>.sock` using the `RELAYFABRIC_SOCKET` env var. |
| `peer_uid` | int \| null | `null` | Plugin isolation (v0.4): when set, **exactly** this UID may connect to the plugin's socket, verified via `SO_PEERCRED` before any frame is parsed; the socket file opens to 0666 so the foreign UID can reach it (the credential check is the gate). When unset, only the daemon's own UID may connect. Pair with `deploy/systemd/relayfabric-plugin@.service`. |
| `config` | map | `{}` | Arbitrary per-plugin settings, forwarded to the plugin process over `RELAYFABRIC_PLUGIN_CONFIG` at spawn. Any string value may be a [secret reference](#secret-references). |

Python plugins run under a venv and need an absolute interpreter path
(`command: /path/to/.venv/bin/python /path/to/relayfabric-lxmf`) — a bare
`relayfabric-lxmf` isn't on `PATH` under `sh -c`, and the script's shebang
won't see the venv's dependencies.

!!! note "Live vs. restart"
    Adding, removing, or changing a plugin's `enabled`/`command`/`config`
    reports that plugin's name in `restart_required` — the daemon doesn't
    restart itself, but that one plugin process needs to be
    stopped/restarted for the change to take effect. Unrelated plugins are
    unaffected.

## `routes`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | *required* | Unique route name. `@identity` is reserved for identity-link delivery. |
| `sources` | list of `"protocol:endpoint"` | *required* | Inbound endpoints this route accepts from. Must reference enabled plugins; `fed` is never a valid source protocol. |
| `destinations` | list of `"protocol:endpoint"` | *required* | Outbound endpoints this route fans a message out to. `fed:<peer_name>/<remote_route>` is valid here (see [federation](#federation)). |
| `identity_mode` | `pseudonymous` \| `linked` | `pseudonymous` | `linked` renders a verified identity link's `display_name` at egress instead of the route's HMAC alias, when one exists for the sender. Linking itself is always an explicit operator/user action (`switchyardctl link`/`unlink`/`identities`, or the admin API), never implicit. |
| `render` | map | see below | Per-route rendering knobs — see [Render knobs](#render-knobs). |
| `security_mode` | `gateway` \| `sealed` | `gateway` | `sealed` end-to-end AEAD-seals the payload between federation gateways; see [Security & Sealed Routing](security.md). Rejected below the node's `privacy.minimum_security` floor. |
| `allow_gateway_decryption` | bool \| null | `null` | Per-route override of `privacy.allow_gateway_decryption`. `null` defers to the node-level floor. |

### Render knobs

`render` tunes the transform pipeline that already runs on every send:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `tag` | `alias` \| `none` | `alias` | `alias` renders the `[tag]` sender prefix (pseudonym, or a linked `display_name`). `none` suppresses it entirely, including a linked display name. |
| `max_chars` | integer | `0` | `0` disables route-level truncation. `16` or greater truncates the message **body** to that many Unicode characters — the sender tag is never shortened by this. Values `1`–`15` are rejected. The transport's own byte cap still applies afterward to the whole assembled message as a hard floor, and unlike `max_chars` it may still truncate into the tag. |

```yaml
routes:
  - name: demo
    sources: ["mqtt:chat/a", "mqtt:chat/b"]
    destinations: ["mqtt:chat/a", "mqtt:chat/b"]
    render:
      tag: alias
      max_chars: 900
```

See [Routing & Policy](routing.md) for how routes interact with `policies`
and `public_services`.

## `transports`

A map of plugin name → transport class and optional policy overrides,
distinct from the plugin's wire protocol. This drives egress payload caps
and image/video allow/disallow — see [Transport Classes](transport-classes.md)
for the full class list and built-in policy defaults.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `class` | transport class name | *required per entry* | Selects the built-in `TransportPolicy` baseline for this plugin. |
| `max_payload_bytes` | integer \| null | `null` (class default) | Overrides the class's payload cap. Minimum `64` bytes. |
| `allow_images` | bool \| null | `null` (class default) | Overrides whether image attachments are allowed. |
| `allow_video` | bool \| null | `null` (class default) | Overrides whether video attachments are allowed. |
| `compress` | bool \| null | `null` (class default) | Overrides the class's compression default. |
| `batch_telemetry` | bool \| null | `null` (class default) | Overrides the class's telemetry-batching default. |

A plugin with no `transports` entry gets a default class by protocol name:
`mqtt`/`signal`/`nostr`/`bitchat` → `terrestrial_internet`, `meshtastic` →
`meshtastic`, `meshcore` → `mesh_core`, `lxmf` → `reticulum`; anything else
also falls back to `terrestrial_internet`. That default reproduces
pre-transport-class behavior exactly (no cap beyond the daemon's 16 MiB
frame limit, images and video allowed).

At egress, the composed policy caps payload to `min(plugin cap, transport
cap)`; an attachment the class forbids is dropped and replaced with a body
note (e.g. `[image 'photo.jpg' omitted — constrained transport]`) rather
than sent. Sealed routes are exempt — no transform ever touches a sealed
payload.

```yaml
transports:
  meshtastic: { class: meshtastic }
  mqtt:       { class: satellite_internet, max_payload_bytes: 32768, allow_images: false }
```

Takes effect live — no restart needed.

## `transport_budgets`

Rate limits per egress protocol.

| Field | Type | Default | Meaning |
|---|---|---|---|
| *(map key)* | plugin name | — | Must name an enabled plugin. |
| `messages_per_minute` | integer | *required per entry* | `0` is rejected at `--check-config` (it would block all egress) — omit the entry instead to leave that protocol unlimited. |

```yaml
transport_budgets:
  mqtt:
    messages_per_minute: 500
  lxmf:
    messages_per_minute: 200
```

Takes effect live: reload resets the budget window for every configured
protocol (and every `fed/<peer_name>` window).

## `privacy`

Node-level sealed-routing privacy floor.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `minimum_security` | `gateway` \| `sealed` | `gateway` | Minimum `security_mode` any route may declare. A route below the floor is rejected at `--check-config`, never silently downgraded. |
| `allow_gateway_decryption` | bool | `true` | Whether this node may terminate a sealed inbound envelope by decrypting it for delivery to a plaintext leg. `false` refuses that role. |
| `allow_protocol_downgrade` | bool | `true` | Parsed and stored; not yet separately enforced — `allow_gateway_decryption` is today's actual downgrade-refusal gate. |

```yaml
privacy:
  minimum_security: sealed
  allow_gateway_decryption: false
```

Deliberately kept a top-level block (not nested under `node`) so it applies
live rather than forcing a restart. See
[Security & Sealed Routing](security.md).

## `federation`

Absent entirely — as in every pre-federation config — means the feature is
off: no Noise listener, no fed egress/ingress, no trust seeding.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `listen` | string \| null | `null` | Bind address for the Noise listener. `null` means outbound-only (no inbound listener). |
| `accept_from` | `verified` \| `trusted` | `verified` | Minimum trust-store level an inbound envelope's signer chain must have to be accepted. |
| `max_hops` | integer | `4` | Inbound envelopes at or over this hop count are dead-lettered `HOP_LIMIT`. |
| `max_ttl_secs` | integer | `86400` | Inbound TTL is clamped down to this many seconds. |
| `identity_exposure` | `pseudonymous` \| `full` | `pseudonymous` | Outbound source-reference handling. |
| `ingress_routes` | list of route names | `[]` | Local routes federated peers may inject an inbound envelope into. Empty means no route accepts fed ingress. |
| `peers` | list of peer entries | `[]` | See below. |
| `trusted` | list of node IDs | `[]` | Extra `node_id`s seeded to trust level `trusted` at boot, beyond what `peers[].trust` already grants. |
| `blocked` | list of node IDs | `[]` | Node IDs refused at handshake. |

Each `peers[]` entry:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | *required* | Local label for the peer. |
| `node_id` | string | *required* | `"rf:"` + 64 hex chars — the peer's Ed25519 public key. |
| `addr` | string | *required* | `host:port` to dial. |
| `trust` | `verified` \| `trusted` | `verified` | Trust level seeded at boot. |
| `messages_per_minute` | integer | `0` (unlimited) | Aggregate egress budget for this peer's fed link. |
| `sealed_key` | string \| null | `null` | 64 lowercase hex chars pinning this peer's sealed-routing X25519 key; `null` means it's learned from the peer's advert. |

```yaml
federation:
  listen: "127.0.0.1:47000"
  accept_from: verified
  peers:
    - name: phoenix
      node_id: "rf:<64hex>"
      addr: "10.0.0.2:47000"
```

!!! warning "Restart required"
    Any change to `federation` — including a single peer added, removed,
    or edited — reports the `"daemon"` restart entry. Live fed reconfig
    (rebinding the listener, renegotiating already-connected peers) is not
    yet implemented; the block only takes effect on the next daemon start.

RFDP discovery (node adverts describing `public_services`) is a related,
separately-versioned `discovery:` block that requires `federation` to be
set — see [Federation & Discovery](federation.md).

## Top-level TTLs and limits

| Field | Type | Default | Meaning |
|---|---|---|---|
| `ttl_default_secs` | integer | `86400` | Default message time-to-live, in seconds. |
| `dedup_ttl_secs` | integer | `86400` | How long a delivered message's dedup fingerprint is remembered. |
| `hop_limit` | integer | `8` | Maximum route hops before a message is dropped. |
| `max_attachment_bytes` | integer | `8000000` (8 MB) | Daemon-wide inbound attachment budget, in bytes. |

`dedup_ttl_secs` applies live (pushed into the dedup store's TTL on reload;
entries already recorded keep aging out under whatever TTL was in effect
when they were recorded). The other three are read fresh on every use, so
they also take effect on the next config apply with no restart.

## Secret references

Any **string** value inside a plugin's `config:` block may be, in its
entirety, one of two forms:

- `${env:NAME}` — the named environment variable, resolved once at config
  load. Errors at load if unset or empty.
- `${file:/abs/path}` — a file's trimmed contents, resolved once at config
  load. The path **must be absolute**; a relative `${file:...}` is
  rejected. Errors at load if unreadable or empty after trimming. A
  group/world-readable secret file triggers a warning (still resolves —
  not a hard error).

```yaml
config:
  broker_token: ${env:RELAYFABRIC_MQTT_TOKEN}
  api_key: ${file:/etc/relayfabric/secrets/api-key}
```

!!! note "Whole-value only"
    There's no interpolation inside a longer string — a value is either
    exactly `${env:...}`/`${file:...}` or it's ordinary literal text, never
    a mix. `prefix ${env:TOKEN}` is treated as a literal string, not
    resolved.

Resolved values are passed to the plugin process via the
`RELAYFABRIC_PLUGIN_CONFIG` env var at spawn (the plugin scrubs it from its
own environment immediately after parsing, so children it spawns don't
inherit it). Resolved secret values **never** appear in admin API
responses, logs, or `--check-config` output — those always show the
unresolved `${...}` form.

## Other top-level blocks

A few blocks round out the example config but are documented in depth
elsewhere:

| Block | Purpose | See |
|---|---|---|
| `policies` | Per-destination-protocol rules: payload caps, dropped message kinds, attachment allow/reject. | [Routing & Policy](routing.md) |
| `public_services` | Named ingress/egress protocol sets a `node.public: true` node advertises. | [Routing & Policy](routing.md) |
| `limits` | Per-sender, per-route, and global rate/queue limits. All fields default to `0` (unlimited). | [Operations](operations.md) |

## Validating configuration

```bash
switchyardd --config /path/to/relayfabric.yaml --check-config
```

Parses, validates, and resolves secrets using the exact same pipeline the
daemon uses at startup, then exits without binding any sockets or spawning
any plugins:

- Valid: prints `configuration valid: N route(s), M plugin(s)` and exits 0.
- Invalid: prints `config error: <message>` to stderr and exits 1.

The admin API exposes the same pipeline for a running daemon:
`POST /v1/config/validate` checks a candidate YAML body without applying
it, `PUT /v1/config` validates and applies it (returning which parts need a
restart), and `GET /v1/config` serves the currently loaded config back
byte-for-byte, secrets still in `${...}` form. See
[Operations](operations.md).

## Hot reload summary

`PUT /v1/config` (or restarting against an edited file) swaps in the new
config. Most blocks apply live; a few require a restart:

| Block / field | Effect |
|---|---|
| `routes`, `policies`, `public_services`, `limits`, `transport_budgets`, `transports`, `privacy` | Live — next read picks up the new value, no restart. |
| `render`, `identity_mode`, `security_mode`, `allow_gateway_decryption` (route-level) | Live. |
| `dedup_ttl_secs`, `ttl_default_secs`, `hop_limit`, `max_attachment_bytes` | Live. |
| `plugins.<name>` (`enabled`/`command`/`config` changed, or added/removed) | That plugin's name is reported in `restart_required` — only it needs restarting. |
| `node` (any field) | Reports `"daemon"` — full daemon restart required. |
| `federation` (any field) | Reports `"daemon"` — full daemon restart required. |
| `discovery` (any field) | Reports `"daemon"` — full daemon restart required. |

## Minimal working example

```yaml
node:
  name: example-gateway
  data_dir: /var/lib/relayfabric

plugins:
  mqtt:
    enabled: true
    command: relayfabric-mqtt
    config:
      broker: mqtt://127.0.0.1:1883
      topics: [chat/a, chat/b]

routes:
  - name: demo
    sources: ["mqtt:chat/a", "mqtt:chat/b"]
    destinations: ["mqtt:chat/a", "mqtt:chat/b"]

ttl_default_secs: 86400
dedup_ttl_secs: 86400
hop_limit: 8
max_attachment_bytes: 8000000
```

Validate it, then run the daemon against it:

```bash
switchyardd --config docs/relayfabric.example.yaml --check-config
switchyardd --config docs/relayfabric.example.yaml
```

For the complete, heavily annotated reference — every plugin's config
shape, `policies`, `public_services`, `limits`, `federation`, `discovery`,
and `privacy` all shown together — see
[`docs/relayfabric.example.yaml`](relayfabric.example.yaml).

## See also

- [Routing & Policy](routing.md) — how `routes`, `policies`, and
  `public_services` combine to decide what's allowed to cross.
- [Security & Sealed Routing](security.md) — `security_mode`, the
  `privacy` floor, and sealed federation routing in depth.
- [Transport Classes](transport-classes.md) — the full class list and
  built-in `TransportPolicy` defaults behind `transports`.
- [Operations](operations.md) — the admin API, `limits`, and running a
  daemon in production.
