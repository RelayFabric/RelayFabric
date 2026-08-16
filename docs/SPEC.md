# RelayFabric Technical Specification

**Project:** RelayFabric
**Core daemon:** `switchyardd`
**Specification version:** 0.1
**Status:** Initial architecture specification
**Primary implementation language:** Rust
**Architecture:** Protocol-independent, plugin-based communications routing fabric

---

## 1. Overview

RelayFabric is an open communications routing fabric for interconnecting otherwise incompatible messaging, mesh, radio, and Internet communications systems.

RelayFabric provides a common routing, policy, identity, security, and message-processing layer while delegating protocol-specific behavior to plugins.

Initial target networks include:

* Reticulum / LXMF
* Signal
* Meshtastic
* MeshCore
* Bitchat
* Nostr
* MQTT

Future adapters may support:

* Matrix
* APRS
* IRC
* XMPP
* Mattermost
* Slack
* email
* SMS
* Gotify
* webhooks
* amateur radio digital messaging systems
* satellite messaging systems
* other store-and-forward networks

RelayFabric is not itself a messaging network. It is infrastructure for routing communications between networks.

The core daemon is named:

```text
switchyardd
```

Conceptually:

```text
                         RelayFabric

                     ┌─────────────────┐
                     │   switchyardd   │
                     │                 │
                     │ routing         │
                     │ policy          │
                     │ identity        │
                     │ queueing        │
                     │ security        │
                     │ audit           │
                     └────────┬────────┘
                              │
          ┌───────────┬───────┼───────┬───────────┐
          │           │       │       │           │
        LXMF       Signal  MeshCore Meshtastic Bitchat
          │           │       │       │           │
     Reticulum     Signal    LoRa    LoRa       BLE/Nostr
```

---

# 2. Goals

RelayFabric SHALL provide:

1. Bidirectional communication between heterogeneous messaging networks.
2. A protocol-independent internal message representation.
3. A stable plugin interface.
4. Policy-controlled routing between networks.
5. Store-and-forward delivery.
6. Loop prevention.
7. Message deduplication.
8. Explicit trust boundaries.
9. Privacy-preserving cross-network operation.
10. Optional cross-network identity association.
11. Protocol capability negotiation.
12. Message transformation and degradation where required.
13. Security controls appropriate for untrusted radio networks.
14. Persistent queues for intermittently connected networks.
15. Support for very low-bandwidth transports.
16. Deployment from Raspberry Pi-class edge nodes through centralized servers.
17. Fault isolation between protocol adapters.
18. Operational observability without requiring collection of message content.
19. Multiple gateway federation.
20. Extensibility without requiring changes to the core daemon.

---

# 3. Non-Goals

RelayFabric SHALL NOT initially attempt to:

* replace Reticulum routing
* replace Meshtastic mesh routing
* replace MeshCore routing
* replace Signal
* implement a new radio PHY
* create transparent Layer 2 bridging
* merge identities across networks automatically
* guarantee semantic parity between protocols
* guarantee cross-network E2EE when unmodified native clients are used
* reimplement complex service protocols when a stable integration API already exists
* provide anonymous communication guarantees against global traffic analysis

RelayFabric routes application communications between systems.

---

# 4. Design Principles

## 4.1 Route messages, not identities

The default behavior SHALL NOT assume:

```text
Signal user A
=
Meshtastic user A
=
LXMF user A
```

Protocol identities remain independent unless explicitly associated.

---

## 4.2 Protocol independence

The core SHALL NOT contain protocol-specific routing logic.

Protocol-specific behavior belongs in plugins.

---

## 4.3 Least information disclosure

RelayFabric SHALL disclose only the information required to route and represent a message on the destination network.

Native identifiers SHALL NOT automatically cross protocol boundaries.

---

## 4.4 Explicit trust boundaries

RelayFabric SHALL clearly distinguish between:

* transport encryption
* gateway-visible plaintext
* signed messages
* application-level end-to-end encrypted messages

Users and administrators MUST be able to determine when a gateway can read content.

---

## 4.5 Store-and-forward first

RelayFabric SHALL assume networks may be:

* intermittent
* slow
* partitioned
* offline
* high-latency

Persistent queues are therefore a core capability rather than an optional extension.

---

## 4.6 Capability-aware routing

The router MUST NOT assume that every destination supports every feature.

Examples:

```text
Signal attachment
     ↓
Meshtastic
```

may become:

```text
[attachment omitted]
```

rather than attempting to transmit several megabytes over LoRa.

---

## 4.7 Failure isolation

A failed Signal adapter MUST NOT terminate Reticulum, MeshCore, or other adapters.

Plugins SHOULD therefore run out-of-process by default.

---

# 5. High-Level Architecture

```text
 ┌─────────────────────────────────────────────────────────┐
 │                      RelayFabric                        │
 │                                                         │
 │                    switchyardd                          │
 │                                                         │
 │  ┌───────────┐   ┌────────────┐   ┌─────────────────┐ │
 │  │ Ingress   │──►│ Normalizer │──►│ Policy / Router │ │
 │  └───────────┘   └────────────┘   └────────┬────────┘ │
 │                                            │           │
 │                                      ┌─────▼─────┐     │
 │                                      │ Queue     │     │
 │                                      │ Manager   │     │
 │                                      └─────┬─────┘     │
 │                                            │           │
 │                                      ┌─────▼─────┐     │
 │                                      │ Transform │     │
 │                                      └─────┬─────┘     │
 │                                            │           │
 │                                      ┌─────▼─────┐     │
 │                                      │ Egress    │     │
 │                                      └───────────┘     │
 │                                                         │
 └─────────────────────────┬───────────────────────────────┘
                           │ Plugin IPC
        ┌──────────────────┼─────────────────────────┐
        │                  │                         │
  relay-lxmf         relay-signal            relay-meshtastic
        │                  │                         │
      LXMF             signal-cli                  radio
```

---

# 6. Components

## 6.1 `switchyardd`

The primary RelayFabric daemon.

Responsibilities:

* plugin lifecycle
* message normalization
* routing
* policy evaluation
* identity aliasing
* deduplication
* persistent queueing
* transformation
* security policy
* provenance
* message TTL enforcement
* rate limiting
* health monitoring
* auditing
* configuration
* administrative API

The daemon SHOULD NOT directly implement individual external protocols.

---

## 6.2 Plugin processes

Recommended naming convention:

```text
relayfabric-lxmf
relayfabric-signal
relayfabric-meshtastic
relayfabric-meshcore
relayfabric-bitchat
relayfabric-nostr
relayfabric-mqtt
```

Plugins communicate with `switchyardd` through a defined IPC protocol.

---

## 6.3 `switchyardctl`

Administrative CLI.

Examples:

```bash
switchyardctl status
switchyardctl plugins
switchyardctl routes
switchyardctl peers
switchyardctl queue
switchyardctl identities
switchyardctl policy test
switchyardctl message trace
```

---

# 7. Plugin Architecture

RelayFabric SHALL support multiple backend styles.

```text
Plugin
  │
  ├── native library
  ├── native protocol
  ├── daemon API
  ├── local socket
  └── external service
```

Preference order:

1. stable native API/protocol
2. stable local daemon API
3. supported SDK
4. CLI integration
5. reverse-engineered protocol only when necessary

---

# 8. Initial Plugin Strategy

## Reticulum / LXMF

Preferred:

```text
native RNS/LXMF integration
```

Capabilities should include where available:

* destination hashes
* signature status
* message hashes
* delivery state
* propagation
* RSSI
* SNR
* stamps
* path information

---

## Signal

Preferred initial backend:

```text
signal-cli JSON-RPC
```

Architecture:

```text
relayfabric-signal
       │
 SignalBackend API
       │
 SignalCliBackend
       │
   signal-cli
       │
 Signal service
```

The Signal plugin SHALL abstract its backend so that a different implementation can replace `signal-cli` later.

---

## Meshtastic

Preferred:

* native client protocol
* protobuf
* official SDK when appropriate

The adapter SHOULD support serial and TCP-connected nodes.

---

## MeshCore

Preferred:

```text
Companion Radio Protocol
```

The gateway should interact directly with a companion-mode radio rather than wrapping a user-facing application.

---

## Bitchat

Preferred:

* native protocol implementation where stable
* separate BLE and Internet/Nostr transport concepts when appropriate

---

## Nostr

Preferred:

```text
native protocol
```

---

## MQTT

Preferred:

```text
native MQTT client
```

MQTT also provides a useful integration and testing transport.

---

# 9. Plugin IPC

Plugins SHOULD run as separate processes.

Recommended IPC mechanisms:

```text
Unix domain socket
```

for local deployments.

Optional later transports:

* TCP
* QUIC
* gRPC
* authenticated remote plugin connections

The initial protocol SHOULD be simple, versioned, and language-neutral.

Candidate encodings:

* MessagePack
* CBOR
* protobuf

CBOR is preferred for constrained deployments.

---

# 10. Plugin Interface

Conceptually:

```rust
trait RelayPlugin {
    fn descriptor() -> PluginDescriptor;

    async fn start() -> Result<()>;

    async fn health() -> HealthStatus;

    async fn send(
        endpoint: Endpoint,
        message: GatewayMessage
    ) -> Result<DeliveryResult>;

    async fn shutdown() -> Result<()>;
}
```

Plugins asynchronously emit received messages to `switchyardd`.

---

# 11. Plugin Descriptor

Example:

```json
{
  "plugin": "meshtastic",
  "version": "1.0",
  "protocol_version": 1,
  "capabilities": {
    "text": true,
    "direct_messages": true,
    "groups": true,
    "attachments": false,
    "location": true,
    "reactions": false,
    "receipts": false,
    "max_payload": 237
  }
}
```

---

# 12. Canonical Message Envelope

Every inbound message SHALL be converted into a RelayFabric envelope before routing.

Example:

```json
{
  "version": 1,
  "id": "01K2RF...",
  "source": {
    "protocol": "meshtastic",
    "instance": "pasadena-01",
    "endpoint": "channel:0"
  },
  "sender": {
    "native_ref": "opaque",
    "alias": "MESH-7F21"
  },
  "type": "text",
  "body": "Testing from Pasadena",
  "created_at": "2026-08-15T08:32:10Z",
  "received_at": "2026-08-15T08:32:12Z",
  "expires_at": "2026-08-16T08:32:10Z",
  "reply_to": null,
  "attachments": [],
  "security": {},
  "provenance": [],
  "native": {}
}
```

---

# 13. Message IDs

RelayFabric SHALL assign a globally unique internal message ID.

Preferred:

```text
UUIDv7
```

or:

```text
ULID
```

The internal ID MUST remain stable as the message passes through RelayFabric.

Protocol-native IDs SHOULD additionally be retained inside the gateway trust boundary.

---

# 14. Message Types

Initial message types:

```text
text
notice
location
telemetry
command
attachment
reaction
receipt
presence
```

Plugins MAY advertise additional native message types.

Unknown types MUST NOT cause router failure.

---

# 15. Native Metadata

Protocol-specific information MAY be retained under:

```json
"native": {}
```

Example LXMF:

```json
{
  "native": {
    "rssi": -104,
    "snr": 7.2,
    "signature_valid": true
  }
}
```

Native metadata SHALL NOT automatically be forwarded.

Policies determine which metadata may cross a boundary.

---

# 16. Capability Model

Every plugin SHALL advertise supported capabilities.

Example:

```rust
struct Capabilities {
    text: bool,
    direct_messages: bool,
    groups: bool,
    attachments: bool,
    location: bool,
    reactions: bool,
    receipts: bool,
    presence: bool,
    max_payload: Option<u64>,
}
```

---

# 17. Transform Pipeline

Before egress:

```text
canonical message
       │
       ▼
destination capabilities
       │
       ▼
policy
       │
       ▼
transform
       │
       ▼
protocol adapter
```

Example:

```text
Signal message

"Look at this"
+ 4 MB photo
```

to Meshtastic:

```text
[SIG-A921]
Look at this
[attachment omitted]
```

---

# 18. Identity Model

RelayFabric SHALL treat every native protocol identity independently.

Examples:

```text
signal:uuid:...
lxmf:82ad...
meshtastic:!ab12cd34
meshcore:key:...
bitchat:key:...
nostr:npub...
```

These SHALL NOT automatically resolve to a common human identity.

---

# 19. Identity Privacy Modes

RelayFabric SHALL provide at least three sender presentation modes.

## Anonymous

Destination sees:

```text
[Meshtastic User]
Hello
```

No stable identifier crosses the route.

---

## Pseudonymous

Default recommended mode.

Destination sees:

```text
[MESH-7F21]
Hello
```

The pseudonym is stable only within a configured privacy scope.

---

## Linked

After explicit identity association:

```text
[Jascha]
Hello
```

Linked mode MUST require explicit administrator policy and/or end-user verification.

---

# 20. Route-Scoped Pseudonyms

RelayFabric SHOULD generate route-specific aliases using an HMAC.

Conceptually:

```text
alias =
HMAC(
    gateway_secret,
    native_identity || privacy_scope
)
```

Example:

```text
Meshtastic !abcd1234

Signal route A:
MESH-7F21

Matrix route B:
MESH-C82A

Nostr route C:
MESH-19EE
```

Observers on separate networks therefore cannot trivially correlate the user.

---

# 21. Identity Linking

Identity linking MUST be opt-in.

Example:

```text
/link signal alice.42
```

RelayFabric sends a verification challenge to the target account.

Example:

```text
Verification code: 391847
```

The user confirms possession.

Only then may RelayFabric store:

```text
mesh:!abcd
       ↕
signal:uuid...
```

---

# 22. Identity Unlinking

Users or administrators SHOULD be able to remove associations.

Example:

```text
/unlink signal
```

RelayFabric SHOULD support deletion of associated correlation data when administratively permitted.

---

# 23. Privacy Rule

A central RelayFabric principle SHALL be:

> Route messages, not identities.

Cross-network identity federation is optional functionality layered on top of routing.

---

# 24. Routing Model

Routes map one or more ingress endpoints to one or more egress endpoints.

Example:

```yaml
routes:

  - name: pasadena-general

    sources:
      - protocol: reticulum
        endpoint: pasadena

      - protocol: meshtastic
        endpoint: longfast

      - protocol: signal
        endpoint: group:pasadena

    destinations:
      - protocol: reticulum
        endpoint: pasadena

      - protocol: meshtastic
        endpoint: longfast

      - protocol: signal
        endpoint: group:pasadena
```

The ingress endpoint SHALL automatically be excluded from immediate echo unless explicitly allowed.

---

# 25. Route Types

RelayFabric SHOULD support:

### One-to-one

```text
LXMF user → Signal user
```

### One-to-many

```text
LXMF room
   ├→ Signal group
   └→ MeshCore channel
```

### Many-to-one

```text
MeshCore
Meshtastic
LXMF
   ↓
Signal emergency room
```

### Many-to-many

```text
communications fabric
```

---

# 26. Routing Criteria

Routes MAY match:

* source protocol
* source instance
* source endpoint
* sender
* pseudonym
* message type
* security mode
* message priority
* destination
* content metadata
* radio metadata
* time of day
* route health
* network availability
* message size

---

# 27. Loop Prevention

Loop prevention is mandatory.

Every gateway SHALL track:

```text
message ID
origin
route history
gateway history
```

A message SHALL NOT be retransmitted through an already traversed route unless explicitly configured.

---

# 28. Deduplication

RelayFabric SHALL maintain a deduplication cache.

Possible key:

```text
canonical message ID
```

For external messages without stable IDs:

```text
hash(
    protocol ||
    native_sender ||
    timestamp_window ||
    payload
)
```

Deduplication TTL SHALL be configurable.

---

# 29. Hop Limit

Messages SHOULD include:

```text
fabric_hop_count
fabric_hop_limit
```

Example default:

```text
hop_limit = 8
```

This is independent from radio-layer hop limits.

---

# 30. Federation

Multiple RelayFabric gateways MAY interconnect.

Example:

```text
Pasadena RelayFabric
       │
       ▼
DX.PE backbone
       │
       ▼
Desert RelayFabric
       │
       ▼
MeshCore
```

Federated routing SHOULD preserve gateway provenance.

---

# 31. Security Modes

RelayFabric SHALL define three content-security modes.

## TRANSLATE

```text
Network A encryption
       ↓
     gateway
    plaintext
       ↓
Network B encryption
```

Provides maximum compatibility.

The gateway can:

* read
* modify
* drop
* replay
* inject

messages.

This MUST be documented as a trusted gateway mode.

---

## SIGNED

Content is visible to the gateway but carries an origin signature.

```text
sender
  ↓ sign
message
  ↓
gateway
  ↓
destination verifies
```

This protects integrity and provenance when destination software understands RelayFabric signatures.

A gateway may drop a message but cannot silently alter signed content without invalidating the signature.

---

## OPAQUE (renamed: SEALED — see §113)

Application-level payload remains encrypted across gateways.

```text
sender
  │ encrypt
  ▼
ciphertext
  │
Network A
  │
Gateway
  │
Network B
  │
recipient
  ▼
decrypt
```

The gateway sees only required routing metadata.

This mode requires RelayFabric-aware endpoints or companion applications.

---

# 32. Universal Secure Envelope

Future SIGNED/OPAQUE operation SHOULD support:

```text
RelayEnvelope
├── version
├── message_id
├── origin
├── destination
├── timestamp
├── expiration
├── payload
├── payload_type
├── origin_signature
├── encryption_metadata
└── gateway_attestations[]
```

---

# 33. Gateway Attestation

Each participating gateway MAY append an attestation.

Example:

```text
Origin signature
       ↓
Gateway A attestation
       ↓
Gateway B attestation
       ↓
Destination
```

This creates a verifiable transit history without requiring every gateway to be trusted for authorship.

---

# 34. Threat Model

RelayFabric SHOULD explicitly address:

## Malicious gateway operator

May attempt to:

* read messages
* correlate identities
* modify messages
* inject messages
* suppress messages

Mitigations:

* OPAQUE mode
* signatures
* minimal logging
* route-scoped pseudonyms
* audit trails

---

## Compromised gateway

Mitigations:

* process isolation
* least privilege
* plugin sandboxing
* encrypted storage
* limited network access
* signed configurations
* secrets separation

---

## Malicious radio participant

May attempt:

* flooding
* replay
* spoofing
* malformed packets
* resource exhaustion

Mitigations:

* ACLs
* rate limits
* message-size limits
* signature verification
* replay protection
* resource quotas

---

## Traffic analysis

Even OPAQUE mode exposes some metadata:

* timing
* message size
* gateway involvement
* some routing information

RelayFabric SHALL NOT claim to defeat global traffic analysis.

---

# 35. Trust Domains

Each route SHALL define its trust boundary.

Example:

```yaml
trust:
  ingress: untrusted
  gateway: trusted
  destination: external
```

Policies SHOULD be able to restrict sensitive routes accordingly.

---

# 36. Policy Engine

The policy engine decides whether and how a message may pass.

Example:

```yaml
policies:

  - name: low-bandwidth-radio

    match:
      destination_protocol:
        - meshtastic
        - meshcore

    rules:
      max_payload: 220
      attachments: reject
      location: strip
```

---

# 37. Policy Actions

Supported actions SHOULD include:

```text
allow
deny
drop
queue
truncate
transform
strip_metadata
anonymize
pseudonymize
require_signature
require_encryption
rate_limit
redirect
mirror
```

---

# 38. Default Security Policy

RelayFabric SHOULD ship deny-by-default for externally exposed administrative functionality.

Message routes SHOULD require explicit configuration.

No automatic cross-network forwarding SHOULD occur solely because two plugins are active.

---

# 39. Message Priority

Suggested priority classes:

```text
emergency
high
normal
bulk
background
```

Low-bandwidth plugins MAY use priority to determine queue ordering.

---

# 40. Store-and-Forward Queue

All messages that cannot immediately be delivered MAY enter a persistent queue.

Queue record:

```text
message_id
route_id
destination
priority
attempt_count
next_attempt
created_at
expires_at
state
```

---

# 41. Queue States

```text
pending
attempting
delivered
failed
expired
dead-letter
```

---

# 42. Retry Strategy

Retry SHOULD support configurable exponential backoff.

Example:

```text
5 seconds
30 seconds
2 minutes
10 minutes
1 hour
```

Radio transports may require significantly different retry policies.

---

# 43. Expiration

Messages MUST support TTL.

Example:

```yaml
ttl:
  default: 24h
  emergency: 6h
  telemetry: 10m
```

Expired messages SHALL NOT be delivered.

---

# 44. Dead-Letter Queue

Permanently failed messages SHOULD enter a DLQ with reason codes.

Examples:

```text
PAYLOAD_TOO_LARGE
DESTINATION_UNKNOWN
POLICY_DENIED
IDENTITY_INVALID
PLUGIN_UNAVAILABLE
TTL_EXPIRED
UNSUPPORTED_CAPABILITY
```

---

# 45. Backpressure

Plugins MUST be unable to exhaust `switchyardd` memory by sending unbounded ingress traffic.

Required controls:

* bounded queues
* per-plugin quotas
* per-route quotas
* disk limits
* rate limiting

---

# 46. Radio-Aware Behavior

RelayFabric SHOULD recognize constrained transports.

Example classes:

```text
high bandwidth
medium bandwidth
low bandwidth
extremely constrained
```

Signal:

```text
high
```

LXMF over TCP:

```text
high/medium
```

LXMF over LoRa:

```text
low
```

Meshtastic:

```text
low
```

MeshCore:

```text
low
```

---

# 47. Transport Cost

Routes MAY expose a cost score:

```text
latency
bandwidth
airtime
monetary cost
energy
reliability
```

Future routing may select between multiple paths based on policy.

---

# 48. Emergency Routing

RelayFabric SHOULD support emergency-specific policy.

Example:

```yaml
routes:
  - name: emergency

    priority: emergency

    destinations:
      - reticulum:regional
      - signal:emergency-team
      - meshcore:emergency
```

Emergency status MUST NOT automatically bypass authorization rules.

---

# 49. Command Messages

RelayFabric MAY expose controlled administrative commands over selected networks.

Examples:

```text
/status
/help
/who
/routes
```

Sensitive commands MUST require authenticated authorization.

Radio participants SHALL NOT obtain administrative control merely by reaching the gateway.

---

# 50. Persistence

Initial implementation MAY use SQLite.

Suggested databases:

```text
relayfabric.db
```

Tables:

```text
messages
deliveries
routes
identities
identity_links
aliases
plugins
audit
dedup
gateway_peers
```

---

# 51. Secrets

Secrets MUST NOT be stored directly in normal YAML configuration.

Supported secret sources SHOULD eventually include:

* environment variables
* system keyring
* files with strict permissions
* OpenBao
* HashiCorp Vault
* systemd credentials

---

# 52. Logging

Default logs SHOULD contain operational information without message content.

Example:

```text
message=01K...
route=pasadena-general
source=meshtastic
destination=signal
result=delivered
latency=482ms
```

---

# 53. Privacy-Preserving Logging

Configuration:

```yaml
logging:
  content: false
  native_identifiers: hash
  retention: 24h
```

Native identifiers SHOULD be salted/HMACed rather than simply SHA hashed.

---

# 54. Audit Events

Security-relevant events SHOULD be auditable:

* route changes
* plugin installation
* configuration changes
* identity linking
* policy denial
* administrative actions
* secret rotation
* gateway federation changes

---

# 55. Metrics

Prometheus-compatible metrics SHOULD include:

```text
relayfabric_messages_ingress_total
relayfabric_messages_egress_total
relayfabric_messages_dropped_total
relayfabric_queue_depth
relayfabric_delivery_latency_seconds
relayfabric_plugin_up
relayfabric_policy_denials_total
relayfabric_duplicate_messages_total
relayfabric_route_messages_total
```

Protocol plugins MAY expose:

```text
RSSI
SNR
radio utilization
queue utilization
peer count
```

---

# 56. Health

```bash
switchyardctl status
```

Example:

```text
switchyardd          healthy

Plugins
--------------------------------
lxmf                 healthy
signal               healthy
meshtastic           healthy
meshcore             degraded
bitchat              offline

Queue
--------------------------------
pending              14
dead-letter          2
```

---

# 57. Administrative API

Local API SHOULD be available through a Unix socket by default.

Potential endpoints:

```text
GET  /v1/status
GET  /v1/plugins
GET  /v1/routes
GET  /v1/queue
GET  /v1/messages/{id}
GET  /v1/identities
POST /v1/routes
POST /v1/messages
POST /v1/policy/test
```

Remote API access MUST require strong authentication and TLS.

---

# 58. Configuration

Primary configuration:

```text
/etc/relayfabric/relayfabric.yaml
```

Example:

```yaml
node:
  name: dxpe-pasadena
  data_dir: /var/lib/relayfabric

plugins:

  lxmf:
    enabled: true

  signal:
    enabled: true
    backend: signal-cli

  meshtastic:
    enabled: true
    connection: tcp://127.0.0.1:4403

privacy:
  default_identity_mode: pseudonymous
  route_scoped_aliases: true
  identity_linking: false

security:
  default_mode: translate

logging:
  content: false
  native_identifiers: hmac

routes:

  - name: pasadena-general

    sources:
      - lxmf:pasadena
      - meshtastic:longfast

    destinations:
      - lxmf:pasadena
      - meshtastic:longfast
```

---

# 59. Configuration Validation

Before startup:

```bash
switchyardd --check-config
```

SHALL validate:

* syntax
* plugin existence
* routes
* duplicate routes
* invalid destinations
* policy references
* secrets references

---

# 60. Hot Reloading

Non-security-critical configuration SHOULD support reload without daemon restart.

Example:

```bash
switchyardctl reload
```

Security-sensitive changes SHOULD generate audit events.

---

# 61. Plugin Discovery

Plugin directories:

```text
/usr/lib/relayfabric/plugins/
/usr/local/lib/relayfabric/plugins/
```

A plugin MUST provide a signed or locally trusted manifest in future hardened deployments.

---

# 62. Plugin Manifest

Example:

```yaml
name: signal
version: 1.2.0
protocol_version: 1
executable: relayfabric-signal

permissions:
  network: true
  serial: false
  bluetooth: false

capabilities:
  text: true
  groups: true
  attachments: true
```

---

# 63. Plugin Sandboxing

Linux deployments SHOULD support sandboxing using:

* systemd hardening
* seccomp
* namespaces
* restricted filesystem access
* capability dropping

Possible future:

* WASI plugins
* containers
* Landlock

Plugins requiring hardware access can receive only required devices.

---

# 64. Deployment Profiles

## Edge gateway

```text
Raspberry Pi
│
├── switchyardd
├── RNode
├── Meshtastic radio
├── MeshCore radio
└── IP backhaul
```

---

## Backbone gateway

```text
Server / VM
│
├── switchyardd
├── Signal plugin
├── LXMF plugin
├── Nostr plugin
├── MQTT plugin
└── federation
```

---

## Hybrid site

```text
                    Raspberry Pi

                    switchyardd
                         │
          ┌──────────────┼──────────────┐
          │              │              │
       RNode       Meshtastic      MeshCore
          │              │              │
      Reticulum         LoRa            LoRa
                         │
                     Internet
                         │
                       Signal
```

---

# 65. Recommended DX.PE Topology

```text
                       DX.PE Backbone
                              │
                   RelayFabric Backbone
                              │
                ┌─────────────┼─────────────┐
                │             │             │
              Signal        Nostr         MQTT
                │
          BackboneInterface
                │
          Pasadena Gateway
                │
           switchyardd
          ┌─────┼─────┐
          │     │     │
        RNode  Mesh  Meshtastic
               Core
```

Other RelayFabric sites can connect to the same backbone.

---

# 66. Network Separation

Different radio protocols SHOULD use separate physical radios.

Do not attempt to operate:

```text
Reticulum
Meshtastic
MeshCore
```

through a single LoRa radio simultaneously unless specifically supported by hardware/firmware.

---

# 67. RF Considerations

Co-located transmitters SHOULD account for:

* antenna isolation
* receiver desensitization
* frequency separation
* filtering
* RF power
* duty cycle
* regulatory requirements

These are deployment concerns rather than RelayFabric protocol functionality.

---

# 68. Reliability

`switchyardd` MUST recover safely after restart.

At startup:

1. load configuration
2. open persistent state
3. recover pending deliveries
4. start plugin supervision
5. resume retry queues
6. begin ingress processing

No queued message should be silently lost due solely to daemon restart.

---

# 69. Plugin Supervision

Plugins SHOULD automatically restart after unexpected termination with bounded backoff.

Example:

```text
1s
5s
30s
2m
```

Repeated crashes SHOULD mark the plugin unhealthy.

---

# 70. Delivery Semantics

RelayFabric SHOULD distinguish:

```text
accepted
queued
sent
transport_acknowledged
destination_acknowledged
failed
```

Not every protocol supports every state.

The system SHALL NOT fabricate delivery guarantees absent from the underlying protocol.

---

# 71. Replies and Threads

Canonical messages SHOULD support:

```text
reply_to: message_id
```

Plugins capable of native replies SHOULD map this appropriately.

Otherwise the adapter may render:

```text
↳ reply to MESH-7F21:
Yes, received.
```

---

# 72. Attachments

Attachments SHOULD be represented separately from message bodies.

Metadata:

```text
id
mime_type
size
hash
filename
storage_ref
```

Policies control whether attachments may cross each route.

---

# 73. Attachment Storage

Attachments SHOULD be content-addressed.

Example:

```text
SHA-256
```

Large attachments MUST NOT automatically traverse constrained networks.

---

# 74. Location Privacy

Location information SHALL be treated as sensitive metadata.

Default policy SHOULD NOT automatically bridge precision location telemetry into public Internet networks.

Possible transformations:

```text
exact
rounded
region-only
strip
```

---

# 75. Presence

Presence SHALL be optional.

Cross-network presence can create powerful correlation information and MUST therefore be disabled by default.

---

# 76. Timestamps

Gateways SHOULD preserve source timestamps but MAY reduce timestamp precision when privacy policy requires.

Example:

```text
08:32:12.481
```

could become:

```text
08:32
```

to reduce cross-network correlation.

---

# 77. Authentication

Administrative authentication SHOULD support:

* Unix peer credentials
* local OS users/groups
* mTLS for remote control
* scoped API tokens

Future:

* hardware-backed credentials
* SSH certificates
* WebAuthn

---

# 78. Authorization

Administrative roles:

```text
viewer
operator
route-admin
identity-admin
security-admin
administrator
```

Routes may independently define message authorization policies.

---

# 79. Rate Limiting

Rate limits SHOULD be available by:

* plugin
* route
* endpoint
* sender
* pseudonym
* message type

Example:

```yaml
rate_limit:
  meshtastic:
    messages: 10
    per: 1m
```

---

# 80. Abuse Prevention

The gateway MUST protect Internet systems from uncontrolled radio-originated abuse.

For example, receiving a packet over Meshtastic MUST NOT automatically permit an unknown radio user to:

* message arbitrary Signal users
* publish arbitrary Nostr events
* send arbitrary emails
* trigger arbitrary webhooks

Destinations MUST be route-authorized.

---

# 81. Content Filtering

RelayFabric MAY support optional filters for:

* payload size
* message type
* binary data
* malformed Unicode
* dangerous commands
* known spam patterns

Content inspection SHALL be impossible in OPAQUE mode by design.

---

# 82. Message Provenance

Messages SHOULD maintain:

```json
{
  "origin_protocol": "meshtastic",
  "origin_gateway": "dxpe-pasadena",
  "fabric_hops": [
    "dxpe-pasadena",
    "dxpe-core"
  ]
}
```

Destination rendering MAY expose a privacy-safe subset.

---

# 83. User Presentation

Default bridged text SHOULD clearly indicate its network origin.

Example:

```text
[MESH-7F21]
Can anyone hear Pasadena?
```

or:

```text
[LXMF • RNS-A91C]
Pasadena node online.
```

Routes MAY customize formatting.

---

# 84. API Stability

RelayFabric SHALL version:

* plugin IPC
* canonical envelope
* administrative API
* federation protocol

Example:

```text
RelayFabric Plugin Protocol v1
```

Backward compatibility SHOULD be maintained within a major version.

---

# 85. Federation Protocol

A future RelayFabric-to-RelayFabric protocol SHOULD transmit canonical envelopes directly.

```text
switchyardd A
      │
 encrypted authenticated connection
      │
switchyardd B
```

This avoids unnecessary translation through another messaging protocol.

---

# 86. Federation Authentication

Federated nodes SHOULD authenticate using public-key identities.

Potential transports:

* QUIC + TLS
* Noise
* mTLS

Federation MUST NOT trust arbitrary peers by default.

---

# 87. Federation Policies

Operators SHOULD control:

```text
which routes may federate
which peers may receive them
whether identities are exposed
whether message content is permitted
maximum TTL
maximum hop count
```

---

# 88. Disconnected Operation

A remote RelayFabric node SHOULD continue serving local protocols when backbone connectivity disappears.

Example:

```text
Internet X

Meshtastic
    │
RelayFabric
    │
Reticulum LoRa
```

Local cross-protocol communication may continue even without Internet connectivity.

---

# 89. Administrative Web Interface

Not required for initial MVP.

A future UI could provide:

* topology
* route editor
* plugin health
* queue status
* message tracing
* RF status
* identity privacy controls
* federation peers

See `docs/webui-notes.md` for detailed WebUI design notes.

---

# 90. Message Trace

Operators SHOULD be able to inspect delivery state without necessarily viewing content.

Example:

```bash
switchyardctl trace 01K2RF...
```

Output:

```text
Ingress:
  meshtastic/pasadena
  08:32:12

Route:
  pasadena-general

Destinations:
  lxmf/pasadena       delivered
  signal/group42      delivered
  meshcore/general    queued

Privacy:
  pseudonymous

Security:
  translate
```

---

# 91. Development Repository Layout

Recommended:

```text
relayfabric/
│
├── Cargo.toml
├── crates/
│   ├── relay-core/
│   ├── relay-protocol/
│   ├── relay-policy/
│   ├── relay-storage/
│   ├── relay-ipc/
│   └── relay-sdk/
│
├── switchyardd/
├── switchyardctl/
│
├── plugins/
│   ├── lxmf/
│   ├── signal/
│   ├── meshtastic/
│   ├── meshcore/
│   ├── bitchat/
│   ├── nostr/
│   └── mqtt/
│
├── schemas/
├── examples/
├── packaging/
├── docs/
└── tests/
```

---

# 92. Plugin SDK

RelayFabric SHOULD ship an SDK containing:

* message types
* endpoint types
* IPC client
* capability definitions
* plugin lifecycle helpers
* test harness

SDKs may eventually exist for:

```text
Rust
Python
Go
TypeScript
```

---

# 93. Testing Strategy

## Unit tests

* routing
* policy
* aliases
* deduplication
* TTL
* queue behavior

## Plugin tests

Mock protocol endpoints.

## Integration tests

Examples:

```text
LXMF → Signal
Signal → LXMF
Meshtastic → LXMF
LXMF → Meshtastic
MeshCore → Signal
```

## Loop tests

Ensure:

```text
A → B → A
```

does not endlessly retransmit.

## Failure tests

* plugin crash
* database restart
* network partition
* radio disconnect
* malformed packet
* queue overflow

---

# 94. Security Testing

Required classes:

* fuzz plugin IPC
* fuzz message parsing
* malformed native metadata
* replay testing
* authorization bypass
* identity-link spoofing
* queue exhaustion
* message amplification
* plugin impersonation
* configuration injection
* secret leakage

---

# 95. Privacy Testing

Tests SHOULD verify:

* no phone numbers leak when disabled
* Signal UUID does not cross route
* native Meshtastic ID does not leak
* aliases differ across privacy scopes
* location is stripped as configured
* logs contain no message content by default
* unlink operations remove associations as intended

---

# 96. Performance Objectives

`switchyardd` itself SHOULD have minimal resource requirements.

Target idle deployment:

```text
Raspberry Pi Zero 2 W class:
possible for small deployments

Raspberry Pi 4/5:
recommended edge gateway

x86/ARM server:
backbone/federation
```

The core should be capable of substantially higher message throughput than radio networks require.

---

# 97. MVP

RelayFabric v0.1 SHOULD include:

### Core

* `switchyardd`
* canonical message envelope
* static YAML routes
* SQLite persistence
* deduplication
* loop prevention
* TTL
* retry queues
* DLQ
* pseudonymous aliases
* basic policy engine
* Prometheus metrics
* `switchyardctl`

### Plugins

1. LXMF
2. Signal
3. Meshtastic

This combination validates all three major transport classes:

```text
Reticulum
Internet messenger
LoRa mesh
```

---

# 98. v0.2

Add:

* MeshCore
* MQTT
* richer transforms
* identity verification/linking
* plugin SDK
* route-scoped secrets
* improved RF metrics

---

# 99. v0.3

Add:

* Bitchat
* Nostr
* gateway federation
* RelayFabric Discovery Protocol (RFDP, §111)
* Public Node Profile (§112): node identities, trust levels, public_services, quotas, airtime policy
* Sealed Routing phase 1 (§113): gateway-to-gateway sealed transit over Noise federation links
* signed RelayFabric envelopes
* origin signatures

---

# 100. v0.4

Add:

* OPAQUE messages
* application-level E2EE
* gateway attestations
* companion client/library
* stronger plugin sandboxing

---

# 101. v1.0 Criteria

RelayFabric SHOULD reach 1.0 when:

* plugin protocol is stable
* canonical envelope is stable
* migration strategy exists
* at least five production-quality protocol adapters exist
* federation is authenticated
* security documentation is complete
* privacy behavior is documented
* recovery from failures is tested
* upgrade compatibility is defined

---

# 102. Suggested Command-Line Interface

```bash
switchyardd
switchyardd --config /etc/relayfabric/relayfabric.yaml
switchyardd --check-config
switchyardd --foreground

switchyardctl status
switchyardctl routes
switchyardctl plugins
switchyardctl queue
switchyardctl queue retry <id>
switchyardctl queue purge
switchyardctl identities
switchyardctl trace <message-id>
switchyardctl reload
```

---

# 103. Service Naming

Systemd:

```text
switchyardd.service
```

Plugins:

```text
relayfabric-lxmf.service
relayfabric-signal.service
relayfabric-meshtastic.service
relayfabric-meshcore.service
```

or plugin lifecycle may be managed entirely by `switchyardd`.

---

# 104. Package Naming

Recommended:

```text
relayfabric
relayfabric-plugin-lxmf
relayfabric-plugin-signal
relayfabric-plugin-meshtastic
relayfabric-plugin-meshcore
relayfabric-plugin-bitchat
relayfabric-plugin-nostr
```

---

# 105. Terminology

**RelayFabric**
The complete project and architecture.

**Switchyard**
The routing concept inside RelayFabric.

**`switchyardd`**
The core daemon.

**Plugin**
Protocol-specific integration module.

**Backend**
Implementation used by a plugin to access its native network.

**Endpoint**
A protocol-specific source or destination.

**Route**
Policy-controlled relationship among endpoints.

**Fabric message**
Canonical RelayFabric message.

**Native identity**
Identity from an external network.

**Alias**
Privacy-preserving RelayFabric representation of a native identity.

**Gateway**
A running RelayFabric instance handling one or more networks.

**Federation**
Direct communication between RelayFabric gateways.

---

# 106. Core Security Statement

RelayFabric must never imply that protocol translation preserves native end-to-end encryption.

For normal translated traffic:

```text
Network A E2EE
       ↓
 RelayFabric
       ↓
Network B E2EE
```

RelayFabric is a trusted content endpoint.

Only RelayFabric OPAQUE mode or another application-level cryptographic mechanism can prevent the gateway from seeing message contents across the protocol boundary.

---

# 107. Core Privacy Statement

RelayFabric must not silently transform protocol interoperability into identity federation.

A user who communicates as:

```text
!abcd1234
```

on Meshtastic should not automatically be exposed as:

```text
alice.42
```

on Signal.

Default behavior is route-scoped pseudonymity.

Explicit verified linking may override this policy.

---

# 108. Core Operational Statement

RelayFabric should function equally well as:

```text
small Raspberry Pi radio bridge
```

and:

```text
multi-protocol regional communications backbone
```

The same core routing model should apply to both.

---

# 109. Example Pasadena Deployment

```text
                       DX.PE Backbone
                              │
                    ┌─────────┴─────────┐
                    │                   │
              RelayFabric Core      Internet
                 switchyardd             │
                    │                  Signal
                    │
              BackboneInterface
                    │
             Pasadena RF Site
                    │
              Raspberry Pi 5
                    │
               switchyardd
          ┌─────────┼─────────┐
          │         │         │
        RNode    MeshCore  Meshtastic
          │         │         │
       915 MHz   915 MHz    915 MHz
          │         │         │
       RNS users MeshCore  Meshtastic
                   users      users
```

Traffic can be selectively routed:

```text
Meshtastic ↔ Reticulum
MeshCore   ↔ Reticulum
Signal     ↔ Reticulum
Signal     ↔ MeshCore
Signal     ↔ Meshtastic
```

without requiring any protocol to become the RelayFabric internal transport.

---

# 110. Final Architectural Summary

RelayFabric consists of five principal layers:

```text
┌──────────────────────────────────────────────┐
│ 5. Native Networks                          │
│ Signal / LXMF / MeshCore / Meshtastic / ... │
├──────────────────────────────────────────────┤
│ 4. Protocol Plugins                         │
├──────────────────────────────────────────────┤
│ 3. Canonical Message + Identity Model       │
├──────────────────────────────────────────────┤
│ 2. Routing / Policy / Security / Queueing   │
├──────────────────────────────────────────────┤
│ 1. switchyardd                              │
└──────────────────────────────────────────────┘
```

The fundamental model is:

```text
       Native Network A
              │
              ▼
            Plugin
              │
              ▼
      Canonical Envelope
              │
              ▼
     Policy + Switchyard
              │
              ▼
     Queue + Transformation
              │
              ▼
            Plugin
              │
              ▼
       Native Network B
```

RelayFabric therefore becomes a general-purpose communications interoperability layer capable of spanning:

```text
Internet
LoRa
Reticulum
BLE
local networks
store-and-forward systems
decentralized networks
traditional messaging platforms
```

while maintaining explicit policy, provenance, privacy boundaries, and security semantics.

The defining design principle is:

> **RelayFabric routes communications across networks while preserving the separation of identities, trust domains, and protocol security boundaries by default.**

---

# 111. RelayFabric Discovery Protocol (RFDP)

*Added 2026-08-15 as a first-class future component, pairing with federation (§30, §85–87). Target: groundwork alongside federation (v0.3).*

`switchyardd` SHOULD advertise what protocols and services it supports — but discovery MUST be **capability-based, scoped, and optional**, never a broadcast of full inventory.

## 111.1 Node Advertisement

The useful advertisement describes what this particular gateway can actually do, not merely which protocols it links. A **RelayFabric Node Advertisement** is a signed, expiring capability document:

```json
{
  "rf_version": 1,
  "node_id": "rf:75bc...",
  "name": "DX.PE Pasadena",

  "services": {
    "chat": true,
    "store_forward": true,
    "telemetry": true
  },

  "protocols": {
    "lxmf":       { "rx": true, "tx": true, "text": true, "files": true },
    "meshtastic": { "rx": true, "tx": true, "text": true, "location": true, "max_payload": 237 },
    "signal":     { "rx": true, "tx": true, "groups": true, "attachments": true }
  },

  "security": {
    "translate": true,
    "signed": true,
    "opaque": false
  },

  "expires": 1786838400
}
```

Advertisements SHALL be signed (Ed25519) by the RelayFabric node identity so peers can verify that a capability announcement genuinely came from the advertising node rather than being spoofed.

## 111.2 Services above protocols

Nodes advertise **services** (chat, emergency-messaging, store-and-forward, telemetry, git, …); protocols describe *how those services are reachable*:

```text
DX.PE Pasadena
│
├── chat
│    ├── LXMF
│    ├── Meshtastic
│    └── Signal
│
├── telemetry
│    ├── Meshtastic
│    └── MQTT
│
└── git
     └── rngit / Reticulum
```

Another node can then ask "can you deliver chat toward Signal?" without caring how the gateway is implemented.

## 111.3 Reachability

Protocol support alone does not imply route availability. Advertisements SHOULD express reachable service classes:

```yaml
reachability:
  chat:
    via: [lxmf, meshtastic, signal]
  telemetry:
    via: [meshtastic, mqtt]
```

This enables service-layer intermesh routing: a gateway needing Signal delivery discovers a peer advertising `signal/chat available` and routes through it — without knowing the Signal account behind it.

Discovery SHALL NOT initially advertise full route tables (A→B→C→Signal chains). Scope stays limited to node capabilities + directly attached protocols + available services; federation calculates reachable paths.

## 111.4 What MUST NOT be advertised

Discovery leaks infrastructure information. Advertisements SHALL NOT include:

```text
Signal usernames / phone numbers
Meshtastic node IDs
LXMF user identities
local device paths
IP addresses / VPN topology
exact GPS coordinates
identity mappings
private route names
```

A public advertisement is limited to protocol families, service classes, and supported security modes.

## 111.5 Discovery scopes

```yaml
discovery:
  mode: federation
```

| Mode | Behavior |
|---|---|
| `disabled` | advertise nothing (sensitive gateways) |
| `local` | local RelayFabric peers only (LAN / local RNS neighborhood) |
| `federation` | authenticated RelayFabric peers only — **recommended default** |
| `public` | deliberately limited service advertisement for community gateways |

## 111.6 Cost metrics (later)

Advertisements MAY later carry broad, coarse cost classes (`bandwidth_class`, `latency_class`, `metered`, `reliability`, `store_forward`) so policy can prefer e.g. direct IP over LoRa over satellite. Exact bandwidth/latency measurements are deliberately excluded initially.

## 111.7 Architecture

```text
              RelayFabric Node Advertisement
                         │
              signed capability document
                         │
           ┌─────────────┼─────────────┐
           │             │             │
       Protocols      Services      Security
```

Signed advertisements flowing between `switchyardd` peers give the decentralized intermesh **service discovery without a central directory**.

---

# 112. Public Node Profile

*Added 2026-08-15. Pairs with RFDP (§111) and federation (§30, §85–87). Target: profile definition alongside v0.3 federation; quotas build on §45/§79.*

Public-node operation SHALL be a first-class RelayFabric deployment mode — but a **public federation node** is not a **public open relay**. The first is desirable. The second is an abuse magnet.

"Public" means: *other RelayFabric nodes and users may discover and use explicitly published services* — never "any anonymous person can route anything anywhere."

## 112.1 Public-node roles

A node MAY provide one or several of:

| Role | Provides |
|---|---|
| **Public federation node** | accepts authenticated RelayFabric peers; carries allowed intermesh traffic |
| **Public access node** | exposes selected local services (Reticulum, Meshtastic, MeshCore access) |
| **Public gateway node** | controlled crossing into another network (Signal, Nostr, MQTT, Matrix, APRS) |

## 112.2 Public discovery

```yaml
node:
  name: "DX.PE Pasadena"
  public: true

discovery:
  mode: public
```

publishes a signed, expiring RFDP advertisement describing **capabilities, not sensitive infrastructure**:

```yaml
node_id: rf:7fa219...
name: DX.PE Pasadena
services:
  chat: true
  store_forward: true
  federation: true
protocols:
  lxmf:       { ingress: true,  egress: true }
  meshtastic: { ingress: true,  egress: true }
  signal:     { ingress: false, egress: true }
privacy:
  identities: pseudonymous
security:
  translate: true
  signed: true
```

It SHALL NOT reveal: Signal accounts, phone numbers, internal IPs, RNode addresses, VPN topology, or identity mappings (§111.4 applies).

## 112.3 Explicit published services

**Plugin available ≠ publicly routable.** An operator must not be able to accidentally turn on Signal and thereby create a public Signal relay. Public exposure requires an explicit `public_services` entry:

```yaml
public_services:
  - name: regional-chat
    type: chat
    ingress: [lxmf, meshtastic, meshcore]
    egress:  [lxmf, meshtastic, meshcore]
    identity_mode: pseudonymous
```

A plugin that is `enabled: true` but absent from `public_services` remains private.

## 112.4 No unrestricted forwarding

Public routes SHALL terminate at specific permitted destinations:

```text
Meshtastic Pasadena → RelayFabric → Signal group "Pasadena Emergency"     ✔
Meshtastic          → RelayFabric → ANY Signal user                       ✘
public radio        → RelayFabric → SMTP open relay                      ✘
```

This extends §38 and §80 to the public profile.

## 112.5 Federation as the scalable public mechanism

Nodes advertise services; peers learn *what is reachable through whom* without learning credentials:

```text
Pasadena learns: "Signal chat reachable via Phoenix"
              — without learning Phoenix's Signal account.
```

Cross-fabric delivery (`Meshtastic user → Pasadena → federation → Phoenix → Signal community`) is the beginning of the intermesh.

## 112.6 Node identities

Every `switchyardd` instance SHALL generate a cryptographic node identity (Ed25519) on first startup under `/var/lib/relayfabric/identity/`, presented as `rf:<hex>`. It signs: discovery advertisements, federation handshakes, route advertisements, gateway attestations (§33). Trust policies bind to identities, not IP addresses:

```yaml
federation:
  allow: [rf:a73c91..., rf:bb2107...]   # or: trust: community
```

## 112.7 Trust levels

```text
UNKNOWN → SEEN → VERIFIED → TRUSTED    (and BLOCKED)
```

A newly discovered node might be allowed basic chat but not administrative commands, identity linking, large files, or expensive gateways until trusted. **Discovery must never automatically become trust.**

## 112.8 Quotas (built into switchyardd, not left to plugins)

```yaml
limits:
  per_sender: { messages_per_minute: 10, bytes_per_hour: 50000 }
  per_route:  { queue_max: 5000 }
  global:     { queue_max: 100000, cas_max_bytes: 2000000000 }

transport_budgets:
  mqtt: { messages_per_minute: 500 }
  lxmf: { messages_per_minute: 200 }
```

`limits` and `transport_budgets` are siblings at the top of the config, not nested inside each other. Every `limits` field defaults to 0, meaning unlimited — a node MAY ship with no quotas configured at all, but if `node.public` is true and both `per_sender` and `global` are left at 0, `switchyardd` logs a startup warning (unlimited on a public node is allowed, not silently assumed safe). `transport_budgets` keys must name enabled plugins; a configured budget of 0 is rejected at load rather than silently meaning unlimited, so omit the entry instead. These ship in v0.1+ config (`switchyardd`'s `Config::limits` / `Config::transport_budgets`).

Transport classes carry different budgets: Reticulum/IP generous, LoRa constrained, Signal controlled, satellite extremely restricted (extends §45, §46, §79).

## 112.9 Radio airtime policy

Hundreds of Internet users MUST NOT be able to saturate one 915 MHz channel. Public RF nodes treat airtime as a scarce resource, with queue scheduling:

```text
emergency → local radio → federated traffic → bulk/background
```

under hard airtime/rate budgets (extends §39).

## 112.10 Store-and-forward

A public node MAY advertise `store_forward: { enabled: true, max_ttl: 24h }` — queueing for currently-unreachable destinations (mobile Reticulum/LoRa users) per §40–44.

## 112.11 Public privacy defaults

Public mode SHALL ship:

```yaml
privacy:
  identity_mode: pseudonymous
  aliases: route_scoped
  expose_native_identifiers: false
  expose_location: false
logging:
  content: false
  identifiers: hmac
```

A public operator must not accidentally create a correlation database.

## 112.12 Operator experience (future)

The WebUI (§89) should surface public operation as checkboxes (services published, federation peers by trust level, RF queue depth), and CLI init should make a community node buildable without RelayFabric expertise:

```bash
switchyardctl node init
switchyardctl plugin enable lxmf
switchyardctl plugin enable meshtastic
switchyardctl public enable     # wizard: name, services, identity exposure
```

## 112.13 The larger model

Communities contribute whatever connectivity they have — one node brings Reticulum + LoRa, another MeshCore + fiber, another Meshtastic + Nostr, another satellite + Reticulum. RelayFabric doesn't require everyone to deploy the same network; **people contribute capabilities rather than joining one monolithic system.** The Public Node Profile exists so that doing this is safe by default: discovery, federation, pseudonymity, quotas, RF airtime, store-and-forward, and service publishing all ship with safe defaults.

---

# 113. Sealed Routing (zero-knowledge payload routing)

*Added 2026-08-15. Deepens §31's OPAQUE mode (renamed SEALED), §32 (RelayEnvelope), §106–107. Staged: gateway-to-gateway with v0.3 federation; user-to-user with the v0.4 companion client; groups/PQ/metadata hardening v0.5+.*

A cross-network gateway is otherwise a surveillance and compromise point by design. Sealed routing makes RelayFabric infrastructure **mathematically unable to read message payloads** it transports:

```text
Alice → encrypt for Bob → [ sealed envelope: opaque dest, ciphertext, auth, expiry ]
      → any transports → switchyardd nodes (ciphertext only) → Bob → decrypt
```

`switchyardd` answers only *"where does this ciphertext go?"* — never *"what does it say?"*

## 113.1 Naming and modes

§31's three modes are renamed for configuration clarity; semantics unchanged:

| Mode (config) | Was | Privacy | Compatibility |
|---|---|---|---|
| `native` | (per-protocol bridge) | low–medium | excellent |
| `gateway` | TRANSLATE | medium — gateway reads plaintext | excellent |
| `sealed` | OPAQUE | excellent — infrastructure cannot read content | requires RelayFabric-aware endpoints |

All three are supported; their security characteristics MUST be explicit to operators and users (§4.4).

## 113.2 Downgrade refusal

Routes and nodes MAY pin a floor; a sealed message MUST NOT be silently decrypted into a `gateway` leg:

```yaml
privacy:
  minimum_security: sealed
  allow_gateway_decryption: false
  allow_protocol_downgrade: false
```

Policy enforcement: a route whose effective mode falls below the floor is rejected at `--check-config`,
and a sealed envelope arriving at a route that would require decryption is dead-lettered
(`SECURITY_DOWNGRADE_REFUSED`), never translated.

## 113.3 The honest limitation: legacy edges

Traffic originating from an unmodified native client (Signal, Sideband, Meshtastic…) is plaintext at
its ingress gateway — unavoidably. Sealed mode therefore protects, in adoption order:

1. **Gateway-to-gateway (v0.3, with federation):** the origin edge gateway encrypts to the destination
   edge gateway; every intermediate/public transit node carries ciphertext only. Requires ZERO client
   adoption and transforms the public-node operator posture: *"the node transports encrypted envelopes
   it cannot decrypt."* Keys anchor to §112.6 node identities; federation links use Noise (§86) with
   periodic rekey; envelopes use AEAD (XChaCha20-Poly1305 class) with an algorithm-tagged key-agreement
   field for future PQ-hybrid agility.
2. **User-to-user (v0.4, companion client/library):** X3DH/PQXDH-style asynchronous prekeys
   (store-and-forward-compatible; prekey distribution is a propagation-node-like role) + Double Ratchet
   for forward secrecy and post-compromise security; sealed sender (intermediaries receive no
   conventional sender identity); ephemeral rotating routing identifiers derived from a long-term
   identity.
3. **Groups (v0.5+):** MLS rather than an invented group ratchet. PQ-hybrid key establishment (ML-KEM)
   and metadata hardening (padding, batching, delayed forwarding, cover traffic, onion-style
   forwarding, rendezvous points) also land here.

## 113.4 Sealed routing trades away in-transit transformation

A sealed payload CANNOT be transformed by the fabric: no image downscaling, no truncation to
`max_payload`, no attachment stripping, no drop-notes (§17; §81's content-inspection impossibility
applies to ALL content operations). Consequences, stated plainly:

- Capability-aware degradation happens at the ORIGIN edge or not at all — destination capability
  information must flow end-to-end before send, and oversized sealed payloads for constrained
  transports are rejected at origin, not shrunk in transit.
- Content filtering, spam heuristics, and body-dependent policy are unavailable on sealed legs by
  design; policy operates on envelope metadata only.

## 113.5 Interactions with fabric machinery

- Dedup and replay protection key on the envelope's unique message ID + expiry (not sender) — sealed
  and ephemeral-sender traffic remain replay-protected.
- Per-sender quotas key on the presented (possibly ephemeral) routing identity per epoch; rotation
  bounds correlation, quotas still bind within an epoch.
- Delivery receipts on sealed routes leak liveness metadata and are opt-in.

## 113.6 Claim discipline

This is **zero-knowledge payload routing / blind E2EE routing** — not traffic anonymity. Nodes still
observe timing, sizes, interfaces, addresses, and RF activity (§34's traffic-analysis statement
stands). RelayFabric SHALL NOT describe sealed mode as anonymity.

> **RelayFabric nodes should know only what they need to forward traffic, and no more.**
