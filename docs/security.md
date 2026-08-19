# Security & Sealed Routing

RelayFabric gateways sit at the seam between networks that were never meant to talk to each other, which makes every gateway a potential surveillance and compromise point by design. This page covers the three content-security modes a route can run under, the universal secure envelope and gateway attestation model that backs them, the threat model RelayFabric explicitly addresses (and the one it explicitly does not solve), and **sealed routing** — Phase 1's gateway-to-gateway blind payload encryption ([SPEC §113](SPEC.md)). It closes with the admin API's access-control model, which is filesystem-only and has no daemon-level authentication.

## Security modes

Every route runs under one of three content-security modes (SPEC §31). They differ in what the gateway itself can see and do to the payload as it transits — not in what a destination-side recipient sees, which is the separate identity-presentation question covered in [Identity & Privacy](identity.md).

| Mode (config `security_mode`) | SPEC §31 name | Gateway sees | Gateway can modify/drop/replay/inject | Compatibility |
|---|---|---|---|---|
| `gateway` (default) | TRANSLATE | Full plaintext | Yes — this is a trusted-gateway mode, by design | Excellent — any endpoint |
| *(envelope-level; not yet a route `security_mode` value)* | SIGNED | Full plaintext | Can drop, but cannot silently alter content without invalidating the origin signature | Good — needs a signature-aware destination |
| `sealed` | SEALED (was OPAQUE) | Ciphertext only, plus required routing metadata | No — cannot read, so cannot selectively modify | Requires RelayFabric-aware endpoints |

SPEC §113.1's config-naming table adds a fourth, lower-privacy entry — `native` (a direct per-protocol bridge, no fabric-level content control at all: low–medium privacy, excellent compatibility) — for completeness alongside the `gateway`/`sealed` renaming of TRANSLATE/OPAQUE; it isn't one of the three original §31 modes and isn't discussed further on this page.

### TRANSLATE / `gateway`

```text
Network A encryption
       ↓
     gateway
    plaintext
       ↓
Network B encryption
```

Maximum compatibility, minimum confidentiality: this is the default mode, and it must be documented as a trusted-gateway mode. The gateway can read, modify, drop, replay, or inject messages, because it decrypts Network A's transport and re-encrypts for Network B — that's what "translate between two protocols" means. Every existing plugin bridge (Reticulum/LXMF, Signal, Meshtastic, Nostr, …) runs in this mode today.

### SIGNED

```text
sender
  ↓ sign
message
  ↓
gateway
  ↓
destination verifies
```

Content stays visible to the gateway, but it carries an origin signature the destination can verify. This protects integrity and provenance when the destination software understands RelayFabric signatures: a gateway can still drop a signed message, but it cannot silently alter it without invalidating the signature. SIGNED is part of the [Universal Secure Envelope](#universal-secure-envelope) model (`origin_signature`, `gateway_attestations[]`) rather than a `RouteConfig.security_mode` value in the current implementation — the two shipped, configurable modes are `gateway` and `sealed`.

### SEALED (was OPAQUE) / `sealed`

```text
sender
  │ encrypt
  ▼
ciphertext
  │
Network A → Gateway → Network B
  │
recipient
  ▼
decrypt
```

The application-level payload stays encrypted across every gateway it transits; the gateway sees only the routing metadata it needs to forward the envelope. This mode requires RelayFabric-aware endpoints — it cannot bridge to an unmodified native client. See [Sealed routing (Phase 1)](#sealed-routing-phase-1-113) below for how this is actually implemented today.

## Universal Secure Envelope

SPEC §32 defines the fields a fully SIGNED/SEALED envelope should carry, as the general target shape:

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

This is the general-purpose shape the spec describes; what Phase 1 sealed routing actually ships is a narrower, concrete wire format for one leg of it — the `SealedEnvelope` described below — not the full `RelayEnvelope` with an open-ended attestation chain.

## Gateway attestation

SPEC §33: each participating gateway *may* append an attestation as an envelope transits it.

```text
Origin signature
       ↓
Gateway A attestation
       ↓
Gateway B attestation
       ↓
Destination
```

Chained attestations create a verifiable transit history without requiring every gateway on the path to be trusted for authorship — a destination can check who touched an envelope and in what order, even for gateways it has no independent relationship with. This is the model that federation's Noise-authenticated links and signed envelopes build on: gateway-to-gateway traffic between `switchyardd` nodes carries signed attestation as it crosses each federation peer.

## Threat model

SPEC §34 requires RelayFabric to state explicitly what it defends against — and, just as importantly, what it does not. Four actors are named explicitly; the first two are the ones this page is primarily about, since sealed routing and the admin API's access-control model exist because of them.

### Malicious gateway operator

May attempt to: read messages, correlate identities, modify messages, inject messages, suppress messages.

Mitigations: SEALED mode, signatures, minimal logging, route-scoped pseudonyms, audit trails.

None of these mitigations assume the operator is benign — SEALED mode in particular is built on the premise that the operator's own infrastructure should be *mathematically unable* to read payloads, not merely asked not to.

### Compromised gateway

Mitigations: process isolation, least privilege, plugin sandboxing, encrypted storage, limited network access, signed configurations, secrets separation.

This is why plugins run as separate, supervised processes speaking a small CBOR-over-Unix-socket protocol to the daemon rather than linking directly into it — a compromised or crashing plugin cannot read the daemon's memory or take the fabric down with it.

### Malicious radio participant

May attempt: flooding, replay, spoofing, malformed packets, resource exhaustion — the concerns of an untrusted party with radio access to a mesh, not administrative access to a gateway.

Mitigations: ACLs, rate limits, message-size limits, signature verification, replay protection, resource quotas.

### Traffic analysis

Even SEALED mode exposes some metadata: timing, message size, gateway involvement, and some routing information. **RelayFabric shall not claim to defeat global traffic analysis.** This is the same limitation restated, in the specific context of sealed routing, in the claim-discipline warning below — it isn't a gap unique to Phase 1's implementation, it's a limit inherent to what payload-only encryption can ever hide.

**In short:** RelayFabric defends message *content and integrity* against a gateway operator or a compromised gateway process, using SEALED mode, signatures, sandboxing, and least privilege. It does not defend, and does not claim to defend, against an operator or observer who only ever looks at *metadata* — who talked to whom, when, and how much.

## Sealed routing (Phase 1, §113)

A cross-network gateway is otherwise a surveillance and compromise point by design. Sealed routing makes `switchyardd` infrastructure **mathematically unable to read the message payloads it transports**:

```text
Alice → encrypt for Bob → [ sealed envelope: opaque dest, ciphertext, auth, expiry ]
      → any transports → switchyardd nodes (ciphertext only) → Bob → decrypt
```

`switchyardd` answers only *"where does this ciphertext go?"* — never *"what does it say?"*

Phase 1 covers the first of §113.3's three staged legs: **gateway-to-gateway**, shipped with federation. The origin edge gateway encrypts to the destination edge gateway; every intermediate/public transit node between them carries ciphertext only. This requires zero client adoption. User-to-user sealing (X3DH/PQXDH + Double Ratchet, sealed sender) and MLS-based groups with metadata hardening are later phases, not yet built.

### Per-node sealed key

Every node generates a static X25519 keypair on first use, persisted at `data_dir/sealed.key` (mode `0600`, alongside the same `data_dir` that hosts the admin socket — see [Admin API access control](#admin-api-access-control)). The public half is published in the node's RFDP advertisement (`security.sealed_key`, 64 hex characters) and is covered by the advert's own Ed25519 signature, so a peer trusts a node's sealed key because the advert is signed by the node it claims to be — it cannot be spoofed by another peer. A route's destination peer's sealed key can also be pinned explicitly in config (`federation.peers[].sealed_key`), which overrides or complements the advert-learned value.

### `SealedEnvelope`

The wire format for one sealed leg, built with `crypto_box::ChaChaBox` — X25519 key agreement plus XChaCha20-Poly1305 AEAD, algorithm-tagged for future post-quantum agility:

```rust
struct SealedEnvelope {
    alg: String,       // "x25519-xchacha20poly1305-v1" today; unrecognized alg -> reject, never fall back
    id: String,         // the envelope's message ID; bound inside the ciphertext too
    expires_at: i64,    // also bound inside the ciphertext
    epk: [u8; 32],      // per-message ephemeral X25519 public key
    nonce: [u8; 24],    // XChaCha20 nonce
    ct: Vec<u8>,        // ChaChaBox ciphertext of the already-signed canonical envelope
}
```

Sealing generates a fresh ephemeral X25519 keypair per message and runs `ChaChaBox(ephemeral_sk, recipient_sealed_pub)` against the recipient's published sealed key — the sender's own long-term identity never appears in the sealed payload itself. Unsealing runs the box against the node's own `sealed.key` secret, then checks that the `id` and `expires_at` bound inside the plaintext match the outer envelope fields before accepting it; any mismatch, unsupported `alg`, or authentication failure is a rejection, never a best-effort decrypt.

### Configuring it: `security_mode` and the privacy floor

Each route selects its mode; a node can additionally pin a hard floor:

```yaml
routes:
  - name: cross-site
    security_mode: sealed   # gateway (default) | sealed
```

```yaml
privacy:
  minimum_security: sealed
  allow_gateway_decryption: false
  allow_protocol_downgrade: false
```

A route's own `security_mode: sealed` is **best-effort only** — an operator can edit that same route back to `security_mode: gateway` in place, and the edit reloads cleanly. `privacy.minimum_security` is the hard, reload-enforced guarantee: `--check-config` rejects any route whose effective mode falls below the node's floor, rather than allowing it to load and silently run downgraded. `sealed` also requires every destination to be a `fed:<peer>` peer with a resolvable sealed key (config-pinned or advert-learned) — `--check-config` rejects a `sealed` route to anything else, including a local plaintext plugin.

### Downgrade refusal (§113.2)

A sealed message must never be silently decrypted onto a route that isn't prepared to terminate it. Enforcement happens at two points:

- **Config-check time:** `--check-config` rejects any route whose effective `security_mode` sits below the node's `privacy.minimum_security` floor, and rejects a `sealed` route with no resolvable peer sealed key.
- **Runtime ingress:** `privacy.allow_gateway_decryption` (default `true`, overridable per route) gates whether a route will terminate sealed traffic into plaintext at all. When it's `false`, a sealed inbound envelope aimed at that route is dead-lettered `SECURITY_DOWNGRADE_REFUSED` — never translated.

`allow_protocol_downgrade` is parsed and stored but is not yet a separate enforcement point in Phase 1; `allow_gateway_decryption` is the actual downgrade-refusal gate today, documented as such rather than left to look enforced when it isn't.

### §113.4 — no in-transit transformation

A sealed payload cannot be transformed by the fabric at all: no image downscaling, no truncation to a route's `max_chars`, no attachment stripping, no drop-notes. This follows directly from the fabric being unable to read the content — a transform it can't inspect, it can't safely apply. The consequence is stated plainly:

- Capability- and transport-aware degradation happens at the **origin edge**, before sealing, or not at all — destination capability information has to flow end-to-end before send.
- An oversized sealed payload for a constrained destination transport is **rejected at origin** (`SEALED_OVERSIZE`), never shrunk in transit. This is a structural exemption, not an in-line guard: sealed egress dispatches through a separate code path that never reaches transport-policy resolution in the first place, so there's no shared transform step to accidentally apply.
- Content filtering, spam heuristics, and any body-dependent policy are unavailable on sealed legs by design; policy on a sealed route can only act on envelope metadata.

Other Phase-1 sealed-ingress rejection reasons — unsupported algorithm, expired envelope, failed authentication (wrong recipient or tampered ciphertext), missing peer key — are visible on the `relayfabric_sealed_egress_total`, `relayfabric_sealed_ingress_total`, and `relayfabric_sealed_rejected_total` counters (`GET /metrics`); none of these rejections are persisted to `/v1/queue?state=dead_letter`, since writing a just-decrypted refusal into a queryable table would make the refusal cosmetic rather than real.

| Reason | When |
|---|---|
| `SEALED_OVERSIZE` | Sealed payload exceeds a constrained destination transport's cap — rejected at origin, never shrunk |
| `SECURITY_DOWNGRADE_REFUSED` | Sealed inbound aimed at a route with `allow_gateway_decryption: false` |
| `NO_SEALED_KEY` | Egress route has no resolvable peer sealed key (config-pinned or advert-learned) |
| unsupported algorithm / bad seal | Ingress envelope's `alg` isn't recognized, or authentication fails (wrong recipient, tampered ciphertext) |
| expired | Ingress envelope's `expires_at` has passed |

### §113.5 — interactions with fabric machinery

Sealed traffic still has to play by the fabric's existing dedup, quota, and receipt rules — with adjustments where "who sent this" is deliberately less available:

- **Dedup and replay protection** key on the envelope's unique message ID and expiry, not on sender — sealed and ephemeral-sender traffic stays replay-protected without needing a stable sender identity.
- **Per-sender quotas** key on the presented (possibly ephemeral) routing identity per epoch; rotating that identity bounds how far quota state can be correlated, while quotas still bind meaningfully within a single epoch.
- **Delivery receipts** on sealed routes leak liveness metadata (that *someone* received *something*, at a given time) and are opt-in rather than automatic.

!!! danger "Sealed routing is zero-knowledge payload routing — not anonymity"
    This is the single most important claim-discipline point in this document (SPEC §113.6). Sealed routing makes `switchyardd` infrastructure unable to read message **content** as it moves gateway-to-gateway. It does **not** provide traffic anonymity:

    - Every node still observes **timing**, **message size**, **which interfaces and addresses are involved**, and RF activity where applicable.
    - "Who talks to whom, when, and roughly how much" is metadata, not payload — sealed routing was never designed to hide it, and nothing in this API, `switchyardctl`, or any future WebUI may describe sealed mode as anonymous, hidden, or untraceable.
    - The correct description is **payload confidentiality between the origin and destination edge gateways** — full stop.

    > RelayFabric nodes should know only what they need to forward traffic, and no more.

## Admin API access control

The `switchyardd` admin API (`switchyardctl`, `GET /v1/status`, config replace/rollback, identity linking, and every other route documented in [API Reference](api-reference.md)) is served **only** over a Unix domain socket — there is no TCP listener, and none is planned for `switchyardd` itself.

!!! danger "There is no daemon-layer authentication or authorization"
    This is a deliberate, not-yet-filled gap, stated plainly rather than implying a protection that doesn't exist:

    - Access control is entirely the OS filesystem's. The admin socket lives inside `data_dir`, which `switchyardd` creates — and tightens, if it already exists with looser permissions — to mode `0700`. A `0700` directory cannot even be traversed by another UID, so **any process running as the same UID as the daemon has full admin access**, including config replace/rollback and identity linking, and `root` always does regardless of UID. There is no per-route, no per-user, and no read-only tier: reaching the socket at all is equivalent to full admin.
    - As defense-in-depth on that same same-UID boundary — not a new one — `admin.sock` and the per-plugin sockets are also explicitly locked to mode `0600` right after `bind()` (a plugin socket opens to `0666` only when its `peer_uid` is configured, where the `SO_PEERCRED` check is the real gate), since `bind()` alone leaves a socket file's mode umask-derived rather than tightened. This protects against the parent directory's permissions being loosened by mistake; it adds no authentication.
    - `switchyardd` binds no network listener by default. Nothing here is reachable over a network unless an operator deliberately exposes it — an SSH tunnel, a `socat` forward, a reverse proxy — and doing so without adding an auth layer in front of it extends the same-UID trust boundary to whoever can reach that new listener.
    - `GET /docs` (the interactive Swagger UI) inherits exactly this same socket boundary and adds nothing of its own: no login screen, no session, no separate permission check.
    - **Real authentication and authorization — TLS, WebAuthn/passkeys, RBAC, session expiration, audit logging, and role separation that keeps identity-linking permissions apart from route-management permissions — is explicitly the job of the separate `relayfabric-ui` service, fronting this socket. `relayfabric-ui` exists (v0.2) but has no authentication yet — WebAuthn/passkeys + scoped roles land in v0.4 cycle E.** Until then, do not expose this admin socket or the UI's TCP listener to anyone you wouldn't give a shell on this host.

The `sealed.key` file described above lives in the same `data_dir`, under the same `0700` protection — compromising admin-socket-level access also exposes the node's sealed private key, which is one reason the same-UID boundary matters even for a daemon that otherwise "only" routes ciphertext.

The OpenAPI document's own `info.description` states this same boundary and deliberately declares no `securityScheme` — inventing a bearer/OAuth scheme the daemon doesn't implement would mislead client generators into thinking one exists. Two related guarantees the API does keep, independent of the authentication gap: `GET /v1/config` always returns secret *references* (`${env:...}`) rather than a resolved value, and no handler ever echoes a resolved secret or an identity-link verification code back to a caller.

## Where this fits

- [Identity & Privacy](identity.md) — the three sender-presentation modes and route-scoped pseudonyms, which govern what a *recipient* sees and are orthogonal to (and combinable with) the content-security modes on this page, which govern what the *gateway* sees.
- [Federation & Discovery](federation.md) — the Noise-authenticated links, signed attestation chains, and RFDP adverts (including the `sealed_key` field) that sealed routing's gateway-to-gateway leg rides on.
- [Operations](operations.md) — running `switchyardd`, `--check-config`, and the admin surfaces referenced above day to day.
