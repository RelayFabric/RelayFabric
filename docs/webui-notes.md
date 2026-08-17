# RelayFabric WebUI — Design Notes

Status: future work (v0.3 in staging plan). The administrative API is designed
for the WebUI from day one, even while the only client is `switchyardctl`.

## Architecture

The WebUI is NOT part of `switchyardd`. The daemon stays headless; a separate
service fronts it:

```text
Browser
   │ HTTPS
relayfabric-ui        (React/TypeScript or Svelte)
   │ authenticated API
switchyardd           (Rust, REST/WebSocket over Unix socket)
```

Contract: the UI never touches SQLite, never manages plugins, never shells
into `switchyardd`. One source of truth: UI → authenticated API → daemon.

## Feature focus (the things painful in YAML)

* visual route creation/editing, with per-edge controls (identity mode,
  security mode, max size, location handling, TTL)
* plugin status, health, and capabilities (feeds the route editor)
* queue / DLQ inspection
* gateway topology map (green/yellow/red/gray node health)
* federation peers
* identity/privacy mappings
* policy configuration
* radio dashboard (frequency, SF, bandwidth, TX power, RSSI, SNR, RF peers)
* message tracing (ID, size, source, destination, transforms, timing,
  delivery status — no content when content logging is disabled)
* logs, metrics, configuration validation

## Security boundary visibility

The UI must make trust boundaries visually obvious — show that a route's
`security_mode: gateway` (SPEC §113.1's renamed `TRANSLATE`, the default)
means the gateway reads plaintext, and `security_mode: sealed` (renamed
`OPAQUE`) means ciphertext-only transit: the origin edge AEAD-seals the
payload for the destination edge's key, and every intermediate node —
including this one, for traffic it merely relays — carries opaque ciphertext
it cannot read. This prevents operators from misunderstanding what the
bridge guarantees.

**Claim discipline (SPEC §113.6 — MUST be honored in every UI string):**
sealed mode is **zero-knowledge / blind payload routing, NOT anonymity** —
nodes still observe timing, sizes, interfaces, and addresses. The UI must
never describe sealed mode as anonymous, hidden, or untraceable; label it
as payload confidentiality only. `allow_protocol_downgrade` is parsed and
stored (design cycle H) but phase-1's actual downgrade-refusal enforcement
runs through `allow_gateway_decryption` — a route/node that sets it `false`
refuses to terminate a sealed inbound message into a plaintext leg
(`SECURITY_DOWNGRADE_REFUSED`), rather than silently downgrading it.

## Privacy defaults

* dedicated identity-handling page (default: route-scoped pseudonyms)
* linked identities listed with verification state and an unlink control,
  plus a correlation warning
* never display phone numbers or full native identifiers by default —
  masked (`****921A`, `!****cd34`, `82ad…1172`) with privileged reveal

## Configuration workflow

UI generates the declarative configuration (no separate UI database):

```text
WebUI → validated config object → API → relayfabric.yaml/state → reload
```

With pending-changes review, validate/apply steps, and revision history with
rollback.

## Security model

Defaults: daemon admin API on Unix socket only; UI binds 127.0.0.1 only.
Remote access via SSH tunnel / WireGuard / Tailscale / mTLS reverse proxy.
Remote configuration supports TLS, WebAuthn/passkeys, RBAC, session
expiration, audit logging. Roles per spec §78; identity-linking permissions
stay separate from route management (correlation data is more sensitive).

## Shipped API surface (v0.2+)

- `GET /v1/config` — raw YAML, secrets unresolved
- `POST /v1/config/validate` — dry-run validation, 422 on error
- `PUT /v1/config` — apply a new config; writes + one-revision `.prev` history
- `POST /v1/config/rollback` — restore previous config; 404 (none) / 409 (env drift)
- `GET /v1/events` — SSE: ingress, delivery, plugin, link_verified, config_applied
- `GET /v1/routes` — per-route identity_mode, render knobs, matched policies
- `GET /v1/plugins` — per-plugin connection state, capabilities, gauges
- `GET /v1/federation` — peers: name, node_id, trust, connected, last_seen (no addr)
- `GET /v1/discovery` — mode, our_advert, peers: node_id/name/services/protocols/security/expires/received_at
- `GET /v1/openapi.json` — generated OpenAPI 3.1 document for this whole API
- `GET /docs` — self-contained Swagger UI (no CDN), browsable via `socat`/SSH
  tunnel over the admin socket; see `docs/api-reference.md`
- `switchyardctl openapi` — dumps `/v1/openapi.json` to stdout for headless use
