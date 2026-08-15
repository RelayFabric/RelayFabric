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

The UI must make trust boundaries visually obvious — show that TRANSLATE mode
means gateway plaintext access, and show OPAQUE mode as ciphertext-only
transit. This prevents operators from misunderstanding what the bridge
guarantees.

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
