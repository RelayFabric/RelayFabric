# RelayFabric WebUI — Design Notes

Status: the UI and its reverse-proxy are built: see `relayfabric-ui/`. What
remains deferred is authentication/RBAC on the proxy; today it binds to
loopback with no auth of its own. The administrative API was designed for the
WebUI from day one, and these notes capture that architecture and the deferred
auth work.

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
  delivery status: no content when content logging is disabled)
* logs, metrics, configuration validation

## Security boundary visibility

The UI must make trust boundaries visually obvious: show that a route's
`security_mode: gateway` (SPEC §113.1's renamed `TRANSLATE`, the default)
means the gateway reads plaintext, and `security_mode: sealed` (renamed
`OPAQUE`) means ciphertext-only transit: the origin edge AEAD-seals the
payload for the destination edge's key, and every intermediate node
(including this one, for traffic it merely relays) carries opaque ciphertext
it cannot read. This prevents operators from misunderstanding what the
bridge guarantees.

**Claim discipline (SPEC §113.6, MUST be honored in every UI string):**
sealed mode is **zero-knowledge / blind payload routing, NOT anonymity**:
nodes still observe timing, sizes, interfaces, and addresses. The UI must
never describe sealed mode as anonymous, hidden, or untraceable; label it
as payload confidentiality only. `allow_protocol_downgrade` is parsed and
stored (design cycle H) but phase-1's actual downgrade-refusal enforcement
runs through `allow_gateway_decryption`: a route/node that sets it `false`
refuses to terminate a sealed inbound message into a plaintext leg
(`SECURITY_DOWNGRADE_REFUSED`), rather than silently downgrading it.

## Privacy defaults

* dedicated identity-handling page (default: route-scoped pseudonyms)
* linked identities listed with verification state and an unlink control,
  plus a correlation warning
* never display phone numbers or full native identifiers by default:
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

## Remote access (TLS reverse proxy)

The UI binds `127.0.0.1:8087` by default. To reach it from another machine,
front it with a **TLS reverse proxy**: do not expose the plain HTTP port.
Two hard requirements come from WebAuthn:

- **HTTPS is mandatory.** Browsers only offer passkeys in a *secure context*
  (`https://`, or `localhost`). Terminate TLS at the proxy.
- **The hostname is the passkey identity.** Passkeys are bound to the
  **RP-ID** (the domain). Serve the UI under one **stable** hostname and set
  `--rp-id <hostname>` (it defaults to the first non-IP `--allowed-host`).
  Changing the hostname/RP-ID later invalidates every registered passkey.

Also pass `--allowed-host <hostname>` for the public name: the UI rejects
requests whose `Host` isn't allow-listed, and Origin-checks every
state-changing request. The proxy must forward the `Host` header and **not
buffer responses**, or the `/v1/events` SSE stream won't flow.

**Caddy** (automatic Let's Encrypt TLS):

```caddy
relay.example.com {
    reverse_proxy 127.0.0.1:8087 {
        flush_interval -1   # stream SSE (/v1/events) without buffering
    }
}
```
Run: `relayfabric-ui --socket <admin.sock> --listen 127.0.0.1:8087 --allowed-host relay.example.com --rp-id relay.example.com`

**nginx**:

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;
    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8087;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;          # stream SSE
    }
}
```

**Tailscale** (simplest for a private tailnet, TLS + a stable
`*.ts.net` name, no public exposure):

```shell
tailscale serve --bg 8087
# UI at https://<node>.<tailnet>.ts.net ; run with:
relayfabric-ui --socket <admin.sock> --allowed-host <node>.<tailnet>.ts.net --rp-id <node>.<tailnet>.ts.net
```

For a quick one-off without a proxy, an SSH tunnel keeps the loopback bind
and the `localhost` secure-context exemption:
`ssh -L 8087:127.0.0.1:8087 user@host`, then browse `http://localhost:8087`.

## Shipped API surface (v0.2+)

- `GET /v1/config`: raw YAML, secrets unresolved
- `POST /v1/config/validate`: dry-run validation, 422 on error
- `PUT /v1/config`: apply a new config; writes + one-revision `.prev` history
- `POST /v1/config/rollback`: restore previous config; 404 (none) / 409 (env drift)
- `GET /v1/events`: SSE: ingress, delivery, plugin, link_verified, config_applied
- `GET /v1/routes`: per-route identity_mode, render knobs, matched policies
- `GET /v1/plugins`: per-plugin connection state, capabilities, gauges
- `GET /v1/federation`: peers: name, node_id, trust, connected, last_seen (no addr)
- `GET /v1/discovery`: mode, our_advert, peers: node_id/name/services/protocols/security/expires/received_at
- `GET /v1/openapi.json`: generated OpenAPI 3.1 document for this whole API
- `GET /docs`: self-contained Swagger UI (no CDN), browsable via `socat`/SSH
  tunnel over the admin socket; see `docs/api-reference.md`
- `switchyardctl openapi`: dumps `/v1/openapi.json` to stdout for headless use
