# switchyardd Admin API — Reference

This is a curated overview of the `switchyardd` admin API. It does not
duplicate every field, request/response schema, or exact status code. The
authoritative, always-in-sync machine contract is the generated OpenAPI 3.1
document at `GET /v1/openapi.json` (view it interactively at `GET /docs`).
If this file and `/v1/openapi.json` ever disagree, the OpenAPI document
wins: it is generated from the handler annotations in
`switchyardd/src/admin.rs`, so it cannot drift the way hand-written prose
can.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/status` | Node status |
| GET | `/v1/plugins` | Per-plugin state and capabilities |
| GET | `/v1/routes` | Configured routes with policy/render detail |
| GET | `/v1/config` | Loaded config as YAML (secrets unresolved) |
| GET | `/v1/config/prev` | A retained previous revision (`?n=1..5`, newest first) |
| PUT | `/v1/config` | Replace and apply the config (keeps up to 5 rotated backups) |
| POST | `/v1/config/validate` | Validate a config document without applying it |
| POST | `/v1/config/rollback` | Roll back to the previous applied config |
| GET | `/v1/queue` | Queue counts, or a delivery listing with `?state=` |
| POST | `/v1/queue/{id}/requeue` | Requeue a dead-lettered/failed/expired delivery |
| POST | `/v1/queue/purge` | Purge the dead-letter queue |
| GET | `/v1/messages/{id}` | Delivery trace for one message |
| GET | `/v1/public` | Publicly exposed services |
| GET | `/v1/limits` | Configured quotas and transport budgets |
| GET | `/v1/identities` | Verified identity links |
| POST | `/v1/identities/link` | Request an identity link (sends a challenge) |
| DELETE | `/v1/identities/link/{id}` | Remove an identity link |
| GET | `/v1/identities/challenges` | Pending identity link challenges |
| GET | `/v1/federation` | Federation peers |
| GET | `/v1/discovery` | RFDP: this node's advert and known peer adverts |
| GET | `/v1/events` | Live event feed (Server-Sent Events) |
| GET | `/metrics` | Prometheus metrics (text exposition, not JSON) |
| GET | `/v1/openapi.json` | This API's own OpenAPI 3.1 document |

`/v1/events` streams `text/event-stream`: `ingress`, `delivery`, `plugin`,
`link_verified`, `config_applied`, `federation`, and `advert` events, each
with its own payload shape described in the OpenAPI document rather than a
fabricated JSON request/response schema (SSE doesn't fit one). `/metrics`
is Prometheus text exposition, not JSON. See `/v1/openapi.json` for the
full metric name list.

Status codes actually returned (not aspirational ones) are documented per
operation in `/v1/openapi.json`: e.g. `/v1/identities/link` returns
202/400/409, `/v1/config/rollback` returns 200/404/409/500, `DELETE
/v1/identities/link/{id}` returns 204/404. Read the spec for the current,
authoritative set.

## Transport & access

The admin API is served **only** over a Unix domain socket
(`<data_dir>/admin.sock` by default). There is no TCP listener, and none
is planned for `switchyardd` itself. Every example below reaches that same
socket by a different path; none of them add authentication, because there
isn't any at this layer (see the next section).

- **`switchyardctl`**: the bundled CLI client. `switchyardctl status`,
  `switchyardctl routes`, etc. `switchyardctl openapi` dumps the raw
  `/v1/openapi.json` document to stdout (byte-for-byte, unformatted, so
  it's pipeable straight to a file): `switchyardctl openapi >
  relayfabric-openapi.json`. `switchyardctl docs` prints the browsing
  recipe below, filled in with whatever `--socket` you gave it.
- **Browse `/docs` locally**: forward a TCP port to the socket with
  `socat`, then point a browser at it:

  ```
  socat TCP-LISTEN:8099,fork UNIX-CONNECT:<data_dir>/admin.sock &
  xdg-open http://localhost:8099/docs
  ```

- **Browse `/docs` on a remote host**: tunnel the socket over SSH instead
  (no `socat` needed on the remote end):

  ```
  ssh -L 8099:<data_dir>/admin.sock <user>@<host>
  xdg-open http://localhost:8099/docs
  ```

- **Headless / scripting**: `switchyardctl openapi`, or `curl
  --unix-socket <data_dir>/admin.sock http://localhost/v1/openapi.json`,
  needs no browser at all.

The full machine-readable contract is always `GET /v1/openapi.json`; the
interactive, try-it-out UI is `GET /docs` (and `/docs/`): a self-contained
Swagger UI with no external CDN or script host, since it only ever loads
`/v1/openapi.json` (a relative URL, so it works through any of the above
transports unmodified).

## Access control & security model

**There is no daemon-layer authentication or authorization on this API.**
That is a deliberate, not-yet-filled gap, and this document states it
plainly rather than implying a protection that doesn't exist:

- Access control is entirely the OS filesystem's: the admin socket lives
  inside `data_dir`, which `switchyardd` creates (and, if it already
  exists with looser permissions, tightens) to mode `0700`. A `0700`
  directory cannot even be traversed by another UID, so **any process
  running as the same UID as the daemon has full admin access (every
  route above, including config replace/rollback and identity linking)
  and `root` always does, regardless of UID.** There is no per-route, no
  per-user, and no read-only tier: reaching the socket at all is
  equivalent to full admin. As a second belt on top of the `0700`
  directory, `admin.sock` and the per-plugin `plugins.d/*.sock` are themselves
  explicitly locked to mode `0600` right after `bind()` (`bind()` alone
  leaves a socket file's mode umask-derived, not tightened). So even if
  the parent directory's permissions were ever loosened by mistake, the
  socket files stay owner-only. This is still filesystem-only,
  defense-in-depth on the *same* same-UID boundary described above, not a
  new one: it adds no authentication and no per-route/per-user
  distinction.
- `switchyardd` binds no network listener by default. Nothing here is
  reachable over a network unless an operator deliberately exposes it (an
  SSH tunnel, a `socat` forward, a reverse proxy), and doing so without
  adding an auth layer in front of it extends the "same-UID = full admin"
  trust boundary to whoever can reach that new listener.
- `GET /docs` inherits exactly this same socket boundary and adds nothing
  of its own: it's served by the same daemon, over the same socket, with
  no login screen, no session, and no separate permission check. Anyone
  who can reach `/v1/openapi.json` can reach `/docs`, and vice versa.
- Real authentication/authorization (TLS, WebAuthn/passkeys, RBAC, session
  expiration, audit logging, and role separation that keeps
  identity-linking permissions apart from route-management permissions
  (`docs/webui-notes.md` §78, since correlation data is more sensitive than
  routing config)) is explicitly the job of the separate `relayfabric-ui`
  service described in `docs/webui-notes.md`, fronting this socket.
  **As of v0.4, `relayfabric-ui` provides it: passkey (WebAuthn)
  authentication with scoped roles**, enforced on every proxied request
  (first-run bootstrap via a one-time console setup token). The socket
  itself stays filesystem-guarded; expose only the authenticated UI, and
  only behind TLS for non-localhost use.

The OpenAPI document's `info.description` states this same boundary, and
deliberately declares no `securityScheme`. Inventing a bearer/OAuth scheme
the daemon doesn't implement would mislead client generators into thinking
one exists.

## Security modes (sealed routing, SPEC §113)

A route's `security_mode` is `gateway` (default: this daemon reads and may
transform plaintext, SPEC §113.1's renamed `TRANSLATE`) or `sealed`
(SPEC §113.1's renamed `OPAQUE`: the origin edge gateway AEAD-seals the
payload (X25519 + XChaCha20-Poly1305, algorithm-tagged for future PQ
agility) for the destination edge gateway's `sealed_key`; every
intermediate/transit node carries ciphertext only). `sealed` requires every
destination to be a `fed:<peer>` peer with a config-pinned `sealed_key`
(`federation.peers[].sealed_key`); `--check-config` rejects a `sealed` route
otherwise. Node-level `privacy.minimum_security` (`gateway` default,
`sealed`) is a floor: `--check-config` rejects any route whose effective mode
falls below it, rather than silently allowing a downgrade.

A route's own `security_mode: sealed` is best-effort only. An operator can
still edit that same route to `security_mode: gateway` in place, and the
edit reloads cleanly (already-queued deliveries then egress as cleartext);
for a hard, reload-enforced guarantee that a route can never be downgraded,
set the node's `privacy.minimum_security: sealed` instead.

**Downgrade refusal (§113.2):** a sealed inbound message is never silently
decrypted onto a route that refuses to terminate it. That refusal is gated
by `privacy.allow_gateway_decryption` (node-level, default `true`) or its
per-route override: `false` means this route will not be a
sealed→plaintext termination point, and a sealed inbound message aimed at
it dead-letters `SECURITY_DOWNGRADE_REFUSED`, never translated.
`allow_protocol_downgrade` is parsed and stored (config-only, this phase)
but is NOT a separate enforcement point yet. Phase-1's actual
downgrade-refusal gate is `allow_gateway_decryption` above; this is
documented rather than left to look enforced when it isn't. Rejected sealed
inbound (any reason: unsupported algorithm, tampered ciphertext, wrong
recipient, downgrade refusal, etc.) is never persisted to
`/v1/queue?state=dead_letter`: writing a just-decrypted refusal into a
queryable table would make the refusal cosmetic, not real. Watch the
`relayfabric_sealed_egress_total` / `relayfabric_sealed_ingress_total` /
`relayfabric_sealed_rejected_total` counters on `GET /metrics` instead.

**Claim discipline (§113.6):** sealed routing is **zero-knowledge / blind
payload routing. NOT anonymity.** Nodes still observe timing, sizes,
interfaces, and addresses. Nothing in this API, in `switchyardctl`, or in
any future WebUI may describe sealed mode as anonymous, hidden, or
untraceable: only as payload confidentiality between the origin and
destination edge gateways.

## Privacy

- Identity references are masked in every response that isn't the raw
  config itself: verification codes are never exposed by any API
  response, and `/v1/identities/challenges` returns only a masked target
  ref and expiry.
- `GET /v1/config` returns the raw YAML with secret *references*
  (`${env:...}`) intact and unresolved: never the resolved secret value.
  No handler on this API ever echoes a resolved secret back to a caller.
- `/v1/events` (SSE) is an advisory, best-effort live feed for UI/tooling
  convenience, not a durable or complete audit log. A client that
  disconnects misses events emitted while it was away; use `/v1/queue` and
  `/v1/messages/{id}` for the persisted, queryable state.
