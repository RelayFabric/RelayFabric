# switchyardd Admin API — Reference

This is a curated overview of the `switchyardd` admin API. It does not
duplicate every field, request/response schema, or exact status code — the
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
| PUT | `/v1/config` | Replace and apply the config |
| POST | `/v1/config/validate` | Validate a config document without applying it |
| POST | `/v1/config/rollback` | Roll back to the previous applied config |
| GET | `/v1/queue` | Queue counts, or a delivery listing with `?state=` |
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
is Prometheus text exposition, not JSON — see `/v1/openapi.json` for the
full metric name list.

Status codes actually returned (not aspirational ones) are documented per
operation in `/v1/openapi.json` — e.g. `/v1/identities/link` returns
202/400/409, `/v1/config/rollback` returns 200/404/409/500, `DELETE
/v1/identities/link/{id}` returns 204/404. Read the spec for the current,
authoritative set.

## Transport & access

The admin API is served **only** over a Unix domain socket
(`<data_dir>/admin.sock` by default) — there is no TCP listener, and none
is planned for `switchyardd` itself. Every example below reaches that same
socket by a different path; none of them add authentication, because there
isn't any at this layer (see the next section).

- **`switchyardctl`** — the bundled CLI client. `switchyardctl status`,
  `switchyardctl routes`, etc. `switchyardctl openapi` dumps the raw
  `/v1/openapi.json` document to stdout (byte-for-byte, unformatted, so
  it's pipeable straight to a file): `switchyardctl openapi >
  relayfabric-openapi.json`. `switchyardctl docs` prints the browsing
  recipe below, filled in with whatever `--socket` you gave it.
- **Browse `/docs` locally** — forward a TCP port to the socket with
  `socat`, then point a browser at it:

  ```
  socat TCP-LISTEN:8099,fork UNIX-CONNECT:<data_dir>/admin.sock &
  xdg-open http://localhost:8099/docs
  ```

- **Browse `/docs` on a remote host** — tunnel the socket over SSH instead
  (no `socat` needed on the remote end):

  ```
  ssh -L 8099:<data_dir>/admin.sock <user>@<host>
  xdg-open http://localhost:8099/docs
  ```

- **Headless / scripting** — `switchyardctl openapi`, or `curl
  --unix-socket <data_dir>/admin.sock http://localhost/v1/openapi.json`,
  needs no browser at all.

The full machine-readable contract is always `GET /v1/openapi.json`; the
interactive, try-it-out UI is `GET /docs` (and `/docs/`) — a self-contained
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
  running as the same UID as the daemon has full admin access — every
  route above, including config replace/rollback and identity linking —
  and `root` always does, regardless of UID.** There is no per-route, no
  per-user, and no read-only tier: reaching the socket at all is
  equivalent to full admin. As a second belt on top of the `0700`
  directory, both `admin.sock` and `plugins.sock` are themselves
  explicitly locked to mode `0600` right after `bind()` (`bind()` alone
  leaves a socket file's mode umask-derived, not tightened) — so even if
  the parent directory's permissions were ever loosened by mistake, the
  socket files stay owner-only. This is still filesystem-only,
  defense-in-depth on the *same* same-UID boundary described above, not a
  new one: it adds no authentication and no per-route/per-user
  distinction.
- `switchyardd` binds no network listener by default. Nothing here is
  reachable over a network unless an operator deliberately exposes it (an
  SSH tunnel, a `socat` forward, a reverse proxy) — and doing so without
  adding an auth layer in front of it extends the "same-UID = full admin"
  trust boundary to whoever can reach that new listener.
- `GET /docs` inherits exactly this same socket boundary and adds nothing
  of its own: it's served by the same daemon, over the same socket, with
  no login screen, no session, and no separate permission check. Anyone
  who can reach `/v1/openapi.json` can reach `/docs`, and vice versa.
- Real authentication/authorization — TLS, WebAuthn/passkeys, RBAC, session
  expiration, audit logging, and role separation that keeps
  identity-linking permissions apart from route-management permissions
  (`docs/webui-notes.md` §78, since correlation data is more sensitive than
  routing config) — is explicitly the job of the separate `relayfabric-ui`
  service described in `docs/webui-notes.md`, fronting this socket. **That
  service is not built yet.** Until it exists, do not expose this API to
  anyone you wouldn't give a shell on this host.

The OpenAPI document's `info.description` states this same boundary, and
deliberately declares no `securityScheme` — inventing a bearer/OAuth scheme
the daemon doesn't implement would mislead client generators into thinking
one exists.

## Privacy

- Identity references are masked in every response that isn't the raw
  config itself — verification codes are never exposed by any API
  response, and `/v1/identities/challenges` returns only a masked target
  ref and expiry.
- `GET /v1/config` returns the raw YAML with secret *references*
  (`${env:...}`) intact and unresolved — never the resolved secret value.
  No handler on this API ever echoes a resolved secret back to a caller.
- `/v1/events` (SSE) is an advisory, best-effort live feed for UI/tooling
  convenience, not a durable or complete audit log — a client that
  disconnects misses events emitted while it was away; use `/v1/queue` and
  `/v1/messages/{id}` for the persisted, queryable state.
