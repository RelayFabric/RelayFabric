# relayfabric-ui

A web admin UI for `switchyardd`, and a thin proxy that serves it.

The daemon's admin API is a Unix-domain socket with **no TCP listener and no
authentication** (see `docs/security.md`). A browser can't reach a Unix
socket, so this binary:

- serves the static single-page UI (`web/`) over TCP, and
- transparently reverse-proxies `/v1/*`, `/metrics`, and `/docs/*` to the
  admin socket — streaming preserved, so the `/v1/events` SSE feed works.

This is an **optional** component: it's a workspace member but excluded from
the default build set, so a bare `cargo build --release` ships only the
daemon, CLI, and MQTT plugin. Build the UI explicitly with `-p relayfabric-ui`
(or `--bin relayfabric-ui`).

## Build & run

```bash
cargo build --release --bin relayfabric-ui
target/release/relayfabric-ui \
  --socket /run/relayfabric/admin.sock \
  --listen 127.0.0.1:8087 \
  --web-dir relayfabric-ui/web
# open http://127.0.0.1:8087
```

Flags: `--socket <admin.sock>` (required), `--listen` (default
`127.0.0.1:8087`), `--web-dir` (default `relayfabric-ui/web`).

The UI has eight screens — Overview, Queue, Config (validate / apply /
rollback, with the last five revisions viewable), Identities, Federation &
discovery, Routes & plugins, Live events (SSE), and Limits & metrics — each
backed by the matching `/v1/...` endpoint.
When the admin socket is unreachable it drops into an offline demo with
sample data so the interface stays browsable.

## Authentication (v0.4)

Passkeys (WebAuthn) with scoped roles. On first start with no registered
credentials, the console logs a one-time `setup_token`; open the UI, paste
it, and register the first passkey — it becomes the `administrator`
credential. Further credentials are added by an administrator
(`/auth/credentials`), each with a role: `viewer`, `operator`,
`route-admin`, `identity-admin`, `security-admin`, or `administrator`.
Every proxied admin request is gated per method + path; identity-link data
requires identity-admin. Sessions are HttpOnly `SameSite=Strict` cookies
(12 h). Flags: `--state-dir` (credential store, 0600), `--rp-id` (WebAuthn
RP id, defaults to the first DNS-name allowed host or `localhost`),
`--no-auth` (loopback development only; logged loudly). Remote use
requires fronting TLS — browsers only offer WebAuthn in a secure context.

## Security

!!! this proxy adds NO authentication of its own yet.

It binds to loopback by default. The admin API grants full control to anyone
who can reach the socket (same-UID = full admin), and this proxy extends that
boundary to whoever can reach its TCP listener. **Do not expose it to a
network without an authenticating reverse proxy in front.** Real auth (TLS,
passkeys, RBAC, audit) is the deferred work this service is the seam for —
see `docs/webui-notes.md`.

## Front end

- **Preact + htm**, vendored offline at `web/vendor/preact-htm.js` (both MIT),
  no build step — the app is plain ES modules.
- **Nocturne** design system (`web/styles.css`) — dark blurple tokens,
  compact spacing, outlined actions.
- Phosphor icons and the Inter font load from a CDN; swap them for vendored
  copies for a fully air-gapped deployment.
- The brand mark is `web/logo.png` (a 128×128 web copy); replace it with your
  own if you like.

## License

Apache-2.0, Copyright © 2026 Jascha Wanger / Tarnover, LLC. Sponsored by
[Tarnover](https://tarnover.com).
