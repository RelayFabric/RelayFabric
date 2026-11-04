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
`127.0.0.1:8087`), `--web-dir` (default `relayfabric-ui/web`),
`--state-dir` (default `relayfabric-ui-state` in the working directory),
`--rp-id`, `--allowed-host`, `--origin`, `--no-auth` — the last five are
described under Authentication.

The UI has eight screens — Overview, Queue, Config (validate / apply /
rollback, with the last five revisions viewable), Identities, Federation &
discovery, Routes & plugins, Live events (SSE), and Limits & metrics — each
backed by the matching `/v1/...` endpoint.
When the admin socket is unreachable it drops into an offline demo with
sample data so the interface stays browsable.

## Authentication (v0.4)

Passkeys (WebAuthn) with scoped roles. On first start with no registered
credentials, the service writes a one-time setup token to
`<state-dir>/setup-token` (mode 0600) and logs that path — never the token
itself. Read the file (`cat relayfabric-ui-state/setup-token`), open the
UI, paste it, and register the first passkey — it becomes the
`administrator` credential; the file is deleted once that registration
succeeds. Further credentials are added by an administrator
(`/auth/credentials`), each with a role: `viewer`, `operator`,
`route-admin`, `identity-admin`, `security-admin`, or `administrator`.
Every proxied admin request is gated per method + path; identity-link data
requires identity-admin. Sessions are HttpOnly `SameSite=Strict` cookies
(12 h). Flags: `--state-dir` (credential store + setup token, 0600),
`--rp-id` (WebAuthn RP id, defaults to the first DNS-name allowed host or
`localhost`), `--allowed-host <name>` (repeatable: accept `Host: <name>`
and the `https://<name>` origin — the TLS proxy's public name),
`--origin scheme://host[:port]` (repeatable: additionally accept exactly
this browser origin, needed when the UI is served on a non-default port,
e.g. `--origin https://relay.example.com:8443`, since origins are
port-specific while `--allowed-host` only admits the default-port
`https://` origin), `--no-auth` (loopback development only; logged loudly).
Remote use requires fronting TLS — browsers only offer WebAuthn in a
secure context.

## Security

This service is the authentication boundary for the admin API: the daemon's
socket grants full control to anyone who can reach it (same-UID = full
admin), and the proxy gates every request with the passkey session and
role checks above. It binds to loopback by default; it does **no** TLS of
its own, so for any non-localhost use front it with a TLS reverse proxy
and set `--allowed-host`/`--rp-id` (see `docs/webui-notes.md`, "Remote
access"). With `--no-auth` the proxy extends the socket's full-admin
boundary to whoever can reach its listener — keep that to loopback
development only.

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
