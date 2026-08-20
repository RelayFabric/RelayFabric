# Operations

This page covers running a `switchyardd` gateway day to day: starting the
daemon, talking to its admin API and `switchyardctl` client, reloading
configuration live, reading metrics, and reading logs. For the config file
format see [Configuration](configuration.md); for the access-control model
behind the admin socket see [Security & Sealed Routing](security.md); for
the full machine-readable API contract see [API Reference](api-reference.md).

## Running switchyardd

```shell
switchyardd --config /etc/relayfabric/relayfabric.yaml
```

`switchyardd` takes exactly two flags:

| Flag | Effect |
|---|---|
| `--config <path>` | Config file to load. Defaults to `/etc/relayfabric/relayfabric.yaml` if omitted. |
| `--check-config` | Load and validate the config, print the route/plugin count, and exit — no daemon starts, no sockets are bound. |

```shell
switchyardd --config docs/relayfabric.example.yaml --check-config
# configuration valid: 1 route(s), 1 plugin(s)
```

There is no `--data-dir` flag: the data directory comes entirely from
`node.data_dir` in the config file. `switchyardd` creates that directory if
it doesn't exist (and tightens its permissions to `0700` if it already
exists with looser ones), then keeps everything the daemon needs to persist
inside it:

- `admin.sock` — the admin API, bound fresh on every start (any stale
  socket file from a previous run is removed first) and hardened to `0600`
  immediately after `bind()`.
- `plugins.d/<name>.sock` — one CBOR-over-Unix-socket plugin IPC endpoint
  per enabled plugin (v0.4: a connection can only become the plugin its
  socket is bound to, and each socket carries its own `peer_uid` policy),
  bound and
  hardened the same way. Plugins `switchyardd` spawns itself connect to it
  automatically; a plugin run out-of-process instead is pointed at it via
  the `RELAYFABRIC_SOCKET` environment variable.
- A SQLite-backed store for the message/delivery queue, dedup state, and
  identity links.
- Node identity keys, under their own subdirectory.
- `relayfabric.yaml` / `relayfabric.yaml.prev` / `relayfabric.yaml.prev.2` …
  `.prev.5` — the applied config and up to five rotated backups, when config is
  managed through the admin API rather than edited on disk directly (see
  [Config hot-reload](#config-hot-reload)).

!!! note "0700 directory, 0600 sockets"
    The `0700` directory is the actual access-control boundary — see
    [Security & Sealed Routing](security.md) for what that does and doesn't
    protect. The `0600` socket mode is defense-in-depth on top of it, not a
    second boundary.

## The admin API

`switchyardd` exposes an HTTP admin API **only** over the `admin.sock` Unix
domain socket in `data_dir` — there is no TCP listener, and none is
planned. Reaching that socket at all is equivalent to full admin access:
there is no authentication, no per-route authorization, and no read-only
tier at this layer.

!!! warning "No authentication on this API"
    Anyone who can reach `admin.sock` (same UID as the daemon, or root) can
    read config, replace it, roll it back, and manage identity links.
    Do not expose it to a network without fronting it with something that
    adds real auth. See [Security & Sealed Routing](security.md) for the
    full model and what a future `relayfabric-ui` service is meant to add.

### Endpoints

The table below is a curated subset for day-to-day operation. The
authoritative, always-in-sync contract is the generated OpenAPI 3.1
document — see [API Reference](api-reference.md) for the full endpoint
list, request/response schemas, and status codes.

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/status` | Node status: name, public flag, per-plugin connection state, aggregate queue counts |
| GET | `/v1/plugins` | Per-plugin connected state, capabilities, latest gauge values |
| GET | `/v1/routes` | Configured routes with policy/render detail |
| GET | `/v1/config` | Loaded config as YAML (secret references unresolved) |
| POST | `/v1/config/validate` | Validate a candidate config document without applying it |
| PUT | `/v1/config` | Replace and apply the config (atomic write, `.prev` backup) |
| POST | `/v1/config/rollback` | Roll back to the previously applied config |
| GET | `/v1/queue` | Aggregate queue counts by delivery state, or a delivery listing with `?state=` (e.g. `dead_letter`) |
| GET | `/v1/messages/{id}` | Delivery trace for one message |
| GET | `/v1/federation` | Federation peers and their connection state |
| GET | `/v1/discovery` | RFDP: this node's advert and known peer adverts |
| GET | `/v1/events` | Live event feed (Server-Sent Events) |
| GET | `/metrics` | Prometheus metrics, text exposition (not JSON) |
| GET | `/v1/openapi.json` | This API's own OpenAPI 3.1 document — the source of truth |
| GET | `/docs`, `/docs/` | Interactive Swagger UI, self-contained (no external CDN), loads `/v1/openapi.json` |

Every endpoint reaches the same socket. A few examples with `curl`:

```shell
sock=<data_dir>/admin.sock

curl --unix-socket "$sock" http://localhost/v1/status
curl --unix-socket "$sock" http://localhost/v1/routes
curl --unix-socket "$sock" 'http://localhost/v1/queue?state=dead_letter&limit=50'
curl --unix-socket "$sock" http://localhost/metrics
```

### Browsing `/docs`

There's no URL to open directly — `/docs` lives behind the same Unix
socket as everything else. Forward a local TCP port to it with `socat`:

```shell
socat TCP-LISTEN:8099,fork UNIX-CONNECT:<data_dir>/admin.sock &
xdg-open http://localhost:8099/docs
```

Or, for a remote host, tunnel the socket over SSH (no `socat` needed on the
remote end):

```shell
ssh -L 8099:<data_dir>/admin.sock <user>@<host>
xdg-open http://localhost:8099/docs
```

Headless / scripting doesn't need a browser at all —
`switchyardctl openapi` or `curl .../v1/openapi.json` is enough.
`switchyardctl docs` prints this same recipe, filled in with whatever
`--socket` you gave it.

## switchyardctl

`switchyardctl` is a thin client for the admin API. Every subcommand takes
an optional `--socket <path>` before it (default
`/var/lib/relayfabric/admin.sock`):

```shell
switchyardctl --socket <data_dir>/admin.sock status
```

| Command | Example | Result |
|---|---|---|
| `status` | `switchyardctl status` | Node status JSON |
| `plugins` | `switchyardctl plugins` | Per-plugin connection state, capabilities, gauges |
| `routes` | `switchyardctl routes` | Configured routes and their policy/render detail |
| `queue` | `switchyardctl queue` | Aggregate queue counts by delivery state |
| `trace <id>` | `switchyardctl trace 01890000-0000-7000-8000-000000000000` | Full delivery trace for one message |
| `federation` | `switchyardctl federation` | Federation peers and connection state |
| `discovery` | `switchyardctl discovery` | RFDP advert and known peer adverts |
| `identities` | `switchyardctl identities` | Verified identity links |
| `link <requester> <target> <name...>` | `switchyardctl link lxmf:abc123 signal:+15551234567 Jascha Dub` | Request an identity link (sends a challenge) |
| `unlink <id>` | `switchyardctl unlink 42` | Remove an identity link |
| `config show` | `switchyardctl config show` | Dump the running config as YAML (secrets unresolved) |
| `config validate <file>` | `switchyardctl config validate candidate.yaml` | Validate a local file against the daemon's own environment, without applying |
| `config apply <file>` | `switchyardctl config apply candidate.yaml` | Validate, write, and apply a local file |
| `config rollback` | `switchyardctl config rollback` | Revert to the previously applied config |
| `events` | `switchyardctl events` | Tail the live SSE feed, one JSON object per line |
| `openapi` | `switchyardctl openapi > relayfabric-openapi.json` | Dump the raw OpenAPI document, byte-for-byte |
| `docs` | `switchyardctl docs` | Print the `socat`/SSH recipe for browsing `/docs` |

!!! tip "Inspecting the dead-letter queue"
    `switchyardctl queue` only prints aggregate counts — it doesn't expose
    `?state=` yet. To list actual dead-lettered messages, hit the endpoint
    directly:
    ```shell
    curl --unix-socket <data_dir>/admin.sock \
      'http://localhost/v1/queue?state=dead_letter&limit=50'
    ```
    Then `switchyardctl trace <message-id>` for the full per-delivery
    history of any one message that turns up.

`config validate`/`config apply` read the given file from **this**
machine's filesystem but POST/PUT its raw text unmodified — the daemon
resolves any `${env:...}`/`${file:...}` secret references against **its
own** environment when it receives that text, not the operator's shell.
That's deliberate: it validates "would this apply cleanly on the running
daemon," not "on my workstation."

## Config hot-reload

Config changes go through the admin API rather than a `SIGHUP` or restart:

1. **`POST /v1/config/validate`** — runs the same parse/validate/
   secret-resolution pipeline `PUT` uses, against the request body, and
   discards the result. Returns `{"valid": true}` (200) or
   `{"valid": false, "errors": [...]}` (422). No filesystem changes either way.
2. **`PUT /v1/config`** — validates first (422, nothing written, on
   failure), then writes the new config to disk (`0600`, atomic) and applies
   it live. The replaced file is kept as `<path>.prev`, and the previous
   backups rotate down one slot (`.prev` → `.prev.2` → … → `.prev.5`, oldest
   dropped) — **up to five revisions** are retained, each forced to `0600`.
   Returns `{"applied": true, "restart_required": [...]}`.
3. **`GET /v1/config/prev[?n=N]`** — reads a retained revision byte-verbatim
   (secret refs unresolved), `n=1` newest (default) to `n=5` oldest kept;
   404 for an empty slot. To restore an older revision, read it and `PUT` it.
4. **`POST /v1/config/rollback`** — undoes the last apply: re-validates the
   newest backup (`.prev`) before touching anything, then swaps it back in as
   the live config (current becomes the new `.prev`) and applies it. 404 if
   no `.prev` exists yet. Same `{"applied": true, "restart_required": [...]}`
   response shape.

`restart_required` names any enabled plugin whose process must be
restarted for the change to take full effect (e.g. its `command` or
`config:` block changed) — empty for a route-only or policy-only change,
which applies without touching any plugin process.

```shell
switchyardctl config validate candidate.yaml
switchyardctl config apply candidate.yaml
switchyardctl config rollback
```

## Secret references

A plugin config value can be, in its entirety, `${env:NAME}` or
`${file:/abs/path}` — never interpolated inside a longer string, the whole
value must be the reference. These are resolved once, at config load time,
against the *daemon's* environment (an unset/empty env var, or an
unreadable/relative file path, is a load error). Resolved values are
passed to the plugin process at spawn and never appear anywhere on the
admin surface:

- `GET /v1/config` always serves the raw, pre-resolution YAML — the
  `${...}` reference form, never the resolved value.
- `/v1/routes` and `/v1/plugins` don't echo plugin `config:` blocks at all.
- `--check-config` output shows the unresolved form too.

See [Configuration](configuration.md) for the full secret-reference syntax.

## Metrics

`GET /metrics` serves Prometheus text exposition (not JSON) — scrape it
directly, no separate metrics port. Two guarantees make it safe to scrape
even with plugin-supplied gauge data mixed in:

- **Bounded** — custom gauges reported by any one plugin are capped at 32;
  extras are dropped rather than accepted unbounded.
- **Finite-only** — non-finite values (`NaN`, `+inf`, `-inf`) that a plugin
  reports are dropped before rendering, never passed through. A
  plugin-controlled value can't silently poison a PromQL query with a
  Prometheus-incompatible token.

| Family | Examples |
|---|---|
| Ingress / egress | `relayfabric_messages_ingress_total`, `relayfabric_messages_egress_total`, `relayfabric_messages_dropped_total`, `relayfabric_duplicate_messages_total` |
| Policy / limits | `relayfabric_policy_denials_total`, `relayfabric_ratelimited_total`, `relayfabric_queue_rejected_total`, `relayfabric_budget_deferred_total` |
| Delivery / queue | `relayfabric_delivery_latency_seconds` (summary), `relayfabric_queue_depth{state}`, `relayfabric_route_messages_total{route}` |
| DLQ | `relayfabric_queue_depth{state="dead_letter"}` — watch this gauge; see [Inspecting the dead-letter queue](#switchyardctl) above for the underlying rows |
| Identity | `relayfabric_links_verified_total` |
| Federation / discovery | `relayfabric_federation_ingress_total`, `relayfabric_federation_egress_total`, `relayfabric_federation_rejected_total`, `relayfabric_federation_peer_up{peer}`, `relayfabric_advert_rx_total`, `relayfabric_advert_tx_total`, `relayfabric_advert_rejected_total` |
| Sealed routing | `relayfabric_sealed_egress_total`, `relayfabric_sealed_ingress_total`, `relayfabric_sealed_rejected_total` |
| Transport class | `relayfabric_transport_demoted_total` |
| Plugin health | `relayfabric_plugin_up{plugin}`, `relayfabric_plugin_gauge{plugin,name}` |

The full metric name list is documented on the `/metrics` operation in
`/v1/openapi.json`.

```shell
curl --unix-socket <data_dir>/admin.sock http://localhost/metrics | grep dead_letter
```

## Logging

`switchyardd` logs via `tracing`, controlled by the standard `RUST_LOG`
environment variable (defaults to `info` if unset).

Plugin processes that `switchyardd` spawns itself run with
`PYTHONUNBUFFERED=1` set. Python's stdout is block-buffered by default
when it isn't attached to a TTY — without this, a Python plugin's
diagnostic output could sit in its own buffer instead of reaching the
daemon's log in real time. With it, `print()`/logging output from the
LXMF, Signal, Meshtastic, MeshCore, Nostr, and Bitchat plugins surfaces
live, interleaved with the daemon's own log lines, instead of arriving in
delayed bursts.

## See also

- [API Reference](api-reference.md) — the full admin API contract
- [Configuration](configuration.md) — config file format and secret syntax
- [Security & Sealed Routing](security.md) — the access-control model
  behind the admin socket, and sealed-routing security modes
</content>

## Hardened systemd deployment

`deploy/systemd/` ships two units (v0.4 cycle B):

- `switchyardd.service` — the daemon as its own `relayfabric` user with
  full sandboxing (`ProtectSystem=strict`, seccomp `@system-service`, empty
  capability set, `MemoryDenyWriteExecute`).
- `relayfabric-plugin@.service` — one instance per plugin, each under its
  own `relayfabric-plugin-<name>` user. Pair each instance with the
  plugin's `peer_uid` in `relayfabric.yaml`; the daemon then accepts only
  that UID on the plugin's socket. Radio/serial plugins loosen
  `PrivateDevices` per-instance via a drop-in (`DeviceAllow=/dev/ttyUSB0`),
  and radio plugins drop `AF_INET` entirely.

Under this layout a compromised plugin parser cannot read the daemon's
identity/sealed keys, open `admin.sock`, impersonate another plugin, or
reach devices and networks outside its allowlist.

## Key rotation

Every key the daemon holds, what rotating it costs, and how (v0.4 security
review item 5). Stop the daemon before touching key files; all of them are
created-if-absent on startup.

| Key | File (under `data_dir`) | Rotation cost |
|---|---|---|
| Fed Noise static (X25519) | `fed_static.key` | **Free.** Peers never pin it — each handshake carries an Ed25519-signed identity binding over the current static. Delete the file, restart; existing connections reconnect and rebind. |
| Sealed-routing key (X25519) | `sealed.key` | **Bounded staleness.** Peers learn it from your signed advert. Delete + restart publishes the new key on the next advert refresh (`advert_ttl_secs / 2`); until each peer refreshes, sealed envelopes they encrypt to the OLD key are rejected `BAD_SEAL` (never silently readable — the old private key is gone). Rotate during a quiet window. |
| Node identity (Ed25519) | `identity/node.key` | **This is replacement, not rotation.** The `rf:` node_id IS this key: every peer's `federation.peers[].node_id`, trust store entry, and allow list names it. A new key is a new node — coordinate with every peer, or you drop out of the fabric. Treat compromise as decommission + re-introduction. |
| Alias key (HMAC) | `alias.key` | **A deliberate privacy reset.** Every route-scoped pseudonym changes at once; persona continuity across all bridged networks breaks by design. Never rotate casually; rotate immediately if the key may have leaked (it enables offline alias-to-sender correlation attempts). |
| UI passkeys | `<ui state-dir>/credentials.json` | Remove individual credentials as an administrator (`DELETE /auth/credentials/<id>`); full reset = delete the file and restart `relayfabric-ui`, which prints a fresh one-time setup token. Sessions are in-memory — a UI restart revokes all of them. |

Compromise triage order: **node identity** (decommission), then **sealed
key** (rotate now — future sealed traffic; past traffic to the old key is
compromised), then **alias key** (rotate — pseudonym unlinkability), then
Noise static (rotate, cheap), then UI credentials.
