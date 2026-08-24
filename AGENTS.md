# AGENTS.md

Guidance for AI coding agents (and humans) working in the RelayFabric repo.

## What this is

RelayFabric is a protocol-bridging **routing fabric**: a headless Rust daemon
(`switchyardd`) with one common routing/policy/identity/security layer that
delegates every protocol-specific detail to **plugins** (separate supervised
processes speaking a CBOR-over-Unix-socket IPC, Plugin Protocol v1). It is
not a chat app or a library; it bridges messaging/mesh/radio/Internet
networks.

## Layout

- `crates/relay-core` — canonical `Envelope`/types (published as `relayfabric-core`).
- `crates/relay-ipc` — the Plugin Protocol wire format (published as `relayfabric-ipc`).
- `switchyardd/` — the daemon: routing engine, storage (SQLite), CAS, admin API, federation, plugin supervisor. Also `backup`/`restore`/`init` subcommands.
- `switchyardctl/` — thin admin CLI (HTTP over the admin Unix socket).
- `plugins/` — `mqtt` (Rust); `lxmf`/`signal`/`meshcore`/`meshtastic`/`meshtastic-direct`/`nostr`/`bitchat`/`potatomesh` (Python).
- `sdk/python/relayfabric_sdk/` — shared Python plugin scaffold (`run_plugin`, `FrameWriter`, `SentCache`).
- `relayfabric-ui/` — optional web admin UI (Rust reverse-proxy + WebAuthn/RBAC in `src/`, static frontend in `web/`).
- `docs/`, `examples/` (task-oriented configs, CI-validated), `deploy/` (systemd, grafana).

## Build / test / lint (do this before every commit)

```bash
cargo build   -j2 --workspace
cargo test    -j2 --workspace
cargo clippy  -j2 --workspace --all-targets    # CI: clippy -D warnings
cargo fmt                                        # CI: cargo fmt --check
```

- **Always pass `-j2`** to cargo (build/test) — a repo convention to bound parallelism.
- CI (`.github/workflows/ci.yml`) enforces `cargo fmt --check`, clippy, workspace tests, Python suites, golden IPC vectors, `cargo deny`, `cargo audit`. **CI runs on branch pushes, not tags** — a fmt/clippy miss fails it, so run both locally first.
- Python plugin tests: from a plugin dir, `PYTHONPATH=<repo>/sdk/python python -m unittest`. SDK tests: `sdk/python/tests` (`python -m unittest discover -s tests`). Some suites need optional libs (`coincurve`, `paho`); a missing-dep import error is environmental, not a failure.
- Validate a config: `switchyardd --check-config --config <path>`.

## Conventions

- **TDD**: write the failing test first (RED), then minimal code (GREEN). Non-trivial logic ships with a runnable check.
- **Commit messages**: never mention AI tools/assistants or any AI vendor in commit messages, code, or comments. Write them as an ordinary engineer would.
- **Licensing**: in-tree code is permissive (Apache-2.0). GPL/AGPL is allowed **only out-of-process** — a separate plugin process behind the Apache IPC (precedent: the `signal` sidecar and `meshtastic-direct`, both GPL, isolated to their own process). Never link GPL into the daemon or a permissive crate.
- **Plugin Protocol** is versioned + golden-byte-locked; enum variants evolve **additive-last** so existing variants' canonical CBOR is unchanged.
- **Admin API is filesystem-only** (Unix socket + 0700 dir + `SO_PEERCRED`); there is no daemon-level auth. RBAC/WebAuthn live in the `relayfabric-ui` service, not the daemon (standing decision).
- **Config**: most fields apply live via `cfg_snapshot`/`cfg.read()`; `node.*`, `federation`, and `discovery` are restart-required (see `Daemon::apply_config`). Reject dangerous values at load in `config::validate`.
- **Deny-by-default routing**: nothing bridges between plugins unless a `routes` entry says so.
- Match surrounding code's comment density and idiom. Keep diffs focused.

## Releasing

Tag `vX.Y.Z` (via `gh release create --target <full-sha>`) triggers
`release.yml` (signed binaries/`.deb`/cosign) and `publish.yml` (crates.io +
PyPI via Trusted Publishing). Bump the version in `Cargo.toml`
(`[workspace.package]` + the two `[workspace.dependencies]` pins) and
`sdk/python/pyproject.toml`. See `docs/` and the release memory for the full
checklist.

## Where to start

New plugin → `docs/plugin-authors.md` + the Python SDK. Config → `docs/configuration.md` + `examples/`. The daemon's contracts live in `docs/SPEC.md`.
