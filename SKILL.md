---
name: relayfabric-dev
description: Use when developing on the RelayFabric codebase — the switchyardd protocol-bridging daemon, its Rust crates and CLI, the Python plugin fleet + SDK, or the web UI. Covers the repo's build/test/lint workflow and its conventions.
---

# Developing on RelayFabric

RelayFabric is a protocol-bridging routing fabric: the `switchyardd` daemon
plus plugins (separate processes over a CBOR/Unix-socket IPC). Full repo
guidance is in [`AGENTS.md`](AGENTS.md); this is the essential loop.

## Before every commit

```bash
cargo build  -j2 --workspace
cargo test   -j2 --workspace
cargo clippy -j2 --workspace --all-targets   # CI: -D warnings
cargo fmt                                      # CI: fmt --check
```

Always pass `-j2` to cargo. CI enforces fmt + clippy + tests on branch
pushes (not tags), so run them locally first. Python plugin tests run with
`PYTHONPATH=<repo>/sdk/python python -m unittest` from a plugin dir.

## Non-negotiable conventions

- **TDD** — failing test first, then minimal code.
- **No AI-tool/vendor mentions** in commit messages, code, or comments.
- **Licensing** — in-tree code stays permissive (Apache-2.0); GPL/AGPL only
  runs out-of-process as a plugin behind the Apache IPC (e.g. `signal`,
  `meshtastic-direct`). Never link GPL into the daemon or a permissive crate.
- **Plugin Protocol** — versioned, golden-byte-locked; add enum variants
  additive-last so existing variants' CBOR is unchanged.
- **Admin API is filesystem-only**; RBAC/WebAuthn live in `relayfabric-ui`,
  not the daemon.
- **Deny-by-default routing** — nothing bridges unless a `routes` entry says so.

## Map

`crates/relay-core` + `crates/relay-ipc` (published crates) · `switchyardd`
(daemon) · `switchyardctl` (CLI) · `plugins/` (mqtt=Rust, rest=Python) ·
`sdk/python/relayfabric_sdk` (plugin scaffold) · `relayfabric-ui` (web) ·
`docs/`, `examples/` (CI-validated configs), `deploy/`.

Start points: a new plugin → `docs/plugin-authors.md`; config → `examples/`
+ `docs/configuration.md`; contracts → `docs/SPEC.md`.
