# Publishing Runbook (v0.4 cycle F)

Publishing is automated: `.github/workflows/publish.yml` runs on every
version tag (and on manual dispatch), tests the packages being published,
and pushes `relayfabric-core` → `relayfabric-ipc` to crates.io and
`relayfabric-sdk` to PyPI. Every step is idempotent — already-published
versions are skipped, so re-running after a partial failure is safe.

Both registries authenticate via **OIDC Trusted Publishing** — no
long-lived tokens live in repo secrets. That needs one-time setup by the
account owner:

## One-time setup

### PyPI

**DONE 2026-08-19:** relayfabric-sdk 0.4.0 is published
(https://pypi.org/project/relayfabric-sdk/). Remaining for automation: on
the project's Publishing settings, add a **trusted publisher** at pypi.org → Account → Publishing:

- project: `relayfabric-sdk`
- owner/repo: `RelayFabric/RelayFabric`
- workflow: `publish.yml`
- environment: `pypi`

Also create the `pypi` environment in the GitHub repo settings (it can be
empty; add reviewers if you want a manual approval gate on publishes).

### crates.io (first publish is manual)

**DONE 2026-08-19:** relayfabric-core 0.4.0 and relayfabric-ipc 0.4.0 are
published. Remaining: on each crate's Settings → Trusted Publishing page, add:

- owner/repo: `RelayFabric/RelayFabric`
- workflow: `publish.yml`
- environment: `crates-io`

and create the `crates-io` environment in the GitHub repo settings. Every
later version publishes automatically on tag.

## Local validation already done

- `cargo package -p relayfabric-core` builds the packaged crate cleanly;
  `relayfabric-ipc` resolves its dep once core is on the registry
  (expected publish-order behavior — the workflow polls the index between
  the two publishes).
- The wheel builds: `relayfabric_sdk-0.4.0-py3-none-any.whl`.
- In-tree consumers keep `use relay_core::` / `use relay_ipc::` through
  Cargo dependency renaming in the workspace manifest.

## After the first release

- Flip the "publish pending registry setup" note in the docs/index.md
  feature-status row.
- Tagging `v0.4.0` triggers all three release workflows: `release.yml`
  (binaries/.deb/attestations), `docker.yml` (semver images), and
  `publish.yml` (registries).
