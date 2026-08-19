# Publishing Runbook (v0.4 cycle F)

Everything is prepared and validated; the only missing ingredient is
registry credentials, which stay with the operator. Publish order matters.

## crates.io (needs `cargo login` with your token)

```sh
cargo publish -p relayfabric-core     # first: ipc depends on it
cargo publish -p relayfabric-ipc
```

Validated locally: `cargo package -p relayfabric-core` builds the packaged
crate cleanly; `relayfabric-ipc` resolves its dep only once core is on the
registry (expected publish-order behavior). In-tree consumers keep
`use relay_core::` / `use relay_ipc::` through Cargo dependency renaming in
the workspace manifest.

## PyPI (needs a token; `pip install twine build`)

```sh
cd sdk/python
python -m build          # wheel validated locally: relayfabric_sdk-0.4.0
twine upload dist/*
```

## After publishing

- Flip the "publish pending registry tokens" note in the docs/index.md
  feature-status row.
- Tag `v0.4.0` — release.yml packages binaries/.deb and docker.yml pushes
  semver images automatically.
