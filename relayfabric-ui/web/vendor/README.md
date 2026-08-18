# Vendored front-end libraries

- **preact-htm.js** — the `htm/preact/standalone` bundle
  (https://unpkg.com/htm@3.1.1/preact/standalone.module.js): Preact and htm
  compiled into one self-contained ES module exporting `html`, `render`,
  `Component`, and the Preact hooks.
  - Preact — MIT License (© Preact authors)
  - htm — Apache-2.0 License (© Jason Miller)

Both are permissive and compatible with RelayFabric's Apache-2.0 licensing.
Vendored offline (no CDN at runtime) so the admin UI works air-gapped.
