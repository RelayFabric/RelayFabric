# Docker

RelayFabric ships a single container image that bundles the Rust binaries (`switchyardd`, `switchyardctl`, the MQTT plugin) and a Python virtualenv with the Python plugins' dependencies. Because the daemon spawns each plugin as a local subprocess, one image runs the whole gateway.

## Get the image

Pull the published image (built by CI on every push to `main`):

```bash
docker pull ghcr.io/relayfabric/relayfabric:latest
```

…or build it yourself from the repository root:

```bash
docker build -t relayfabric:latest .
```

The build is multi-stage — a Rust builder compiles the release binaries, a Python builder assembles the plugin virtualenv, and a slim runtime stage carries only what's needed to run.

!!! note "Optional codec2 voice"
    `pycodec2` (codec2 voice transcoding) is **not** in the image — it needs the `libcodec2` system library and is an optional feature. Everything else (MQTT, LXMF, Signal, Meshtastic, MeshCore, Nostr, Bitchat, and image-attachment downscaling) is included.

## Configuration

Mount your config at `/config/relayfabric.yaml` and a data volume at `/data`. Two things must match the container's layout:

- **`node.data_dir: /data`** — the queue database, CAS attachments, the admin socket, and plugin identities live here (mount a named volume so they persist).
- **Plugin `command` paths** — invoke the in-image virtualenv and plugin scripts:

    ```yaml
    plugins:
      lxmf:
        enabled: true
        command: /opt/venv/bin/python /opt/relayfabric/plugins/lxmf/relayfabric-lxmf
        config: { ... }
    ```

Start from the bundled example (`/opt/relayfabric/relayfabric.example.yaml`, also `docs/relayfabric.example.yaml` in the repo) and adjust those paths. See [Configuration](configuration.md) for the full reference.

## Run

```bash
docker run -d --name relayfabric \
  -v "$PWD/config:/config:ro" \
  -v relayfabric-data:/data \
  ghcr.io/relayfabric/relayfabric:latest
```

The admin API is a **Unix socket** under `/data` (no TCP, no auth — see [Security & Sealed Routing](security.md)), so there are no ports to publish for it. Inspect the running gateway by exec-ing `switchyardctl` inside the container:

```bash
docker exec relayfabric switchyardctl --socket /data/admin.sock status
docker exec relayfabric switchyardctl --socket /data/admin.sock plugins
```

!!! tip "Federation port"
    Federation (see [Federation & Discovery](federation.md)) listens on a TCP port only when you configure it. Publish that port with `-p` (or a compose `ports:` entry) if you federate.

## Compose

`docker-compose.yml` runs the gateway alongside an optional local MQTT broker (for the MQTT and Meshtastic plugins):

```bash
mkdir -p config
cp docs/relayfabric.example.yaml config/relayfabric.yaml
# edit config/relayfabric.yaml: data_dir /data, plugin command paths,
# and point MQTT plugins at mqtt://mosquitto:1883
docker compose up -d
docker compose exec switchyardd switchyardctl --socket /data/admin.sock status
```

Remove the `mosquitto` service if you point the plugins at an external broker.

## Continuous builds

The `Docker` GitHub Actions workflow builds the image on every commit and pull request, and publishes `ghcr.io/relayfabric/relayfabric:latest` (and a `sha-<commit>` tag) on pushes to `main`. It uses build-layer caching so incremental builds are fast.
