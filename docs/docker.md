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

The build is multi-stage: a Rust builder compiles the release binaries, a Python builder assembles the plugin virtualenv, and a slim runtime stage carries only what's needed to run.

!!! note "Optional codec2 voice"
    `pycodec2` (codec2 voice transcoding) is **not** in the image: it needs the `libcodec2` system library and is an optional feature. Everything else (MQTT, LXMF, Signal, Meshtastic, MeshCore, Nostr, Bitchat, and image-attachment downscaling) is included.

## Configuration

Mount your config at `/config/relayfabric.yaml` and a data volume at `/data`. Two things must match the container's layout:

- **`node.data_dir: /data`**, the queue database, CAS attachments, the admin socket, and plugin identities live here (mount a named volume so they persist). The home directory of the service user is also `/data`, so a plugin that keeps state under `~` (Reticulum's `~/.reticulum` when `rns_configdir` is unset) persists too.
- **Plugin `command` paths**: invoke the in-image virtualenv and plugin scripts:

    ```yaml
    plugins:
      lxmf:
        enabled: true
        command: /opt/venv/bin/python /opt/relayfabric/plugins/lxmf/relayfabric-lxmf
        config: { ... }
    ```

Start from the bundled example (`/opt/relayfabric/relayfabric.example.yaml`, also `docs/relayfabric.example.yaml` in the repo) and adjust those paths. See [Configuration](configuration.md) for the full reference.

!!! note "Nothing in the container runs as root"
    The daemon, every plugin it spawns, and the optional web UI run as the image's `relayfabric` user (uid/gid 10001). A **named** volume picks that ownership up automatically the first time it is mounted. A **bind-mounted** data directory must be owned by that uid (`sudo chown -R 10001:10001 ./data`), and the config bind mount just needs to be world-readable. A data volume created by an image older than this one belongs to root and must be re-owned once, with the stack stopped:

    ```bash
    docker compose run --rm --user root --entrypoint chown switchyardd -R 10001:10001 /data
    ```

## Run

```bash
docker run -d --name relayfabric \
  -v "$PWD/config:/config:ro" \
  -v relayfabric-data:/data \
  ghcr.io/relayfabric/relayfabric:latest
```

The admin API is a **Unix socket** under `/data` (no TCP, no auth, see [Security & Sealed Routing](security.md)), so there are no ports to publish for it. Inspect the running gateway by exec-ing `switchyardctl` inside the container:

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

### Web UI

The compose stack also starts the optional **web admin UI** (`relayfabric-ui`)
on <http://localhost:8087>, sharing the data volume so it reaches the daemon's
admin socket (both run as the same unprivileged user). It ships with
`--no-auth` for a **local-only** first look: the port is published to
`127.0.0.1` only, and the service sits on its own compose network that no
other container joins, so neither the broker nor the daemon (nor anything you
add to the stack later) can reach the unauthenticated listener; it needs no
network path to the daemon because the admin socket is on the shared volume.

For real or remote use, remove `--no-auth` from the service `command`, front
it with TLS, and set `--rp-id` / `--allowed-host` (and `--origin` if the
public port isn't 443). The UI then keeps its credential store under
`/data/ui-state` and, on first start, writes the one-time setup token there
instead of logging it:

```bash
docker compose exec relayfabric-ui cat /data/ui-state/setup-token
```

See [Web UI notes → Remote access](webui-notes.md). Remove the
`relayfabric-ui` service if you don't want it.

The bundled `mosquitto` runs with its no-auth config: any container on the
default compose network (and the host's loopback) can publish and subscribe.
That is fine for the demo; for anything else mount your own `mosquitto.conf`
with `allow_anonymous false` and a `password_file`, and give the plugins
credentials.

## Continuous builds

The `Docker` GitHub Actions workflow builds the image on every commit and pull request, and publishes `ghcr.io/relayfabric/relayfabric:latest` (and a `sha-<commit>` tag) on pushes to `main`. It uses build-layer caching so incremental builds are fast.
