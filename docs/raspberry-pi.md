# RelayFabric on a Raspberry Pi

RelayFabric runs well on a Raspberry Pi and other small single-board computers. The daemon is a small Rust binary, and every plugin is a separate process, so a Pi 4 or Pi 5 comfortably hosts a full gateway. A Pi makes a natural off-grid base station: pair it with the Meshtastic, MeshCore, or LXMF plugins to bridge a LoRa mesh at a remote site with no mains power or Internet.

This page covers the 64-bit requirement, the install options, and how to keep a gateway lean and easy on the SD card.

## What you need

| Board | Verdict |
|---|---|
| Pi 5, Pi 4 (2 GB or more) | Recommended. Runs several plugins plus the web UI with headroom. |
| Pi 3, Pi Zero 2 W (512 MB to 1 GB) | Works for a couple of plugins. Watch memory; skip the web UI and heavy plugins. |

One hard requirement: a **64-bit OS**. The prebuilt artifacts are `aarch64` / `arm64` only, and there is no 32-bit (`armhf`) build. Use Raspberry Pi OS 64-bit (Bookworm) or Ubuntu arm64. Confirm with:

```bash
uname -m    # must print: aarch64
```

If it prints `armv7l` or similar you are on a 32-bit OS; reflash with a 64-bit image, or build from source for your architecture.

## Install

Three paths, easiest first.

### 1. The `.deb` (recommended)

The releases page publishes an `arm64` package with the daemon, the CLI, the MQTT plugin, and hardened systemd units.

```bash
VER=0.4.2
curl -LO "https://github.com/RelayFabric/RelayFabric/releases/download/v${VER}/relayfabric_${VER}-1_arm64.deb"
sudo dpkg -i "relayfabric_${VER}-1_arm64.deb"
```

Every artifact is signed; verify it with cosign first if you like (the command is on each release page). The Python protocol plugins are not in the `.deb`; set up a virtualenv for the ones you use (see [Python plugins on ARM](#python-plugins-on-arm)).

### 2. The tarball

Download `relayfabric-<version>-aarch64-unknown-linux-gnu.tar.gz`, extract it, and put the binaries on your `PATH`. This carries the same binaries plus the web UI, without the systemd units, so you wire your own service (see [Run as a service](#run-as-a-service)).

### 3. Docker (build it on the Pi)

The published `ghcr.io/relayfabric/relayfabric` image is `amd64` only today, so it does **not** run on a Pi as-is. Build the image locally instead, from a checkout on the Pi:

```bash
docker build -t relayfabric:latest .
```

Then follow the [Docker](docker.md) page. The build compiles the Rust binaries and the Python wheels, so it is slow on a Pi (use a Pi 4 or 5, and expect several minutes). Building on a faster machine with `docker buildx build --platform linux/arm64` and pushing to your own registry is quicker if you have one.

### 4. From source

```bash
cargo build -j2 --release
```

Use `-j2` (or `-j1` on a 1 GB board): an unbounded parallel Rust build can exhaust memory on a small Pi. This needs the Rust toolchain (`rustup`).

## Python plugins on ARM

The Python plugins (LXMF, Signal, Meshtastic, MeshCore, Nostr, Bitchat, XMPP, meshtripwire) run from a virtualenv. Most dependencies ship prebuilt `aarch64` wheels on 64-bit Bookworm, but a few can compile from source, so install the build tools once:

```bash
sudo apt install -y python3-venv python3-dev build-essential libffi-dev
python3 -m venv .venv
.venv/bin/pip install -r plugins/lxmf/requirements.txt   # repeat per plugin you route
```

Install only the plugins you actually route; each one is optional. Reticulum (`rns`) and LXMF pull in the `cryptography` package, which has `aarch64` wheels on Bookworm, so it installs without a Rust build step there.

## Keep it lean

A few habits keep a small board healthy:

- **Run only the plugins you route.** Each Python plugin is its own process using tens of megabytes of RAM. On a 512 MB board, two or three is a sensible ceiling.
- **Treat the web UI as optional.** `relayfabric-ui` is a separate process; skip it on the smallest boards, or start it only while you configure the node.
- **Bound build parallelism.** If you build on-device, `-j2` or `-j1` avoids an out-of-memory kill during compilation.

## Protect the SD card

RelayFabric writes to disk: the SQLite queue and dedup store, plus the content-addressed store (CAS) for attachments. SD cards wear out under sustained writes, so:

- **Put `data_dir` on a USB SSD or USB stick**, not the SD card. This is the single biggest reliability win on a Pi.
- **Set `retention_secs` to what you actually need** (for example one day). Old queue rows and orphaned CAS blobs are then pruned instead of accumulating. See [Configuration](configuration.md).
- **Move system logs off the card** with something like `log2ram`, or cap journald's on-disk size.

## A lean Pi config

An MQTT-to-LXMF gateway with `data_dir` on an SSD, modest retention, and no web UI:

```yaml
node:
  name: pi-gateway
  data_dir: /mnt/ssd/relayfabric      # a USB SSD, not the SD card

plugins:
  mqtt:
    enabled: true
    command: relayfabric-mqtt
    config:
      broker: mqtt://127.0.0.1:1883
      topics: ["sensors/in"]

  lxmf:
    enabled: true
    command: /home/pi/relayfabric/.venv/bin/python /home/pi/relayfabric/plugins/lxmf/relayfabric-lxmf
    config:
      display_name: "Pi Gateway"
      storage: /mnt/ssd/relayfabric/lxmf
      propagation_node: "auto"
      channels:
        - name: bridge
          members: ["309abcbd838a8539d3c9fd56a453a9e5"]   # your peer's LXMF hash
          open: true

routes:
  - name: sensors-to-lxmf
    sources: ["mqtt:sensors/in"]
    destinations: ["lxmf:bridge"]

ttl_default_secs: 86400
dedup_ttl_secs: 86400
retention_secs: 86400
hop_limit: 8
```

Validate it before starting:

```bash
switchyardd --config pi.yaml --check-config
```

See [Example Configs](examples.md) for more starting points, including the meshtripwire off-grid alert relay, which is a common Pi use case.

## Run as a service

If you installed the `.deb`, it ships a hardened systemd unit; enable it:

```bash
sudo systemctl enable --now switchyardd
```

For the tarball or a source build, adapt the units in [`deploy/systemd/`](https://github.com/RelayFabric/RelayFabric/tree/main/deploy/systemd) to your paths and user. The [Operations](operations.md) page covers health probes (`switchyardctl health`), metrics, and backups, all of which work the same on a Pi.

## See also

- [Getting Started](getting-started.md) for a first end-to-end route.
- [Docker](docker.md) for running the container.
- [Operations](operations.md) for health, metrics, and backup.
- [Example Configs](examples.md) for task-oriented starting points.
