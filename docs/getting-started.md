# Getting Started

This walks you from a fresh checkout to a message routed end-to-end through `switchyardd`. The quickest path (an MQTT loopback) needs only the Rust toolchain and a local broker; the protocol plugins add a Python virtualenv.

!!! tip "Packaged releases (v0.4+)"
    Version tags publish x86-64/aarch64 tarballs, a `.deb` (daemon + CLI +
    MQTT plugin + hardened systemd units), sha256 checksums, and GitHub
    build-provenance attestations to the
    [releases page](https://github.com/RelayFabric/RelayFabric/releases),
    plus semver-tagged images at `ghcr.io/relayfabric/relayfabric`.
    Building from source (below) is only needed for development.

## Prerequisites

| Component | Needed for | Notes |
|---|---|---|
| Rust toolchain (`cargo`) | `switchyardd`, `switchyardctl`, the MQTT plugin | Build with `-j2` to bound parallelism. |
| `mosquitto` (or Docker) | the MQTT quick-start and the live-test harness | `mosquitto` + `mosquitto-clients`, or an `eclipse-mosquitto:2` container. |
| Python 3.12 virtualenv | the Python plugins (LXMF, Signal, Meshtastic, MeshCore, Nostr, Bitchat) | One `.venv`; install each plugin's `requirements.txt` as needed. |

!!! note "License"
    RelayFabric is Apache-2.0, and every dependency is chosen under a permissive-only policy: no AGPL or other copyleft. This drives some plugin design choices (see [Plugins](plugins.md)).

## Build

```bash
cargo build -j2 --release
```

Binaries land in `target/release/`. The rest of this guide assumes it is on your `PATH`.

## The Python plugin virtualenv

The Rust MQTT plugin needs no runtime deps, but the Python plugins do. Create one virtualenv and install what a given plugin needs:

```bash
python3 -m venv .venv
.venv/bin/pip install -r plugins/lxmf/requirements.txt   # e.g. for the LXMF plugin
```

A plugin's `command` in the config points at `.venv/bin/python …`. See [Configuration](configuration.md).

## First route: MQTT loopback

1. Generate a starter config (or validate the fully-annotated example). `init`
   writes a minimal, valid config and never overwrites an existing one; the
   web UI's Config view has an equivalent **Starter template** button.

    ```bash
    switchyardd init --config ./relayfabric.yaml   # writes a starter, then:
    switchyardd --config ./relayfabric.yaml --check-config
    # …or start from the annotated reference:
    switchyardd --config docs/relayfabric.example.yaml --check-config
    ```

    For a task-focused starting point (Meshtastic↔LXMF, a public federation
    node, a multi-network hub, MQTT↔Signal, …) copy one of the
    [example configs](examples.md) and edit the few fields its header names.

2. Run a broker, the daemon, and a subscriber, then publish:

    ```bash
    mosquitto -p 1883 &
    switchyardd --config docs/relayfabric.example.yaml &
    mosquitto_sub -t chat/b &
    mosquitto_pub -t chat/a -m "ping"
    ```

    The message published on `chat/a` is routed through `switchyardd` and delivered on `chat/b` (and vice versa) per the example config's `demo` route.

    !!! tip "No echo loops"
        The MQTT plugin sets MQTT v5 *No Local* on its subscriptions, so the broker never echoes a plugin's own publishes back to it.

## Inspect the running daemon

`switchyardctl` talks to the admin API over the Unix socket under `node.data_dir`:

```bash
switchyardctl status              # node id, connected plugins, queue summary
switchyardctl plugins             # advertised capabilities per plugin
switchyardctl routes              # configured routes
switchyardctl queue               # pending / dead-lettered deliveries
switchyardctl trace <message-id>  # a message's per-destination delivery state
```

See [Operations](operations.md) for the full admin surface (metrics, config hot-reload, the Swagger UI at `/docs`).

## Going further

- **Add a real network.** Enable a plugin in your config and add a route to it. See [Plugins](plugins.md) and [Configuration](configuration.md).
- **Test against real hardware/networks.** The `livetest/` kit is a copy-paste runbook for MQTT, then LXMF over Reticulum, then Signal, then real Meshtastic. See [Live & Field Testing](live-testing.md).
- **Understand the model.** [Architecture](architecture.md) explains the daemon, plugins, and the message envelope; [Routing & Policy](routing.md) covers dedup, TTL, retry, and the dead-letter queue.
