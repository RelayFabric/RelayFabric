# RelayFabric container image.
#
# The daemon spawns each protocol plugin as a local subprocess, so a single
# image bundles the Rust binaries (switchyardd, switchyardctl, the MQTT
# plugin) and a Python virtualenv with the Python plugins' dependencies.
#
# Build:  docker build -t relayfabric:latest .
# Run:    docker run -v "$PWD/config:/config:ro" -v relayfabric-data:/data relayfabric:latest
#         (mount a config at /config/relayfabric.yaml; see docs/docker.md)

# Base images are pinned by digest so a build is reproducible and a
# re-tagged upstream image cannot change what ships; Dependabot's docker
# ecosystem bumps the digests.

# ---------- Rust builder ----------
FROM rust:1-slim-bookworm@sha256:f2c004e3d2d8b547e8cf7ffbc29205385f4e71d23e53e4e383065db5e9f822cd AS rust-builder
WORKDIR /build
# The MQTT plugin's TLS comes from the platform OpenSSL (native-tls).
RUN apt-get update && apt-get install -y --no-install-recommends \
      pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
# Copy every workspace member so the workspace resolves, then build only the
# three shipped binaries in release mode.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY switchyardd ./switchyardd
COPY switchyardctl ./switchyardctl
COPY plugins/mqtt ./plugins/mqtt
# relayfabric-ui is a workspace member, so its manifest must exist for the
# workspace to resolve — copied even though we don't build its binary here.
COPY relayfabric-ui ./relayfabric-ui
# Build each shipped binary by package (-p): relayfabric-ui is excluded from
# the workspace default-members, and -p scopes --bin to the named packages,
# so all four are selected explicitly by package.
RUN cargo build -j2 --release \
      -p switchyardd -p switchyardctl -p relayfabric-mqtt -p relayfabric-ui

# ---------- Python dependency builder ----------
FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337 AS py-builder
# build tools cover any dependency without a prebuilt wheel for this platform
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libffi-dev && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# Union of the plugins' requirements (plus Pillow for image-attachment
# downscaling). pycodec2 (codec2 voice transcoding) is intentionally omitted:
# it needs the libcodec2 system library and is an optional feature.
# Every package is pinned to an exact release so an image rebuild is
# reproducible and a fresh upstream release can't change plugin behavior
# unreviewed; Dependabot (.github/dependabot.yml) proposes the bumps.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
      "cbor2==6.1.5" \
      "coincurve==21.0.0" \
      "lxmf==1.2.1" \
      "meshcore==2.3.8" \
      "paho-mqtt==2.1.0" \
      "rns==1.5.7" \
      "slixmpp==1.17.0" \
      "websockets==17.0.1" \
      "Pillow==13.0.0"

# ---------- Runtime ----------
FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

# Everything runs unprivileged: the daemon, every plugin it spawns, and the
# optional relayfabric-ui service (same image, same uid, so it can open the
# admin socket under /data). Fixed uid/gid so a bind-mounted /data can be
# chown'd to it from the host (`chown -R 10001:10001 ./data`). The home
# directory is /data so anything a plugin keeps under `~` (e.g. Reticulum's
# ~/.reticulum when `rns_configdir` is unset) lands on the persistent volume.
RUN groupadd --system --gid 10001 relayfabric && \
    useradd --system --uid 10001 --gid relayfabric --home-dir /data \
      --no-create-home --shell /usr/sbin/nologin relayfabric

# Python venv (self-contained manylinux wheels) and the Rust binaries.
COPY --from=py-builder /opt/venv /opt/venv
COPY --from=rust-builder \
      /build/target/release/switchyardd \
      /build/target/release/switchyardctl \
      /build/target/release/relayfabric-mqtt \
      /build/target/release/relayfabric-ui \
      /usr/local/bin/

# Plugin executables and the Python SDK they import.
WORKDIR /opt/relayfabric
COPY plugins ./plugins
COPY sdk ./sdk
COPY docs/relayfabric.example.yaml ./relayfabric.example.yaml
# Static assets for the optional web UI (relayfabric-ui --web-dir).
COPY relayfabric-ui/web ./ui-web

ENV PATH="/opt/venv/bin:$PATH"
# Plugin `command` entries in your config should invoke the venv python and
# the in-image plugin paths, e.g.:
#   /opt/venv/bin/python /opt/relayfabric/plugins/lxmf/relayfabric-lxmf
# /data is created owned by the service user; a NEW named volume mounted
# here inherits that ownership on first use. An existing volume from an
# image that ran as root must be re-owned once (see docs/docker.md).
RUN install -d -o relayfabric -g relayfabric -m 0700 /data
VOLUME ["/data", "/config"]
USER relayfabric

# Liveness/readiness via the admin socket: `switchyardctl health` GETs
# /readyz and exits non-zero if the daemon isn't ready (503 or unreachable).
# start-period covers first-boot config load + storage open.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD switchyardctl --socket /data/admin.sock health || exit 1

# The admin API is a Unix socket under the data dir (no TCP). If you enable
# federation, publish its configured TCP port with -p at run time.
ENTRYPOINT ["switchyardd"]
CMD ["--config", "/config/relayfabric.yaml"]
