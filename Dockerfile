# RelayFabric container image.
#
# The daemon spawns each protocol plugin as a local subprocess, so a single
# image bundles the Rust binaries (switchyardd, switchyardctl, the MQTT
# plugin) and a Python virtualenv with the Python plugins' dependencies.
#
# Build:  docker build -t relayfabric:latest .
# Run:    docker run -v "$PWD/config:/config:ro" -v relayfabric-data:/data relayfabric:latest
#         (mount a config at /config/relayfabric.yaml; see docs/docker.md)

# ---------- Rust builder ----------
FROM rust:1-slim-bookworm AS rust-builder
WORKDIR /build
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
FROM python:3.12-slim-bookworm AS py-builder
# build tools cover any dependency without a prebuilt wheel for this platform
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libffi-dev && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
# Union of the plugins' requirements (plus Pillow for image-attachment
# downscaling). pycodec2 (codec2 voice transcoding) is intentionally omitted:
# it needs the libcodec2 system library and is an optional feature.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir \
      cbor2 \
      "coincurve==21.0.0" \
      lxmf \
      "meshcore==2.3.8" \
      paho-mqtt \
      rns \
      "slixmpp>=1.8" \
      "websockets==17.0.1" \
      Pillow

# ---------- Runtime ----------
FROM python:3.12-slim-bookworm AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates && rm -rf /var/lib/apt/lists/*

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
RUN mkdir -p /data
VOLUME ["/data", "/config"]

# Liveness/readiness via the admin socket: `switchyardctl health` GETs
# /readyz and exits non-zero if the daemon isn't ready (503 or unreachable).
# start-period covers first-boot config load + storage open.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD switchyardctl --socket /data/admin.sock health || exit 1

# The admin API is a Unix socket under the data dir (no TCP). If you enable
# federation, publish its configured TCP port with -p at run time.
ENTRYPOINT ["switchyardd"]
CMD ["--config", "/config/relayfabric.yaml"]
