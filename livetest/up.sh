#!/usr/bin/env bash
# Brings up a RelayFabric live-test session: renders the config template,
# starts a local mosquitto broker (unless told not to), and starts
# switchyardd against it. See livetest/README.md for the full runbook.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_DIR="$SCRIPT_DIR/run"
DATA_DIR="$RUN_DIR/data"

TEMPLATE="$SCRIPT_DIR/config.template.yaml"
CONFIG="$RUN_DIR/config.yaml"

SWITCHYARDD_BIN="$REPO/target/release/switchyardd"
SWITCHYARDCTL_BIN="$REPO/target/release/switchyardctl"
MQTT_PLUGIN_BIN="$REPO/target/release/relayfabric-mqtt"
VENV_PY="$REPO/.venv/bin/python"

SWITCHYARDD_PID_FILE="$RUN_DIR/switchyardd.pid"
MOSQUITTO_PID_FILE="$RUN_DIR/mosquitto.pid"
MOSQUITTO_CONF="$RUN_DIR/mosquitto.conf"
SWITCHYARDD_LOG="$RUN_DIR/switchyardd.log"
MOSQUITTO_LOG="$RUN_DIR/mosquitto.log"
BROKER_KIND_FILE="$RUN_DIR/broker.kind"
DOCKER_BROKER_NAME="relayfabric-livetest-broker"
DOCKER_BROKER_IMAGE="eclipse-mosquitto:2"

MQTT_PORT=18883
NO_BROKER=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [--port N] [--no-broker]

  --port N      MQTT broker port for this session (default: $MQTT_PORT)
  --no-broker   Don't start a local mosquitto; assume something is already
                listening on 127.0.0.1:PORT.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --port)
      if [ $# -lt 2 ]; then
        echo "up.sh: --port needs a value" >&2
        exit 2
      fi
      MQTT_PORT="$2"
      shift 2
      ;;
    --no-broker)
      NO_BROKER=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "up.sh: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

pid_is_live() {
  # $1: pid file path. True if it names a currently-running process.
  [ -f "$1" ] || return 1
  local pid
  pid="$(cat "$1" 2>/dev/null || true)"
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null
}

port_listening() {
  # $1: TCP port on 127.0.0.1.
  (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1
}

docker_usable() {
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

docker_broker_running() {
  docker_usable || return 1
  [ "$(docker inspect -f '{{.State.Running}}' "$DOCKER_BROKER_NAME" 2>/dev/null)" = "true" ]
}

# --- idempotence: refuse to double-start over a live session ---------------
if pid_is_live "$SWITCHYARDD_PID_FILE" || pid_is_live "$MOSQUITTO_PID_FILE" || docker_broker_running; then
  echo "up.sh: a live-test session already looks up (pid file(s) or the docker" >&2
  echo "       broker container point at running processes). Run" >&2
  echo "       '$SCRIPT_DIR/down.sh' first, then retry." >&2
  exit 1
fi

mkdir -p "$RUN_DIR" "$DATA_DIR"

# --- dependency checks -------------------------------------------------
echo "== dependency checks =="

missing_release_bin=0
for bin in "$SWITCHYARDD_BIN" "$SWITCHYARDCTL_BIN" "$MQTT_PLUGIN_BIN"; do
  if [ ! -x "$bin" ]; then
    echo "  [FAIL] release binary missing: $bin" >&2
    missing_release_bin=1
  fi
done
if [ "$missing_release_bin" -ne 0 ]; then
  echo "Build the release binaries first:" >&2
  echo "  cd \"$REPO\" && cargo build -j2 --release" >&2
  exit 1
fi
echo "  [ok] release binaries present (switchyardd, switchyardctl, relayfabric-mqtt)"

if [ ! -x "$VENV_PY" ]; then
  echo "  [FAIL] python venv not found: $VENV_PY" >&2
  echo "Create it and install the meshtastic plugin's deps:" >&2
  echo "  python3 -m venv \"$REPO/.venv\"" >&2
  echo "  \"$REPO/.venv/bin/pip\" install -r \"$REPO/plugins/meshtastic/requirements.txt\"" >&2
  exit 1
fi
if ! "$VENV_PY" -c "import paho.mqtt.client, cbor2" >/dev/null 2>&1; then
  echo "  [FAIL] .venv is missing the meshtastic plugin's deps (paho-mqtt, cbor2)" >&2
  echo "Install them:" >&2
  echo "  \"$REPO/.venv/bin/pip\" install -r \"$REPO/plugins/meshtastic/requirements.txt\"" >&2
  exit 1
fi
echo "  [ok] .venv has meshtastic plugin deps (paho-mqtt, cbor2)"

BROKER_MODE="none"
if command -v mosquitto >/dev/null 2>&1; then
  echo "  [ok] mosquitto found: $(command -v mosquitto)"
  BROKER_MODE="native"
elif docker_usable; then
  echo "  [ok] mosquitto not found, but docker is available: will run $DOCKER_BROKER_IMAGE in a container"
  BROKER_MODE="docker"
else
  echo "  [warn] neither mosquitto nor a working docker were found." >&2
  echo "         Install one, e.g.: sudo apt-get install -y mosquitto mosquitto-clients" >&2
  echo "         (or install Docker)." >&2
  echo "         Continuing with --no-broker semantics: switchyardd will still start," >&2
  echo "         but nothing will be listening on 127.0.0.1:$MQTT_PORT until you point" >&2
  echo "         this session at a broker yourself." >&2
  NO_BROKER=1
fi

# --- render config -------------------------------------------------
echo "== rendering config =="
sed -e "s|__REPO__|$REPO|g" -e "s|__MQTT_PORT__|$MQTT_PORT|g" "$TEMPLATE" > "$CONFIG"
echo "  wrote $CONFIG"

if ! "$SWITCHYARDD_BIN" --config "$CONFIG" --check-config; then
  echo "up.sh: generated config failed --check-config, aborting." >&2
  exit 1
fi

# --- start mosquitto -------------------------------------------------
rm -f "$BROKER_KIND_FILE"
if [ "$NO_BROKER" -eq 1 ]; then
  echo "== broker: skipped (--no-broker) =="
  echo "none" > "$BROKER_KIND_FILE"
elif port_listening "$MQTT_PORT"; then
  echo "== broker: something is already listening on 127.0.0.1:$MQTT_PORT, using it =="
  echo "           (not managed by this session; down.sh won't stop it)"
  echo "none" > "$BROKER_KIND_FILE"
elif [ "$BROKER_MODE" = "native" ]; then
  echo "== starting mosquitto on port $MQTT_PORT =="
  cat > "$MOSQUITTO_CONF" <<EOF
port $MQTT_PORT
pid_file $MOSQUITTO_PID_FILE
log_dest file $MOSQUITTO_LOG
EOF
  mosquitto -c "$MOSQUITTO_CONF" -d
  waited=0
  until [ -f "$MOSQUITTO_PID_FILE" ] || [ "$waited" -ge 10 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  if [ ! -f "$MOSQUITTO_PID_FILE" ] || ! port_listening "$MQTT_PORT"; then
    echo "up.sh: mosquitto did not come up within 10s, see $MOSQUITTO_LOG" >&2
    exit 1
  fi
  echo "native" > "$BROKER_KIND_FILE"
  echo "  mosquitto pid $(cat "$MOSQUITTO_PID_FILE") listening on 127.0.0.1:$MQTT_PORT"
elif [ "$BROKER_MODE" = "docker" ]; then
  echo "== starting mosquitto in docker ($DOCKER_BROKER_IMAGE) on port $MQTT_PORT =="
  docker rm -f "$DOCKER_BROKER_NAME" >/dev/null 2>&1 || true
  # The image ships /mosquitto-no-auth.conf: a listener on 1883 with
  # allow_anonymous, which is exactly what this throwaway live-test broker
  # needs (verified present in eclipse-mosquitto:2).
  docker run -d --name "$DOCKER_BROKER_NAME" \
    -p "127.0.0.1:${MQTT_PORT}:1883" \
    "$DOCKER_BROKER_IMAGE" mosquitto -c /mosquitto-no-auth.conf >/dev/null
  waited=0
  until port_listening "$MQTT_PORT" || [ "$waited" -ge 10 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  if ! port_listening "$MQTT_PORT"; then
    echo "up.sh: docker mosquitto did not come up within 10s; see: docker logs $DOCKER_BROKER_NAME" >&2
    exit 1
  fi
  echo "docker" > "$BROKER_KIND_FILE"
  echo "  docker container $DOCKER_BROKER_NAME listening on 127.0.0.1:$MQTT_PORT"
fi

# --- start switchyardd -------------------------------------------------
echo "== starting switchyardd =="
# switchyardd removes+recreates these sockets itself on startup, but a
# stale file left behind by a previous session (down.sh intentionally
# leaves run/data intact) would otherwise make the socket-wait loop below
# report "up" before the new process has actually bound them. Clear them
# first so the loop only succeeds once switchyardd has truly rebound both.
rm -f "$DATA_DIR/admin.sock"
rm -rf "$DATA_DIR/plugins.d"
nohup "$SWITCHYARDD_BIN" --config "$CONFIG" >"$SWITCHYARDD_LOG" 2>&1 &
echo $! > "$SWITCHYARDD_PID_FILE"

waited=0
until { [ -S "$DATA_DIR/admin.sock" ] && [ -d "$DATA_DIR/plugins.d" ]; } || [ "$waited" -ge 10 ]; do
  sleep 1
  waited=$((waited + 1))
done
if ! { [ -S "$DATA_DIR/admin.sock" ] && [ -d "$DATA_DIR/plugins.d" ]; }; then
  echo "up.sh: switchyardd did not open its sockets within 10s, see $SWITCHYARDD_LOG" >&2
  exit 1
fi
echo "  switchyardd pid $(cat "$SWITCHYARDD_PID_FILE"); admin.sock and plugins.d up under $DATA_DIR"

# --- status -------------------------------------------------
echo
echo "== status =="
# admin.sock existing (checked above) means switchyardd has bound it, but
# axum's accept loop may need one more tick to actually start serving --
# retry briefly rather than let one unlucky race print a scary error.
status_ok=0
for _ in 1 2 3 4 5; do
  if "$SWITCHYARDCTL_BIN" --socket "$DATA_DIR/admin.sock" status; then
    status_ok=1
    break
  fi
  sleep 1
done
if [ "$status_ok" -eq 0 ]; then
  echo "up.sh: admin socket isn't answering yet; try 'switchyardctl --socket $DATA_DIR/admin.sock status' shortly." >&2
fi

echo
echo "== next: tier 0 =="
echo "  automated:  $SCRIPT_DIR/tier0.sh"
echo "  by hand:"
echo "    mosquitto_sub -h 127.0.0.1 -p $MQTT_PORT -t chat/b"
echo "    mosquitto_pub -h 127.0.0.1 -p $MQTT_PORT -t chat/a -m 'hello'"
echo
echo "Tear down with: $SCRIPT_DIR/down.sh"
