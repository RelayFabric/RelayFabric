#!/usr/bin/env bash
# Tier-0 live-test assertions: requires `up.sh` to already have a broker and
# switchyardd running. Exercises the MQTT loopback route and, without any
# Meshtastic hardware, the meshtastic plugin's uplink parsing and downlink
# publish (see plugins/meshtastic/README.md's "Manual e2e smoke test").
# Prints PASS/FAIL per check and exits nonzero if any check fails.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_DIR="$SCRIPT_DIR/run"
DATA_DIR="$RUN_DIR/data"
CONFIG="$RUN_DIR/config.yaml"

SWITCHYARDCTL_BIN="$REPO/target/release/switchyardctl"
BROKER_KIND_FILE="$RUN_DIR/broker.kind"
DOCKER_BROKER_NAME="relayfabric-livetest-broker"

WAIT_SECS=10
FAILED=0

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1" >&2; FAILED=1; }

# --- preconditions -------------------------------------------------
if [ ! -f "$CONFIG" ]; then
  echo "tier0.sh: no rendered config at $CONFIG -- run up.sh first." >&2
  exit 1
fi

MQTT_PORT="$(sed -n 's#.*broker: mqtt://127\.0\.0\.1:\([0-9]\{1,\}\).*#\1#p' "$CONFIG" | head -n1)"
if [ -z "$MQTT_PORT" ]; then
  echo "tier0.sh: could not read the MQTT port out of $CONFIG." >&2
  exit 1
fi

if [ ! -S "$DATA_DIR/admin.sock" ] || [ ! -d "$DATA_DIR/plugins.d" ]; then
  echo "tier0.sh: switchyardd is not up (no admin.sock/plugins.d under $DATA_DIR)." >&2
  echo "          run up.sh first." >&2
  exit 1
fi
if ! "$SWITCHYARDCTL_BIN" --socket "$DATA_DIR/admin.sock" status >/dev/null 2>&1; then
  echo "tier0.sh: switchyardd's admin socket did not answer 'status'. run up.sh first." >&2
  exit 1
fi

# mosquitto_pub/mosquitto_sub on PATH is the normal case; if up.sh fell
# back to a docker-run broker instead, `docker exec` into that same
# container gives us the clients without installing anything locally.
CLIENT_MODE=""
if command -v mosquitto_pub >/dev/null 2>&1 && command -v mosquitto_sub >/dev/null 2>&1; then
  CLIENT_MODE="native"
elif [ "$(cat "$BROKER_KIND_FILE" 2>/dev/null || true)" = "docker" ] \
     && command -v docker >/dev/null 2>&1 \
     && docker inspect "$DOCKER_BROKER_NAME" >/dev/null 2>&1; then
  CLIENT_MODE="docker"
else
  echo "tier0.sh: no mosquitto_pub/mosquitto_sub on PATH, and no docker-managed" >&2
  echo "          broker container ($DOCKER_BROKER_NAME) to exec into." >&2
  echo "          Install mosquitto-clients, e.g.: sudo apt-get install -y mosquitto-clients" >&2
  echo "          -- or run up.sh so its docker broker container exists." >&2
  exit 1
fi

if ! (exec 3<>"/dev/tcp/127.0.0.1/$MQTT_PORT") >/dev/null 2>&1; then
  echo "tier0.sh: no broker reachable on 127.0.0.1:$MQTT_PORT." >&2
  echo "          Either up.sh ran with --no-broker (no mosquitto and no docker" >&2
  echo "          were found), or the broker died. Start one (see up.sh's" >&2
  echo "          dependency-check output) and retry." >&2
  exit 1
fi

echo "== tier 0: broker on 127.0.0.1:$MQTT_PORT ($CLIENT_MODE clients), daemon up =="

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Mechanism-agnostic pub/sub: everything below just calls these two.
mpub() {
  if [ "$CLIENT_MODE" = "native" ]; then
    mosquitto_pub -h 127.0.0.1 -p "$MQTT_PORT" "$@"
  else
    docker exec "$DOCKER_BROKER_NAME" mosquitto_pub -h 127.0.0.1 "$@"
  fi
}
msub_bg() {
  # $1: topic, $2: output file, $3: name of the variable to receive the
  # subscriber's PID. Sets $3 via printf -v rather than `echo`+command
  # substitution: command substitution runs this function in a subshell, so
  # a background job started in there is never a child of the *calling*
  # shell and a later `wait` on its pid fails with "not a child of this
  # shell". Setting a caller-named variable keeps everything in one shell.
  if [ "$CLIENT_MODE" = "native" ]; then
    mosquitto_sub -h 127.0.0.1 -p "$MQTT_PORT" -C 1 -W "$WAIT_SECS" -t "$1" >"$2" 2>/dev/null &
  else
    docker exec "$DOCKER_BROKER_NAME" mosquitto_sub -h 127.0.0.1 -C 1 -W "$WAIT_SECS" -t "$1" >"$2" 2>/dev/null &
  fi
  printf -v "$3" '%s' "$!"
}

# --- check 1 + check 3: publish to chat/a, expect it on chat/b (tier0
# route) AND, since chat/a is also a mesh-bridge source, a downlink JSON on
# msh/US/2/json/mqtt/ (proves egress to the meshtastic plugin). One publish,
# two subscribers, both started first so neither misses the message. -------
OUT_B="$WORKDIR/chat_b.out"
OUT_EGRESS="$WORKDIR/egress.out"
msub_bg "chat/b" "$OUT_B" PID_B
msub_bg "msh/US/2/json/mqtt/" "$OUT_EGRESS" PID_EGRESS
sleep 1  # let both subscribers finish their CONNECT/SUBSCRIBE handshake

PING="livetest ping $$"
mpub -t chat/a -m "$PING"

wait "$PID_B" || true
wait "$PID_EGRESS" || true

body_b="$(cat "$OUT_B" 2>/dev/null || true)"
if [ -n "$body_b" ] && [[ "$body_b" == "[MQTT-"* ]] && [[ "$body_b" == *"$PING"* ]]; then
  pass "mqtt-loopback: chat/a -> chat/b delivered with [MQTT- alias and ping text"
else
  fail "mqtt-loopback: chat/b did not receive '[MQTT-...] $PING' within ${WAIT_SECS}s (got: ${body_b:-<nothing>})"
fi

body_egress="$(cat "$OUT_EGRESS" 2>/dev/null || true)"
if [ -n "$body_egress" ] && [[ "$body_egress" == *"$PING"* ]]; then
  pass "mesh-egress: chat/a -> msh/US/2/json/mqtt/ downlink JSON carried the ping text"
else
  fail "mesh-egress: msh/US/2/json/mqtt/ did not receive a downlink JSON with '$PING' within ${WAIT_SECS}s (got: ${body_egress:-<nothing>})"
fi

# --- check 2: nodeless Meshtastic uplink -> chat/a (mesh-bridge target) ---
OUT_MESH="$WORKDIR/chat_a_mesh.out"
msub_bg "chat/a" "$OUT_MESH" PID_MESH
sleep 1

# Same shape as plugins/meshtastic/README.md's "Manual e2e smoke test", but
# with a live timestamp: switchyardd's dedup key includes it (see
# switchyardd/src/dedup.rs), so the README's literal example value would
# make every run after the first look like a resend of the same message
# and get silently dropped for up to dedup_ttl_secs (24h by default).
mesh_ts="$(date +%s)"
mpub -t 'msh/US/2/json/general/!12345678' \
  -m "{\"type\":\"text\",\"channel\":0,\"sender\":\"!12345678\",\"payload\":{\"text\":\"test\"},\"timestamp\":${mesh_ts}}"

wait "$PID_MESH" || true

body_mesh="$(cat "$OUT_MESH" 2>/dev/null || true)"
if [ -n "$body_mesh" ] && [[ "$body_mesh" == "[MESH-"* ]]; then
  pass "mesh-uplink: msh/US/2/json/general/!12345678 -> chat/a delivered with [MESH- alias"
else
  fail "mesh-uplink: chat/a did not receive a [MESH-...] message within ${WAIT_SECS}s (got: ${body_mesh:-<nothing>})"
fi

echo
if [ "$FAILED" -eq 0 ]; then
  echo "tier 0: all checks passed"
else
  echo "tier 0: one or more checks FAILED" >&2
fi
exit "$FAILED"
