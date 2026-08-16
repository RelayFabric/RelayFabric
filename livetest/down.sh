#!/usr/bin/env bash
# Stops a RelayFabric live-test session started by up.sh: switchyardd first,
# then the broker it started (if any). Leaves run/data intact so queue.db,
# attachments, the alias key, and logs survive for inspection.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$SCRIPT_DIR/run"

SWITCHYARDD_PID_FILE="$RUN_DIR/switchyardd.pid"
MOSQUITTO_PID_FILE="$RUN_DIR/mosquitto.pid"
BROKER_KIND_FILE="$RUN_DIR/broker.kind"
DOCKER_BROKER_NAME="relayfabric-livetest-broker"

stop_pid_file() {
  # $1: human-readable name, $2: pid file path.
  local name="$1" pid_file="$2" pid waited
  if [ ! -f "$pid_file" ]; then
    echo "  $name: no pid file, nothing to do"
    return 0
  fi
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    echo "  $name: pid file present but process not running"
    rm -f "$pid_file"
    return 0
  fi

  echo "  $name: stopping pid $pid (TERM)"
  kill "$pid" 2>/dev/null || true
  waited=0
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 3 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "  $name: still up after 3s, sending KILL"
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$pid_file"
}

stop_docker_broker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "  mosquitto (docker): docker not on PATH, nothing to do"
    return 0
  fi
  if docker inspect "$DOCKER_BROKER_NAME" >/dev/null 2>&1; then
    echo "  mosquitto (docker): removing container $DOCKER_BROKER_NAME"
    docker rm -f "$DOCKER_BROKER_NAME" >/dev/null 2>&1 || true
  else
    echo "  mosquitto (docker): container already gone"
  fi
}

echo "== stopping live-test session =="
stop_pid_file "switchyardd" "$SWITCHYARDD_PID_FILE"

broker_kind="$(cat "$BROKER_KIND_FILE" 2>/dev/null || true)"
if [ "$broker_kind" = "docker" ]; then
  stop_docker_broker
else
  # covers "native" and the missing/stale-file case: a leftover mosquitto
  # pid file from a native run is still safe (and useful) to check.
  stop_pid_file "mosquitto" "$MOSQUITTO_PID_FILE"
fi
rm -f "$BROKER_KIND_FILE"

echo
echo "run/data left intact (queue db, attachments, alias key, logs)."
echo "For a full reset: rm -rf \"$RUN_DIR\""
