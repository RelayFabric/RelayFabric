# RelayFabric live-test kit

A copy-paste runbook for the four-tier live-testing ladder: MQTT loopback,
then LXMF, then Signal, then real Meshtastic hardware. Each tier adds one
more moving part on top of the last.

## Prerequisites

| Tier | Needs |
| --- | --- |
| 0 (MQTT + nodeless Meshtastic) | `cargo build -j2 --release`; `.venv` with `pip install -r plugins/meshtastic/requirements.txt`; `mosquitto` + `mosquitto-clients`, OR Docker (up.sh runs `eclipse-mosquitto:2` in a container and tier0.sh execs its clients if the native ones aren't found) |
| 1 (LXMF) | `.venv` with `pip install -r plugins/lxmf/requirements.txt`; Sideband (or another Reticulum/LXMF client) reachable over Reticulum |
| 2 (Signal) | `.venv` with `pip install -r plugins/signal/requirements.txt`; `signal-cli` registered or linked |
| 3 (Meshtastic hardware) | A Meshtastic node with MQTT uplink support; the `meshtastic` CLI on the node operator's machine |

`up.sh` checks the tier-0 items itself and tells you what's missing.

## Tier 0: MQTT loopback + nodeless Meshtastic

```
livetest/up.sh
livetest/tier0.sh
```

`up.sh` renders `config.template.yaml` into `run/config.yaml` (filling in
the repo path and MQTT port), validates it with `--check-config`, starts
mosquitto (unless `--no-broker`, or one's already listening), starts
`switchyardd`, and waits for its sockets. Default port 18883; `--port N`
if that's taken. Expect a `== status ==` JSON block and a `next: tier 0`
hint at the end.

`tier0.sh` publishes a probe on `chat/a` and asserts it arrives on
`chat/b` tagged `[MQTT-xxxx]`, and *also* as a downlink JSON on
`msh/US/2/json/mqtt/` (the `mesh-bridge` route sends it both places).
Then it publishes a crafted Meshtastic uplink to
`msh/US/2/json/general/!12345678` and asserts it arrives on `chat/a`
tagged `[MESH-xxxx]` — no radio required. Expect:

```
[PASS] mqtt-loopback: chat/a -> chat/b delivered with [MQTT- alias and ping text
[PASS] mesh-egress: chat/a -> msh/US/2/json/mqtt/ downlink JSON carried the ping text
[PASS] mesh-uplink: msh/US/2/json/general/!12345678 -> chat/a delivered with [MESH- alias
tier 0: all checks passed
```

If neither mosquitto nor Docker is available, `up.sh` prints an install
hint and starts the daemon anyway; `tier0.sh` then fails its precondition
check with a message telling you to install and start a broker.

## Tier 1: LXMF (Sideband)

1. `.venv/bin/pip install -r plugins/lxmf/requirements.txt`
2. In `config.template.yaml`, flip `plugins.lxmf.enabled` to `true`, then
   uncomment the `lxmf-bridge` route (a route to a disabled plugin fails
   `--check-config`, so the plugin must go live first).
3. Re-run `up.sh` (not a hot-reload: `down.sh` then `up.sh` is safest).
4. Watch `run/switchyardd.log` for `Gateway LXMF address: <hash>`.
5. Add that address as a Sideband contact and message it: `/join livetest`
   first if needed (the template's channel ships `open: true`, so a plain
   message should also just land).
6. Expect it on `chat/a` (via `lxmf-bridge`); route a reply back to the
   channel and expect it in Sideband as `[LXMF-xxxxxxxx] ...`.

See `plugins/lxmf/README.md` for the full config reference and attachments.

## Tier 2: Signal

1. `.venv/bin/pip install -r plugins/signal/requirements.txt`
2. Register or link an account, start its daemon:
   `signal-cli -a +1XXXXXXXXXX daemon --http 127.0.0.1:7583`
3. `signal-cli -a +1XXXXXXXXXX listGroups` and note the group id to bridge.
4. In the template, set `account` and `groups.livetest` to your real
   number and group id, flip `plugins.signal.enabled` to `true`, and
   uncomment the `signal-bridge` route.
5. Re-run `up.sh`. Message the group from a member; expect it on
   `chat/a`. Route a reply back to the channel; expect it in the group.

See `plugins/signal/README.md` for linked-account caveats and attachments.

## Tier 3: Meshtastic hardware

Swap tier 0's `mosquitto_pub` for a real device. On the node operator's
machine (GPL `meshtastic` CLI — the gateway itself never touches it):

```
meshtastic --set mqtt.enabled true
meshtastic --set mqtt.json_enabled true
meshtastic --set mqtt.address 127.0.0.1:<port up.sh printed>
meshtastic --ch-set downlink_enabled true --ch-index 0
```

Verify the node's real topic root before trusting `topic_root: msh/US` —
region and MQTT username vary by deployment:
`mosquitto_sub -h 127.0.0.1 -p <port> -t 'msh/#' -v`. Update
`topic_root` to match, re-run `up.sh`, send a text on the mapped channel
from the device and confirm it lands on `chat/a`, then reply and confirm
it reaches the device. Before trusting this in the field, work through
`plugins/meshtastic/README.md`'s "Known field-test risks" checklist
(downlink `from` field validation, timestamp units, the loop-guard's
one-message blind spot).

## Observability

```
target/release/switchyardctl --socket livetest/run/data/admin.sock status
target/release/switchyardctl --socket livetest/run/data/admin.sock plugins
target/release/switchyardctl --socket livetest/run/data/admin.sock queue
target/release/switchyardctl --socket livetest/run/data/admin.sock trace <message-id>
curl --unix-socket livetest/run/data/admin.sock http://localhost/metrics
```

## Teardown

`livetest/down.sh` stops `switchyardd` and any mosquitto `up.sh` started
(graceful, then force after 3s), leaving `run/data` in place so the queue
db, attachments, and logs are still there to inspect. For a full reset,
including the alias key and rendered config: `rm -rf livetest/run`.
