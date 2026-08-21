# Live-Test Plan — Full-Hardware Interop Validation

**Goal:** close the two pending [interop-matrix](../docs/interop-matrix.md)
cells (C-1 MeshCore hardware, C-2 Meshtastic real downlink) with signed-off
evidence, upgrade LXMF to real-RF, and give Nostr its first live-relay
validation. Matrix-closure-first: each network validated in isolation
against `mqtt:chat/a`, then an optional grand-tour demo.

**Setup (decided 2026-08-20):** one Linux host runs `switchyardd`, the MQTT
broker, and `signal-cli`; all radios attach over USB. The RNode is the
gateway's **own** Reticulum interface (real LoRa RF for LXMF). A Meshtastic
node is already configured as an MQTT-JSON uplink gateway.

## Inventory → coverage

| Hardware | Tier | Closes / proves |
|---|---|---|
| 1× RNode LoRa | 1 | LXMF over **real LoRa RF** (gateway's own RNodeInterface) — upgrade from the TCP-backbone field test |
| 2× Meshtastic | 3 | **Matrix C-2** — real RF inbound + real **downlink transmit** (`from:0` firmware check) + round-trip |
| 1× MeshCore | 4 | **Matrix C-1** — inbound/outbound/round-trip over the companion serial protocol |
| Signal account | 2 | Signal end-to-end re-validation |
| Nostr account | 5 | **First live-relay validation** (matrix had fake-tests only) |

## Pre-flight (once)

```
cargo build -j2 --release
python3 -m venv .venv
# per-tier deps installed as each tier is reached
ls /dev/ttyUSB* /dev/ttyACM*   # identify each radio's serial path
```

Note each radio's stable path (prefer `/dev/serial/by-id/...` — USB
enumeration order isn't stable across replug). You'll paste them into the
config per tier.

## Tier 0 — MQTT loopback (sanity, no radio)

```
livetest/up.sh
livetest/tier0.sh
```

Proves the fabric routes and the harness works before any RF is involved.
Expect the three `[PASS]` lines from the README. Leave this passing before
moving on.

## Tier 1 — LXMF over real LoRa RF (RNode)

The RNode is the gateway's Reticulum interface, so LXMF messages ride
actual LoRa.

1. `.venv/bin/pip install -r plugins/lxmf/requirements.txt`
2. Give the gateway a Reticulum config with an RNodeInterface. Create
   `livetest/run/data/reticulum/config`:
   ```
   [reticulum]
     enable_transport = No
     share_instance = Yes
   [interfaces]
     [[RNode LoRa]]
       type = RNodeInterface
       interface_enabled = True
       port = /dev/serial/by-id/<your-rnode>
       frequency = 914500000     # your band plan
       bandwidth = 125000
       spreadingfactor = 8
       codingrate = 5
       txpower = 17
   ```
   Then set `plugins.lxmf.config.rns_configdir:
   __REPO__/livetest/run/data/reticulum` in `config.template.yaml`.
3. Flip `plugins.lxmf.enabled: true` and uncomment the `lxmf-bridge` route.
4. `livetest/down.sh && livetest/up.sh`; watch `run/switchyardd.log` for
   `Gateway LXMF address: <hash>` and the RNode interface coming up.
5. From a second Reticulum/LXMF client (Sideband on a phone with its own
   RNode, or another RNode node in RF range), message the gateway address:
   `/join livetest`, then a text.

**Pass:** the RF-delivered LXMF text arrives on `mqtt:chat/a` tagged
`[LXMF-…]`; a `mosquitto_pub` on `chat/a` is delivered back to the client
over RF. Confirms LXMF inbound/outbound/round-trip and reconnect over real
LoRa (matrix LXMF row, now RF-backed).

## Tier 2 — Signal

Per the README tier 2: register/link `signal-cli`, start its daemon, set
`account`/`groups`, flip `signal.enabled: true`, uncomment `signal-bridge`.
**Pass:** a Signal group message lands on `chat/a` tagged `[SIG-…]`, and a
`chat/a` publish arrives in the Signal group. Re-validates the Signal row.

## Tier 3 — Meshtastic real hardware (closes C-2)

Two nodes: **node A** already uplinks MQTT JSON to the broker; **node B** is
a plain RF node in range of A. The `meshtastic` plugin is already enabled
(tier 0) — point `topic_root`/`channels` at node A's real topic (verify
with `mosquitto_sub -t 'msh/#' -v`).

1. **Inbound:** send a text from node B on the shared channel. It reaches A
   over RF, A uplinks JSON, the plugin bridges it. **Pass:** arrives on
   `chat/a` tagged `[MESH-…]`.
2. **Downlink (the C-2 risk):** `mosquitto_pub` on `chat/a`. The plugin
   publishes a downlink; node A must **actually transmit it over RF** and
   node B must receive it. The plugin always sends `from:0` and some
   firmware validates that field — `delivered:true` only means the broker
   accepted the publish. **Pass = node B physically shows the message.**
   Test once per firmware version in use.

Closes **C-2** (real-node downlink) and the Meshtastic replies/round-trip
cells.

## Tier 4 — MeshCore serial (closes C-1)

1. `.venv/bin/pip install -r plugins/meshcore/requirements.txt`
2. Attach the companion radio; set `plugins.meshcore.config.connection:
   serial:///dev/serial/by-id/<your-meshcore>`.
3. Flip `meshcore.enabled: true`, uncomment `meshcore-bridge`,
   `down.sh && up.sh`.
4. From another MeshCore node on the same PSK channel, send a text.

**Pass:** inbound MeshCore text arrives on `chat/a` tagged `[MC-…]`; a
`chat/a` publish is transmitted and received on the other MeshCore node;
round-trip works. Note the plugin keys sender on channel index
(`mc:channel:<idx>`) — all senders on a channel share one alias, expected.
Closes **C-1**.

## Tier 5 — Nostr live relay (first live validation)

1. `.venv/bin/pip install -r plugins/nostr/requirements.txt`
2. Point `relays` at a real relay you can reach (template defaults to
   `wss://relay.damus.io`). The `relayfabric-livetest` tag keeps the test
   off general feeds.
3. Flip `nostr.enabled: true`, uncomment `nostr-bridge`, `down.sh && up.sh`.
   The gateway's npub logs once at startup.
4. From any Nostr client, publish a kind-1 note tagged `t: relayfabric-livetest`.

**Pass:** the note arrives on `chat/a` tagged `[NOSTR-…]` (proving the
sig-verify-before-bridge path against a live relay); a `chat/a` publish
appears on the relay under the gateway's npub with the livetest tag.
Upgrades the Nostr row from fake-tested to live.

## Tier 6 — Grand tour (optional demo)

After every cell is closed, add one fan-out route:
`sources: ["meshtastic:mesh"]`, `destinations: ["lxmf:livetest",
"signal:livetest", "nostr:livetest"]`. Send one Meshtastic RF message and
watch it surface on LXMF, Signal, and Nostr at once — the intermesh
headline. Note transport-class egress will cap/demote per destination.

## Recording results

For each tier, capture the `[PASS]`/observed evidence and update the
matching cell in [`docs/interop-matrix.md`](../docs/interop-matrix.md):
C-1 and C-2 move from ⏳ to 🌐, the Nostr row's "live pending" clears, and
the LXMF row gains the real-RF note. Keep `run/switchyardd.log` per tier as
the artifact.

## Teardown

`livetest/down.sh` between tiers (config changes aren't hot-reloaded for
plugin enable/disable). Radios can stay attached; the daemon re-opens them
on the next `up.sh`.
