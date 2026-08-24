# Live & Field Testing

RelayFabric ships a copy-paste live-test kit under `livetest/`, and this page adds field-tested recipes for the two setups that involve real radios: **LXMF over a real Reticulum network** and **bridging a Meshtastic mesh to LXMF**. These were validated against a live Reticulum backbone and a real Los Angeles Meshtastic mesh; the caveats below are the ones real hardware actually surfaces.

## The live-test ladder

`livetest/` is a four-tier runbook (see `livetest/README.md`), each tier adding one moving part:

| Tier | Exercises | Needs |
|---|---|---|
| 0 | MQTT loopback + nodeless Meshtastic | `mosquitto` or Docker |
| 1 | LXMF / Reticulum | a Reticulum/LXMF peer reachable over RNS |
| 2 | Signal | a registered/linked `signal-cli` |
| 3 | Meshtastic hardware | a Meshtastic node with an MQTT uplink |

`livetest/up.sh` renders `config.template.yaml`, starts a broker and the daemon, and waits for its sockets; `livetest/tier0.sh` asserts the loopback and nodeless-Meshtastic paths. Tear down with `livetest/down.sh`.

## Tier 1: LXMF over real Reticulum

The LXMF plugin rides Reticulum (RNS). Point it at an RNS configuration that reaches your target network: a TCP backbone interface, a LoRa RNode, or both.

### An RNS configuration

Give the LXMF plugin its own RNS config directory and reference it from the plugin's `rns_configdir`. A minimal backbone-only config:

```ini
[reticulum]
  enable_transport = False
  share_instance = Yes

[logging]
  loglevel = 5

[interfaces]
  [[Backbone TCP]]
    type = TCPClientInterface
    enabled = Yes
    target_host = rns.example.net
    target_port = 4242
```

Verify connectivity before wiring the daemon. Bring up the instance and confirm the link and a path to your peer:

```bash
rnsd --config <configdir>
rnstatus --config <configdir>          # interface Up, traffic flowing
rnpath  --config <configdir> <peer-lxmf-hash>   # "Path found … N hops"
```

### The LXMF plugin

```yaml
plugins:
  lxmf:
    enabled: true
    command: /path/.venv/bin/python /path/plugins/lxmf/relayfabric-lxmf
    config:
      display_name: "RelayFabric Gateway"
      storage: /path/livetest/run/data/lxmf
      rns_configdir: /path/livetest/run/reticulum   # the config above
      channels:
        - name: livetest
          members: ["<peer-lxmf-destination-hash>"]  # who this channel talks to
          open: true
```

On startup the plugin logs its own address once (`Gateway LXMF address: <hash>`), which is what remote peers send *to*. Route a source into `lxmf:livetest` and messages egress to the channel's members over Reticulum.

!!! tip "See the plugin's logs"
    Python block-buffers stdout when it is a pipe, so a plugin's `RNS.log` diagnostics can be invisible in the daemon log. RelayFabric now spawns plugins with `PYTHONUNBUFFERED=1` so these surface live. Watch the daemon log for the gateway address, delivery, and path lines.

### Delivery semantics on high-latency links

Over a multi-hop Reticulum path the recipient's **delivery proof** can time out even though the message arrived. RelayFabric handles this so it does not turn a delivered message into a retry storm:

- **Idempotency**: at most one in-flight LXMF message per delivery; a store-and-forward re-dispatch never re-sends a duplicate.
- **Graceful fallback**: a DIRECT proof-timeout to a *reachable* destination is recorded delivered (the recipient almost certainly received it), not failed. A genuinely unreachable destination is a real failure and retries.

A healthy send shows `state: delivered, attempts: 1` in `switchyardctl trace <id>`.

## RNodes as an RNS interface

A LoRa RNode extends the same RNS instance onto the air. Two things bite in practice:

!!! warning "Use `RNodeInterface`, not `SerialInterface`"
    A stock RNode runs in **host-controlled** mode: RNS programs the radio over serial. That requires the `RNodeInterface` type, which takes the LoRa parameters; a plain `SerialInterface` opens the port but never keys the radio (you see bytes leave but nothing return). Confirm the device with `rnodeconf --info /dev/ttyUSB0`: "Device mode: Normal (host-controlled)".

```ini
  [[RNode LoRa]]
    type = RNodeInterface
    enabled = Yes
    port = /dev/ttyUSB0
    frequency = 915000000    # Hz — must be legal for your region and match the network
    bandwidth = 125000
    spreadingfactor = 8
    codingrate = 5
    txpower = 17             # dBm
```

The RF parameters must match the network you intend to reach; do not guess frequency or power. A correctly configured interface reports live radio telemetry in `rnstatus` (on-air bitrate, noise floor, CPU temperature).

!!! danger "Co-located radios desense each other"
    Two LoRa radios inches apart on the same ISM band (say an RNode and a Meshtastic node both near 915 MHz) will jam each other's receivers whenever one transmits. If a nearby node "sees nothing," separate the antennas, drop TX power, or shift frequency, or simply disable the interface you are not testing.

## Bridging Meshtastic to LXMF

RelayFabric ships **two** Meshtastic plugins (see [Plugins](plugins.md#meshtastic-direct)). For a bench test the simplest is usually **`meshtastic-direct`**: it talks to the radio straight over serial/TCP/BLE with no broker and no proxy. Plug the node in over USB and set `connection: serial:///dev/ttyUSB0` (it was field-tested over BLE with channel + direct messages).

The recipe below instead uses the **`meshtastic` (MQTT-JSON)** plugin: it consumes the node's **MQTT JSON gateway**, so the node's traffic must reach an MQTT broker the plugin reads. Two ways in:

1. **WiFi + MQTT**: the node joins WiFi and connects to a broker on the LAN. Simple when it works; note the ESP32-S3 in a Heltec V3 is **2.4 GHz only**.
2. **USB MQTT client-proxy**: the node speaks MQTT over its USB link and a small relay forwards it to a local broker. No WiFi, no subnet, no firewall. This is the most reliable path for a bench setup.

### The USB client-proxy recipe

Configure the node (with the Meshtastic CLI) for client-proxy and JSON, WiFi off, and enable channel uplink/downlink:

```bash
meshtastic --port /dev/ttyUSB1 \
  --set mqtt.enabled true \
  --set mqtt.proxy_to_client_enabled true \
  --set mqtt.json_enabled true \
  --set mqtt.root msh/US \
  --set network.wifi_enabled false
meshtastic --port /dev/ttyUSB1 --ch-index 0 --ch-set uplink_enabled true --ch-set downlink_enabled true
```

Run a relay that holds the serial link, forwards the node's proxied MQTT to a local broker, and (optionally) feeds broker messages back to the node. The meshtastic Python library exposes the hooks: subscribe to the `meshtastic.mqttclientproxymessage` event and publish each to the broker; call `iface.sendMqttClientProxyMessage(topic, data)` for the reverse. The node then uplinks to topics like:

```
msh/US/2/json/LongFast/!<gateway-node-id>     # JSON — the plugin reads this
msh/US/2/e/LongFast/!<gateway-node-id>         # encrypted protobuf
```

!!! note "Uplink-only avoids loops"
    A relay that both publishes and subscribes on the same broker will loop the node's own messages back down. For a one-way mesh→bridge test, relay uplink only. For bidirectional, subscribe with MQTT v5 *No Local* so the relay never receives its own publishes.

### The daemon config

Match the plugin's topic to what the node publishes (`topic_root` + `topic_channel`), then route the mesh channel into an LXMF channel:

```yaml
plugins:
  meshtastic:
    enabled: true
    command: /path/.venv/bin/python /path/plugins/meshtastic/relayfabric-meshtastic
    config:
      broker: mqtt://127.0.0.1:1883
      topic_root: msh/US
      channels:
        mesh: {index: 0, topic_channel: "LongFast"}
  # ... lxmf plugin as above ...

routes:
  - name: mesh-to-lxmf
    sources: ["meshtastic:mesh"]
    destinations: ["lxmf:livetest"]
```

A text message on the mesh now flows: **Meshtastic node → MQTT proxy → broker → meshtastic plugin → `mesh-to-lxmf` route → LXMF plugin → Reticulum → peer.** Confirm with `switchyardctl trace <id>` (`route: mesh-to-lxmf`, `state: delivered`).

## Field lessons

- **Watch the plugin logs.** With `PYTHONUNBUFFERED=1` in place, the daemon log carries a plugin's RNS/MQTT diagnostics live: the fastest way to see whether a link is up.
- **Trust the daemon's accounting.** `switchyardctl trace` reports the authoritative per-destination state over IPC, independent of what a plugin prints.
- **Real networks catch what fakes cannot.** The high-latency proof-timeout behavior above was found on a live backbone; fake-backed tests never exercised the lost-return-proof path.
- **Physical reality needs tuning.** Antennas, placement, RF coexistence, and regional LoRa parameters are not something a config default can know. Leave the knobs and set them for the site.
