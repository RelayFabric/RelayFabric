# relayfabric-meshtripwire

Relays [meshtripwire](https://github.com/OutandBack/meshtripwire) tripwire
alerts into the fabric so they reach an **off-grid** destination —
LXMF/Reticulum or a Meshtastic channel — instead of relying on the Internet.

meshtripwire is a wireless tripwire: ESP32 sensor nodes detect unknown WiFi/BLE
MACs and relay them over LoRa to a base station whose monitor filters
(whitelist, RSSI floor, per-MAC cooldown) and alerts. Its built-in alert
channels — ntfy, webhook, Twilio SMS — all need the Internet, the opposite of
the remote/no-cellular sites it's designed for. Point meshtripwire's MQTT alert
output at a broker topic, and this plugin subscribes to it and emits each alert
inbound on one endpoint, which a route carries into Reticulum or a mesh.

Ingest-only: alerts flow one way (meshtripwire → fabric). Routed `send` frames
are rejected with `meshtripwire is ingest-only`. **Per-MAC rate limiting is
meshtripwire's job** (`AlertCooldownSeconds`), so this plugin does not duplicate
it — it forwards exactly the alerts meshtripwire decided to raise.

For the zero-plugin alternative — relay the alert topic with the generic `mqtt`
plugin — see [`examples/meshtripwire.yaml`](../../examples/meshtripwire.yaml).
This plugin adds a formatted alert line and a dedicated `meshtripwire:` endpoint.

## Install

```
pip install -r plugins/meshtripwire/requirements.txt
```

## meshtripwire setup

Enable meshtripwire's MQTT alert output so filtered alerts are published to the
broker (see meshtripwire's `config.ini` → `[Notifications] EnableMqtt` /
`MqttAlertTopic`). Point this plugin's `broker`/`topic` at the same broker and
topic.

## Daemon config

```yaml
plugins:
  meshtripwire:
    enabled: true
    command: /path/to/RelayFabric/.venv/bin/python /path/to/RelayFabric/plugins/meshtripwire/relayfabric-meshtripwire
    config:
      broker: mqtt://127.0.0.1:1883        # meshtripwire's broker
      topic: meshtripwire/alerts           # meshtripwire's MqttAlertTopic
      endpoint: alerts                      # inbound endpoint alerts appear on
```

Route the endpoint to wherever alerts should land:

```yaml
routes:
  - name: tripwire-to-reticulum
    sources: ["meshtripwire:alerts"]
    destinations: ["lxmf:security"]
```

## Payload formats

Accepts either format on the topic, so it works however meshtripwire is set up:

- **JSON alert** — `{mac, node, rssi, lat, lon, message}` → a formatted line,
  e.g. `⚠️ Unknown MAC AA:BB:CC:DD:EE:FF at node gate1 · RSSI -58 dBm` plus a
  Google Maps link when the payload carries a GPS fix.
- **Plain text** — a ready-made alert line is forwarded verbatim.

The sender is `meshtripwire:<node>` when the JSON names a node (so multiple
sensor nodes are distinguishable), else `meshtripwire`.

## Limitations

- **Ingest-only.** There is no reply path; `send` frames are rejected. Alerts
  are a one-way notification stream.
- **Deduplication is upstream.** meshtripwire's cooldown decides what's an
  alert; the plugin forwards each one. No extra suppression here.
- The inbound queue is bounded (256); if alerts ever outrun the daemon the
  oldest are dropped (logged). Alert volume is well below this in practice.
