# Example configs

Task-oriented starting points under [`examples/`](https://github.com/RelayFabric/RelayFabric/tree/main/examples).
Each is a **minimal, valid** config for one scenario — copy it, edit the few
fields the header calls out (data_dir, plugin command paths, addresses), and
validate:

```bash
switchyardd --config examples/<name>.yaml --check-config
```

Every file here is checked by CI (`switchyardd --check-config` parity), so a
copied example is always a valid starting point. For the exhaustive,
fully-annotated reference see [`relayfabric.example.yaml`](relayfabric.example.yaml);
for a blank scaffold use `switchyardd init` or the web UI's **Starter
template** button.

| Recipe | Scenario |
|---|---|
| [`meshtastic-lxmf.yaml`](https://github.com/RelayFabric/RelayFabric/blob/main/examples/meshtastic-lxmf.yaml) | Bridge a Meshtastic LoRa mesh (via its MQTT-JSON gateway) to Reticulum/LXMF, both directions. The flagship mesh↔Reticulum case. |
| [`meshtastic-direct.yaml`](https://github.com/RelayFabric/RelayFabric/blob/main/examples/meshtastic-direct.yaml) | Same bridge, but talking to the radio **directly** over serial/TCP/BLE — no MQTT broker. Simplest bench setup (GPL-3.0 plugin). |
| [`mqtt-signal.yaml`](https://github.com/RelayFabric/RelayFabric/blob/main/examples/mqtt-signal.yaml) | Bridge an MQTT topic to a Signal group/thread via the signal-cli sidecar. |
| [`multi-network-hub.yaml`](https://github.com/RelayFabric/RelayFabric/blob/main/examples/multi-network-hub.yaml) | A hub fanning several plugins into shared routes — MQTT↔Nostr cross-post, both mirrored one-way into LXMF. Shows real route wiring and deny-by-default. |
| [`public-federation-node.yaml`](https://github.com/RelayFabric/RelayFabric/blob/main/examples/public-federation-node.yaml) | A public node that advertises services and accepts traffic from trusted federation peers into a local LXMF channel. Shows `node.public` + `public_services` + `limits` + `federation`. |
| [`node-red.yaml`](https://github.com/RelayFabric/RelayFabric/blob/main/examples/node-red.yaml) | Automate RelayFabric from [Node-RED](https://nodered.org/) via MQTT — flows inject into and react to the fabric. See below. |
| [`meshtripwire.yaml`](https://github.com/RelayFabric/RelayFabric/blob/main/examples/meshtripwire.yaml) | Relay [meshtripwire](https://github.com/OutandBack/meshtripwire) tripwire alerts off-grid — its MQTT alert topic fanned into LXMF **and** a Meshtastic channel, no custom code. See below. |

## Node-RED automation (via MQTT)

Node-RED isn't a network RelayFabric bridges — it's a flow automation
runtime, and a **consumer/producer** of messages. Because it speaks MQTT
natively, it plugs straight into the `mqtt` plugin with **no custom code**:

```
Node-RED  ⇄  MQTT broker  ⇄  RelayFabric (mqtt plugin)  ⇄  mesh / XMPP / Signal / …
```

Using [`node-red.yaml`](https://github.com/RelayFabric/RelayFabric/blob/main/examples/node-red.yaml)
against the same broker Node-RED connects to:

- **Inject into the fabric** — wire an **`mqtt out`** node publishing to
  `relayfabric/in`. Its payload is routed on into LXMF (or any destination
  your routes name). Drive it from an `inject`, an `http in`, a schedule, a
  sensor — any Node-RED flow.
- **React to the fabric** — wire an **`mqtt in`** node subscribed to
  `relayfabric/out`; every message RelayFabric routes there fires your flow
  (dashboards, notifications, HTTP calls, home automation, …).

This is the supported way to use Node-RED with RelayFabric. RelayFabric's
admin API is deliberately read/control only — message **ingress is via
plugins**, so MQTT (which Node-RED already speaks) is the injection path. For
read-only observability you can also point a Node-RED flow at the admin
`GET /v1/events` SSE stream and `GET /v1/queue`.

## meshtripwire alerts, off-grid (via MQTT)

[meshtripwire](https://github.com/OutandBack/meshtripwire) is a wireless
tripwire: sensor nodes detect unknown WiFi/BLE MACs and its base station
alerts on them — but only via ntfy, webhook, or Twilio SMS, all of which need
the Internet the remote site doesn't have. Enable meshtripwire's MQTT alert
output (`[Notifications] EnableMqtt`) and it publishes each alert to a broker
topic; from there RelayFabric carries it somewhere that works with no cellular:

```
meshtripwire base station  ──MQTT──▶  RelayFabric  ──▶  LXMF/Reticulum + Meshtastic
```

[`meshtripwire.yaml`](https://github.com/RelayFabric/RelayFabric/blob/main/examples/meshtripwire.yaml)
does this with the **generic `mqtt` plugin** — the alert topic fanned one-way
into an LXMF channel and a Meshtastic channel, no custom code. Drop the
`meshtastic` plugin and its route for LXMF-only delivery.

For a **formatted** alert line (emoji, RSSI, a maps link from the GPS fix) and
a dedicated `meshtripwire:` endpoint, use the
[`meshtripwire` plugin](plugins.md#meshtripwire) instead — it parses the JSON
alert rather than relaying it raw. meshtripwire owns rate-limiting either way
(its `AlertCooldownSeconds`).

See also [Configuration](configuration.md), [Plugins](plugins.md), and
[Live & Field Testing](live-testing.md).
