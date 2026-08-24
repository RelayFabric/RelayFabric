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

See also [Configuration](configuration.md), [Plugins](plugins.md), and
[Live & Field Testing](live-testing.md).
