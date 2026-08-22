# relayfabric-meshtastic-direct

Bridges Meshtastic devices into RelayFabric **directly over the device API**
(serial / TCP / BLE), using the official `meshtastic` Python library.

> ## ⚠️ Licensing: this plugin is GPL-3.0
> Unlike the rest of RelayFabric (Apache-2.0), this plugin is
> **GPL-3.0-or-later** (see [`LICENSE`](LICENSE)) because it imports the
> GPL-3.0 `meshtastic` library — the whole Meshtastic library ecosystem,
> and the protobuf definitions behind it, are GPL. The copyleft is isolated
> to this plugin's own process: it talks to the daemon only over the
> Apache-2.0 CBOR IPC and depends on the Apache-2.0 `relayfabric_sdk`, so
> `switchyardd` and every other component stay Apache-2.0. This is the same
> out-of-process GPL isolation the signal-cli sidecar uses — only here the
> GPL code runs inside RelayFabric's own (separately-licensed) plugin.

## Direct vs. the MQTT plugin — pick one

RelayFabric ships **two** Meshtastic plugins; run whichever suits you:

| | `meshtastic` (Apache-2.0) | `meshtastic-direct` (GPL-3.0) |
|---|---|---|
| License | permissive | GPL-3.0 (via the meshtastic lib) |
| Transport | node's MQTT-JSON gateway → broker | serial / TCP / BLE straight to the radio |
| MQTT broker | required | **not needed** |
| Downlink | sends `from: 0` (some firmware rejects — verify) | sends as the node's **own** identity; no `from:0` issue |
| Sender identity | from the JSON stream | real per-node `fromId` |
| Data | JSON-serialized subset | full protobuf packet |
| Direct messages | channel-only | **DMs supported** (`direct_messages`) |

The direct plugin removes the broker, fixes the downlink-`from:0` risk, and
surfaces real node identities — at the cost of the GPL dependency. The MQTT
plugin stays the permissive default.

## Install

```
pip install -r plugins/meshtastic-direct/requirements.txt
```

## Node setup

None beyond attaching the radio — no MQTT configuration required. Plug the
device in over USB (serial), or reach it over TCP/BLE.

## Daemon config

```yaml
plugins:
  meshtastic-direct:
    enabled: true
    command: /path/to/RelayFabric/.venv/bin/python /path/to/RelayFabric/plugins/meshtastic-direct/relayfabric-meshtastic-direct
    config:
      connection: serial:///dev/ttyUSB0   # or tcp://host[:4403], ble://<addr>
      max_text_bytes: 200
      channels:
        mesh: {index: 0}
        tac:  {index: 1}
```

Each channel maps a Meshtastic channel index to a RelayFabric endpoint. A
loop guard drops the node's re-broadcast of our own downlinks (1h window on
`(channel, text)`).

## Limitations

- **Text only** — the constrained-LoRa transport class caps payloads
  (~237 B) and demotes media to a note at egress, same as the MQTT plugin.
- **Channels + direct messages** — bridges channel broadcasts, and (via
  the `direct_messages` capability) delivers a direct message to a node's
  own identity and bridges the reply back. This is what enables
  **identity-linking**: the daemon sends a challenge DM through this plugin
  and matches the reply. An inbound DM is presented on a synthetic
  `direct:<sender>` endpoint, so a non-challenge DM matches no route and is
  dropped by deny-by-default rather than leaking onto a channel.
- Do not run both Meshtastic plugins against the same radio.
