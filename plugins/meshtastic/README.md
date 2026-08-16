# relayfabric-meshtastic

Bridges Meshtastic devices into RelayFabric as a Plugin Protocol v1 plugin. Each
configured channel maps to a RelayFabric channel: text uplinks from the device's
MQTT JSON stream land on the channel, and messages sent to the channel are delivered
back over MQTT (one topic per Meshtastic channel, fan-out via daemon routing).

Meshtastic's official Python/protobuf libraries are GPL; this plugin uses the device's
native MQTT JSON integration instead, which the node operator controls independently.

## Install

```
pip install -r plugins/meshtastic/requirements.txt
```

## Node setup

Enable MQTT JSON on the Meshtastic device (these run on the **operator's machine** with the
GPL CLI — the gateway only consumes the MQTT stream):

```
meshtastic --set mqtt.enabled true
meshtastic --set mqtt.json_enabled true
meshtastic --set mqtt.address <broker>:<port>
meshtastic --ch-set downlink_enabled true --ch-index <n>  # for each channel
```

## Daemon config

Point `command` at the venv's Python and script absolute path after
`pip install -r plugins/meshtastic/requirements.txt` into the venv:

```yaml
plugins:
  meshtastic:
    enabled: true
    command: /path/to/RelayFabric/.venv/bin/python /path/to/RelayFabric/plugins/meshtastic/relayfabric-meshtastic
    config:
      broker: mqtt://127.0.0.1:1883
      topic_root: msh/2/json
      gateway_id: null                # null = accept all gateways; set to filter by hex ID
      max_text_bytes: 200             # daemon truncates upstream text
      channels:
        zone1: {index: 0, topic_channel: "general"}
        zone2: {index: 1, topic_channel: "tactics"}
```

## Loop guard

The plugin uses SentCache (message deduplication by sender + ID) to break MQTT→Meshtastic→MQTT
loops. Caveat: distinguishing inbound from outbound uses MQTT topic structure, not a
sync marker — if uplink JSON reaches the daemon via a bridging route, loops could re-engage.

## Manual e2e smoke test (nodeless)

Without a Meshtastic device, test the config and uplink parsing:

1. Start the daemon with Meshtastic config.
2. Publish a crafted uplink to the broker:

```
mosquitto_pub -h 127.0.0.1 -t msh/2/json/zone1/\!12345678 \
  -m '{"type":"text","channel":0,"sender":"!12345678","payload":{"text":"test"},"timestamp":1692000000}'
```

3. The message should appear on the RelayFabric channel if routes are configured;
   verify with `switchyardctl queue` or a bridging subscription.
