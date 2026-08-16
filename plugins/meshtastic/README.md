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
      topic_root: msh/US              # your node's full root including region — verify with: mosquitto_sub -t 'msh/#' -v
      gateway_id: null                # null = accept all gateways; set to filter by hex ID
      max_text_bytes: 200             # daemon truncates upstream text
      channels:
        zone1: {index: 0, topic_channel: "general"}
        zone2: {index: 1, topic_channel: "tactics"}
```

Set `gateway_id` when more than one node on the mesh uplinks to this broker; otherwise each
message arrives once per gateway node (each with a different `sender`) — bounded duplicates,
not a loop.

## Loop guard

The plugin uses a consume-on-match cache keyed on `(channel, text)` to break the
MQTT→Meshtastic→MQTT loop: a successful downlink send records `(channel, text)` for 1 hour,
and the next matching uplink is dropped and removes the entry rather than being held for the
full TTL. Caveat: this key has no sender or message-ID component, so a genuine uplink whose
text is identical to something we just sent on that channel can also be swallowed — at most
once per send, and only within that 1 hour window.

## Known field-test risks

- Some firmware validates the downlink `from` field; this plugin always sends `from: 0`.
  Verify one downlink end-to-end on your firmware — `delivered: true` only means the broker
  accepted the publish, not that the node accepted or transmitted it.
- Timestamps (`payload.timestamp`) are assumed to already be epoch seconds.
- A lost echo (our downlink never re-uplinks, e.g. dropped over the air) leaves the loop-guard
  entry live until its 1 hour TTL, during which one identical genuine message can be swallowed.

## Manual e2e smoke test (nodeless)

Without a Meshtastic device, test the config and uplink parsing:

1. Start the daemon with Meshtastic config.
2. Publish a crafted uplink to the broker (note: the topic segment is the `topic_channel` name; the channel index comes from the JSON `channel` field):

```
mosquitto_pub -h 127.0.0.1 -t msh/US/2/json/general/\!12345678 \
  -m '{"type":"text","channel":0,"sender":"!12345678","payload":{"text":"test"},"timestamp":1692000000}'
```

3. The message should appear on the RelayFabric channel if routes are configured;
   verify with `switchyardctl queue` or a bridging subscription.
