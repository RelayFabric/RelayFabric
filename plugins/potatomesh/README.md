# relayfabric-potatomesh

Feeds a [PotatoMesh](https://github.com/l5yth/potato-mesh) community dashboard
from the Meshtastic MQTT JSON gateway stream. Ingest-only: it subscribes to the
same `<root>/2/json/#` topics the meshtastic plugin uses, maps
text/position/telemetry/nodeinfo events onto PotatoMesh's ingest contract
(`data/mesh_ingestor/CONTRACTS.md`, Apache-2.0), and POSTs them with a bearer
token. Routed `send` frames are rejected with `potatomesh is ingest-only`.

PotatoMesh's own ingestors attach to a radio directly (their project bans MQTT
by charter); this plugin fills the complementary niche — an operator already
running RelayFabric's MQTT JSON stream gets the community map/dashboard with no
extra radio connection.

## Install

```
pip install -r plugins/potatomesh/requirements.txt
```

## PotatoMesh setup

On the PotatoMesh instance, issue an API token for this feeder (see the
PotatoMesh docs for `API_TOKEN`). The plugin sends it as
`Authorization: Bearer <token>` on every POST.

## Daemon config

```yaml
plugins:
  potatomesh:
    enabled: true
    command: /path/to/RelayFabric/.venv/bin/python /path/to/RelayFabric/plugins/potatomesh/relayfabric-potatomesh
    config:
      broker: mqtt://127.0.0.1:1883
      topic_root: msh/US            # same values as the meshtastic plugin
      gateway_id: null              # null = accept all gateways; else filter by hex ID
      url: https://potato.example.org
      token: ${env:POTATOMESH_TOKEN}
```

## What gets posted

| MQTT JSON event | PotatoMesh route(s) |
|---|---|
| `text` | `POST /api/messages` (packet id, canonical `!%08x` ids, `^all` broadcast, channel name from the topic path, snr/rssi/hops) |
| `position` | `POST /api/positions` + a `POST /api/nodes` upsert (lat/lon ×1e-7; the contract's `(0,0)`/`time<=0` GPS sentinels stripped at source) |
| `telemetry` | `POST /api/telemetry` (device/environment/air-quality/power metrics on an allowlist) + a nodes upsert when device metrics are present |
| `nodeinfo` | `POST /api/nodes` (names; aggregated in-memory with last position/metrics) |

Every record is stamped `protocol: "meshtastic"` and `ingestor: <gateway id>`.

## Limitations

- **Best-effort delivery.** HTTP failures are logged and counted (see the
  `posted` / `http_failures` gauges), never retried — node and position rows
  are re-upserted by the next beacon anyway.
- **No hardware/role names.** The JSON stream carries firmware enum *codes*
  for `hardware` and `role`; mapping them to the contract's name strings
  would need the GPL protobuf enum tables, so these optional fields are
  omitted.
- **No passive-UDP mode.** Meshtastic's LAN multicast carries protobuf-encoded,
  PSK-encrypted packets; decoding needs the GPL protobufs. Deliberately not
  implemented — the MQTT JSON stream is the license-clean interface.
- The node aggregate is in-memory: after a restart, node rows rebuild as
  beacons arrive (PotatoMesh keeps its own history regardless).
