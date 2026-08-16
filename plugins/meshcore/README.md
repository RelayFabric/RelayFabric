# relayfabric-meshcore

Bridges MeshCore (Companion Radio Protocol) devices into RelayFabric as a
Plugin Protocol v1 plugin. Each configured channel maps to a RelayFabric
channel: text uplinks land on the channel, and sent messages are delivered back
over the radio. Uses the native MeshCore library (2.3.8, MIT) — spec §8's
preferred Companion Radio Protocol backend, without an intermediary broker.

## Install

```
pip install -r plugins/meshcore/requirements.txt
```

## Connection

Companion-mode firmware required. Supported: `serial://<path>[?baud=N]`,
`tcp://host:port`, `ble://<addr>` (best-effort, untested).

## Daemon config

```yaml
plugins:
  meshcore:
    enabled: true
    command: /path/to/RelayFabric/.venv/bin/python /path/to/RelayFabric/plugins/meshcore/relayfabric-meshcore
    config:
      connection: serial:///dev/ttyUSB0
      max_text_bytes: 160
      channels:
        primary: {index: 0}
        secondary: {index: 1}
```

## Sender identity: channel-scoped

**Critical:** MeshCore PSK channels carry no per-node identity. The plugin keys
sender on channel index (`mc:channel:<idx>`), so all messages on a channel map
to the same sender.

**Consequence 1:** daemon rate limits and aliases operate at CHANNEL granularity
(one alias per channel, quotas shared by all participants). Size `per_sender`
limits accordingly and lean on per-route and global queue caps for
meshcore-heavy nodes.

**Consequence 2:** protocol-level moderation per-user impossible: muting or
rate-limiting one user on a meshcore channel affects all users on that channel.

## Loop guard

Consume-on-match cache keyed on `(channel, text)` breaks the radio→daemon→radio
loop: successful downlink records the pair for 1 hour, dropping the next
matching uplink. Caveat: a genuine uplink with text identical to a recent send
can also be swallowed — at most once per send, within 1 hour.

## Known field-test risks

- Library API exercised only against fakes — verify one end-to-end send on
  hardware.
- Alias prefix collision with Meshtastic: both protocols alias as MESH-XXXX
  (first 4 protocol-name chars); cosmetic, aliases remain distinct per sender.
- Some firmware validates downlink `from`; plugin always sends `from: 0`.
- Timestamp (`ts`) units assumed to be epoch seconds.
