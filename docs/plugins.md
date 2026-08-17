# Plugins

RelayFabric never speaks a native protocol itself. Each bridged network is
owned by a **plugin** — a separate process the `switchyardd` daemon spawns,
supervises, and talks to over a small IPC. This page covers the plugin
model shared by every bridge, then one section per shipped plugin: what
network it bridges, its config keys, its licensing posture, and (where the
plugin's own README documents them) known field-test risks. For the full
config schema see [Configuration](configuration.md); to write a new plugin,
see [Plugin Authoring](plugin-authors.md); for how these plugins were
exercised against real infrastructure, see
[Live & Field Testing](live-testing.md).

## The plugin model

**Separate, supervised processes.** A plugin is whatever the daemon's
`command:` spawns — a Rust binary, a Python script, anything that speaks
the wire protocol. The daemon restarts a plugin that dies unexpectedly with
bounded backoff (1s, 5s, 30s, 2m, ...); a plugin that keeps crashing is
marked unhealthy rather than restarted forever.

**CBOR-over-Unix-socket IPC.** The daemon spawns each plugin with
`RELAYFABRIC_SOCKET` (the Unix domain socket path), `RELAYFABRIC_PLUGIN_NAME`,
and `RELAYFABRIC_PLUGIN_CONFIG` (the plugin's `config:` block as JSON) in its
environment. Every frame on the socket is a 4-byte big-endian length prefix
followed by a CBOR body, with a `t` tag identifying the frame
(`hello`, `hello_ack`, `inbound`, `send`, `send_direct`, `delivery_result`,
`shutdown`). Wire bytes are golden-locked across implementations, so a Rust
plugin (`relay-core` + `relay-ipc`) and a Python plugin (`relayfabric_sdk`)
interoperate exactly.

**Capability advertisement (Hello).** Before anything else, a plugin sends
one `Hello { plugin, version, protocol_version, capabilities }` frame and
waits for `HelloAck`; a non-null `error` means the daemon rejected it and it
must exit rather than proceed. Capabilities (`text`, `direct_messages`,
`groups`, `attachments`, `location`, `reactions`, `receipts`, `presence`,
`max_payload`) aren't cosmetic — the daemon uses them to route and to gate
features. `direct_messages` in particular gates whether a plugin ever
receives a `send_direct` frame (used today for identity-link challenge
delivery).

**Deny-by-default.** A plugin only subscribes to, and only accepts sends
for, the channels/topics/filters explicitly present in its config —
unconfigured native traffic is never bridged. Several plugins add a second,
protocol-specific layer of this: Nostr and Bitchat recompute and verify
every inbound event's signature before bridging it, since a relay is
untrusted infrastructure.

**Content never logged.** Default daemon logs carry operational metadata
(message id, route, source protocol) and never message bodies — privacy
tests assert this holds even with linked identities and location data in
play.

---

## MQTT

The in-tree Rust reference plugin (`relayfabric-mqtt`), and also a useful
integration/testing transport in its own right (spec §8). Bridges arbitrary
MQTT topics over MQTT v5: each subscribed topic doubles as the fabric
endpoint name, and there is no separate channel-mapping layer — `topics`
*is* the config. Delivery results are reported only once the broker's QoS 1
PUBACK arrives, not merely on local enqueue. Loop prevention here is
transport-level: subscriptions set MQTT v5's `No Local` flag so the broker
never echoes the plugin's own publishes back to it.

| Key | Default | Notes |
|---|---|---|
| `broker` | — | `mqtt://host[:port]`; port defaults to `1883` |
| `topics` | `[]` | Topics to subscribe; each topic name is also the endpoint |
| `client_id` | `"relayfabric"` | MQTT client identifier |

```yaml
plugins:
  mqtt:
    enabled: true
    command: relayfabric-mqtt
    config:
      broker: mqtt://127.0.0.1:1883
      topics: [chat/a, chat/b]
```

!!! note "Licensing"
    Built on `rumqttc`, an MIT/Apache-2.0 async MQTT client. No GPL
    dependency in this plugin's path.

---

## LXMF

Bridges [LXMF](https://github.com/markqvist/LXMF) over Reticulum (RNS).
Each configured channel maps to a set of LXMF destination hashes
("members"): inbound messages from a member land on the channel, and
messages sent to the channel fan out as direct LXMF messages to every
member, falling back to a propagation node (store-and-forward) if direct
delivery fails.

| Key | Default | Notes |
|---|---|---|
| `display_name` | — | Shown in the gateway's Reticulum announce |
| `storage` | — | Directory for Reticulum/LXMF state and dynamic membership |
| `rns_configdir` | `null` | `null` = default `~/.reticulum` |
| `announce_interval` | `3600` | Seconds between RNS announces |
| `stamp_cost` | `null` | Set to require inbound proof-of-work stamps |
| `propagation_node` | `"auto"` | `"auto"` \| explicit dest hash hex \| `null` |
| `max_attachment_bytes` | `1000000` | Per-attachment cap, applied both directions |
| `image_max_bytes` | `null` | Falls back to `max_attachment_bytes` |
| `voice_to_codec2` | `null` | codec2 bitrate to transcode outbound voice, e.g. `1200` |
| `channels` | — | `name` / `members` (lowercase LXMF dest hashes) / `open` |

```yaml
plugins:
  lxmf:
    enabled: true
    command: /path/to/.venv/bin/python /path/to/plugins/lxmf/relayfabric-lxmf
    config:
      storage: /var/lib/relayfabric/lxmf
      channels:
        - name: pasadena
          members: ["a91d00aa..."]
          open: false
```

!!! note "Licensing"
    Depends on the official `rns`/`lxmf` Python packages and rides
    Reticulum's open mesh transport — no proprietary or copyleft coupling
    in the bridge itself.

Optional extras (Pillow for image downscaling; ffmpeg + `pycodec2` for
voice-to-codec2 transcoding) degrade gracefully when absent — oversize
images or untranscoded voice fall back to plain file attachments rather
than failing the send.

---

## Signal

Bridges Signal groups: each configured group maps to a channel, one
endpoint per group (fan-out across groups is the daemon's routing concern,
not this plugin's). Talks to a locally-run `signal-cli` daemon over
JSON-RPC/SSE rather than embedding Signal's protocol directly.

| Key | Default | Notes |
|---|---|---|
| `account` | — | Gateway's registered phone number |
| `rpc_url` | — | `signal-cli daemon` HTTP URL |
| `groups` | — | `channel: group_id` map (IDs from `signal-cli listGroups`) |
| `allowed_users` | `null` | `null` = all members; else a list of UUIDs |
| `attachment_dir` | `~/.local/share/signal-cli/attachments` | signal-cli's download dir |
| `max_attachment_bytes` | `8000000` | Per-attachment cap, applied both directions |

```yaml
plugins:
  signal:
    enabled: true
    command: /path/to/.venv/bin/python /path/to/plugins/signal/relayfabric-signal
    config:
      account: "+1234567890"
      rpc_url: http://127.0.0.1:7583
      groups:
        pasadena: "GRP=="
```

!!! note "Licensing"
    The plugin process itself has no GPL dependency; it speaks JSON-RPC to
    a separately-run `signal-cli` daemon over HTTP rather than linking any
    Signal client library.

If the account is a linked device, sync-message echoes of the gateway's
own posts are filtered and bare DMs (no group) are dropped; if
`allowed_users` is set, the account's own UUID must be included or its
posts are dropped by the ACL. Attachments cross as opaque bytes — no
downscaling or transcoding happens here (that lives in the LXMF plugin,
for messages routed onward there).

---

## Meshtastic

Bridges Meshtastic device channels. Each configured channel maps to a
RelayFabric channel: text uplinks arrive over the node's MQTT JSON stream,
and messages sent to the channel are delivered back over MQTT (one topic
per Meshtastic channel).

!!! note "Licensing"
    Meshtastic's official Python/protobuf client libraries are GPL-3.0.
    This plugin never links or imports them — it consumes the device's
    **native MQTT JSON integration** instead, an interface the node
    operator enables and controls independently. The `meshtastic` CLI used
    to configure the device (`meshtastic --set mqtt.json_enabled true`)
    runs on the operator's own machine, never on the gateway.

| Key | Default | Notes |
|---|---|---|
| `broker` | — | `mqtt://host:port` |
| `topic_root` | — | Node's full MQTT root incl. region, e.g. `msh/US` |
| `gateway_id` | `null` | `null` = accept all gateways; else filter by hex ID |
| `max_text_bytes` | `200` | Truncation applied to upstream text |
| `channels` | — | `index` / `topic_channel` per named channel |

```yaml
plugins:
  meshtastic:
    enabled: true
    config:
      broker: mqtt://127.0.0.1:1883
      topic_root: msh/US
      channels:
        zone1: {index: 0, topic_channel: "general"}
```

A consume-on-match cache keyed on `(channel, text)` breaks the
MQTT→Meshtastic→MQTT loop: a successful downlink is remembered for 1 hour
and the next matching uplink is dropped instead of re-bridged.

!!! warning "Known field-test risks"
    - Some firmware validates the downlink `from` field; this plugin
      always sends `from: 0`. `delivered: true` only means the broker
      accepted the publish, not that the node transmitted it — verify one
      real downlink per firmware. See
      [Live & Field Testing](live-testing.md).
    - `payload.timestamp` is assumed to already be epoch seconds.
    - A lost echo (downlink never re-uplinks over the air) leaves the
      loop-guard entry live for its full 1-hour TTL, during which one
      identical genuine uplink can be swallowed.

---

## MeshCore

Bridges MeshCore (Companion Radio Protocol) devices directly — no
intermediary broker. Each configured channel maps to a RelayFabric channel;
text uplinks land on the channel, sent messages go back over the radio.
Requires companion-mode firmware.

!!! note "Licensing"
    Uses the native `meshcore` library (2.3.8, MIT) — spec §8's preferred
    Companion Radio Protocol backend — talking directly to a companion-mode
    radio rather than wrapping a user-facing app.

| Key | Default | Notes |
|---|---|---|
| `connection` | — | `serial://path[?baud=N]` \| `tcp://host:port` \| `ble://addr` (best-effort, untested) |
| `max_text_bytes` | `160` | Budget for alias tag + body combined |
| `channels` | — | `index` per named channel |

```yaml
plugins:
  meshcore:
    enabled: true
    config:
      connection: serial:///dev/ttyUSB0
      channels:
        primary: {index: 0}
```

**Sender identity is channel-scoped, not per-node:** MeshCore PSK channels
carry no per-node identity, so the plugin keys sender on `(channel index)` —
every message on a channel maps to the same sender. Rate limits, aliases,
and moderation therefore all operate at channel granularity, not per-user.

!!! warning "Known field-test risks"
    - The library API is exercised only against fakes — verify end-to-end
      on hardware: one inbound channel message reaching the daemon, and
      one max-length send. See [Live & Field Testing](live-testing.md).
    - Re-verify per connection kind when switching serial/tcp/ble.
    - Alias prefix collision with Meshtastic: both alias as `MESH-XXXX`
      (first four protocol-name chars) — cosmetic, aliases stay distinct
      per sender.
    - `ts` timestamp units are assumed to be epoch seconds.

---

## Nostr

Bridges Nostr relays natively over NIP-01 WebSockets — no intermediary
broker. Each channel is a `(relay-set, filter)` pair for inbound plus a
publish target. **Scope: kind-1 public text notes only** — encrypted DMs,
attachments, and profile/contact-list management are out of scope this
cycle.

!!! note "Licensing"
    NIP-01 crypto and relay I/O run on `coincurve` + `websockets`
    (MIT/BSD-3) — never the GPL `strfry` relay, which is reference-only per
    project policy.

| Key | Default | Notes |
|---|---|---|
| `identity_file` | `null` | Persists the plugin's keypair (mode 0600); `null` = fresh identity every restart |
| `relays` | — | Default relay set (`wss://` URLs) |
| `channels` | — | Per channel: `relays` (optional, else default), `filter` (NIP-01 REQ), `publish_tags` |
| `max_text_bytes` | `280` | Outbound text budget |

```yaml
plugins:
  nostr:
    enabled: true
    config:
      identity_file: /var/lib/relayfabric/nostr.nsec
      relays: ["wss://relay.example.com"]
      channels:
        regional:
          filter: {kinds: [1], "#t": ["pasadena"]}
          publish_tags: [["t", "pasadena"]]
```

Every inbound event's id is recomputed and its schnorr signature verified
against the claimed pubkey before bridging — a relay is untrusted; bad
id/sig events are dropped, never bridged.

!!! warning "Known field-test risks"
    - No cross-relay dedup: an event seen from two subscribed relays isn't
      deduplicated. Exercised only against fakes so far — see
      [Live & Field Testing](live-testing.md).
    - An unscoped filter (e.g. bare `{"kinds":[1]}`) bridges relay-wide
      traffic as spam; the operator is responsible for scoping it.
    - `created_at` is relay/author-supplied and not checked against wall
      clock.
    - Sender identity (`nostr:<pubkey hex>`) is stable per author but not
      human-friendly; a rotated keypair reads as an entirely new sender.

---

## Bitchat

Bridges Bitchat's **public geohash channels** over the Internet/Nostr
transport only — ephemeral kind-20000 events, channel = `["g", <geohash>]`
tag. Reuses the shipped Nostr NIP-01 crypto and relay machinery. **BLE mesh
is out of scope, deferred** — Bitchat's direct Bluetooth-LE mesh is a
separate mechanism not built here. DMs and attachments are out of scope
too.

!!! note "Licensing"
    Same crypto stack as the Nostr plugin — `coincurve` + `websockets`
    (MIT/BSD-3) — never the GPL `strfry` relay or the AGPL `NYM`
    Bitchat-Nostr bridge, both reference-only per project policy.

| Key | Default | Notes |
|---|---|---|
| `identity_file` | `null` | One stable keypair authors every outbound event on every configured geohash |
| `relays` | — | Default relay set (`wss://` URLs) |
| `channels` | — | Per channel: `geohash` (base32), `relays` (optional), `nickname` (optional, passthrough `n`-tag) |
| `max_text_bytes` | `280` | Outbound text budget |

```yaml
plugins:
  bitchat:
    enabled: true
    config:
      identity_file: /var/lib/relayfabric/bitchat.nsec
      relays: ["wss://relay.example.com"]
      channels:
        pasadena:
          geohash: "9q5c"
          nickname: "relayfabric"
```

Same sig-verify-before-bridge and deny-by-default rules as Nostr apply
(bad id/sig, wrong-kind, or wrong-geohash events are dropped; only
configured geohashes are subscribed).

!!! warning "Known field-test risks"
    - Pre-1.0 protocol: kind 20000 and the `g`-tag geohash are stable, but
      nickname/teleport semantics are not — expect churn.
    - Events are ephemeral and unstored — bridging only works with a live
      relay connection at publish time.
    - One key per gateway means the same pubkey appears on every geohash
      it posts to, cross-geohash-linkable to anyone watching a relay. Real
      Bitchat clients avoid this with per-geohash ephemeral keys, deferred
      here pending a documented derivation.
    - Interop with real Bitchat clients is **unverified** — fakes only, no
      live cross-check yet. See [Live & Field Testing](live-testing.md).
    - A coarser (shorter) geohash is a wider channel — more traffic
      bridged.
