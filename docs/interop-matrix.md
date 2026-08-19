# Interoperability Matrix

The v0.4 cycle-C deliverable: for the five focus plugins — **LXMF,
Meshtastic, MeshCore, MQTT, Signal** — every interop dimension is either
backed by a named automated test, verified against live infrastructure, or
explicitly listed as pending with the exact validation step. No cell is
assumed.

Legend: **✅** automated test (named) · **🌐** verified against real
infrastructure ([Live & Field Testing](live-testing.md)) · **⚙**
by-construction (provided by a library/daemon mechanism, exercised
indirectly) · **⏳** pending operator validation (step given below).

| Dimension | MQTT | LXMF | Signal | Meshtastic | MeshCore |
|---|---|---|---|---|---|
| Inbound | ✅ e2e `bridges_dedups_and_suppresses_echo` · 🌐 tier 0 | ✅ suite · 🌐 live RNS backbone | ✅ `test_inbound_mapped_group_bridges` · 🌐 tier 2 | ✅ `test_text_ok` · 🌐 tier 0 (nodeless) | ✅ suite · ⏳ C-1 |
| Outbound | ✅ e2e + PUBACK-gated `DeliveryTracker` | ✅ `test_delivered_when_any_member_succeeds` · 🌐 | ✅ `test_send_success_records_loop_guard` · 🌐 | ✅ send suite · ⏳ C-2 (real downlink) | ✅ suite · ⏳ C-1 |
| Replies (round-trip) | ✅ e2e round-trip · 🌐 tier 0 | 🌐 field-tested | 🌐 tier 2 | ⏳ C-2 | ⏳ C-1 |
| Attachments | n/a (text-only capability; daemon demotes: ✅ e2e `attachment_egress_is_capability_aware`) | ✅ media suite (images, codec2 voice, caps) | ✅ attachment suite (traversal, caps, notes) | n/a (text-only; daemon demotes ✅) | n/a (text-only; daemon demotes ✅) |
| Reconnect | ⚙ rumqttc auto-reconnect | ⚙ RNS-managed links | ⚙ SSE reader + supervisor restart | ⚙ paho `connect_async` + auto-reconnect, re-subscribe on connect | ✅ exits on radio disconnect → supervisor backoff restart (by design) |
| Dedup / loop guard | ✅ MQTT v5 No-Local + daemon dedup e2e | ✅ `SentCache` suite | ✅ `test_match_consumes`, sync-echo drop | ✅ `SentCache` echo suite | ✅ `SentCache` suite |
| Offline queue | ✅ e2e `queues_for_offline_plugin_and_survives_restart` (daemon-side, protocol-independent) | ✅ same + propagation-node fallback tests | ✅ same | ✅ same | ✅ same |
| Restart recovery | ✅ same e2e (daemon kill + restart, queue + attachments survive) + supervisor backoff ladder | ✅ | ✅ | ✅ | ✅ |
| Max payload | ✅ caps + daemon truncation e2e | ✅ per-attachment caps | ✅ caps | ✅ `hello_max_payload` two-layer cap | ✅ `hello_max_payload` two-layer cap |
| Failure injection | ✅ tracker ignores orphan acks; broker-down tolerated (`connect_async`) | ✅ all-members-fail, double-fire, proof-timeout tests | ✅ `test_send_failure_reports_detail` | ✅ publish-failure suite | ✅ send-failure suite |

The daemon-side dimensions (offline queue, restart recovery, priority
ordering, rate limits, transport-class demotion) are protocol-independent
and covered once in `switchyardd/tests/e2e.rs` — every plugin inherits
them through the same IPC surface.

## Pending operator validations

These are the only cells not closed by automation, because they need
physical radios or live accounts. Each is a [livetest](live-testing.md)
run:

- **C-1 — MeshCore on real hardware.** Companion-radio device on
  `serial:///dev/ttyUSB0`, tier-style run: one inbound channel message,
  one outbound, one round-trip. The plugin's fake-backend suite models the
  companion protocol; this validates the model.
- **C-2 — Meshtastic real-node downlink.** The plugin always sends
  `from: 0` and some firmware validates the downlink `from` field
  (documented risk in [Plugins](plugins.md)); `delivered: true` means the
  broker accepted the publish, not that the node transmitted. Verify one
  real downlink and one radio round-trip per firmware in use.
- **Nostr/Bitchat** are outside the five-plugin matrix this cycle
  (documented as fake-tested in the [feature status](index.md) table);
  their live validation is deliberately deferred rather than implied.
