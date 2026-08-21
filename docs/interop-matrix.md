# Interoperability Matrix

The v0.4 cycle-C deliverable: for the five focus plugins — **LXMF,
Meshtastic, MeshCore, MQTT, Signal** — every interop dimension is either
backed by a named automated test or verified against live infrastructure.
No cell is assumed.

Legend: **✅** automated test (named) · **🌐** verified against real
infrastructure ([Live & Field Testing](live-testing.md)) · **⚙**
by-construction (provided by a library/daemon mechanism, exercised
indirectly).

| Dimension | MQTT | LXMF | Signal | Meshtastic | MeshCore |
|---|---|---|---|---|---|
| Inbound | ✅ e2e `bridges_dedups_and_suppresses_echo` · 🌐 tier 0 | ✅ suite · 🌐 live RNS backbone | ✅ `test_inbound_mapped_group_bridges` · 🌐 tier 2 | ✅ `test_text_ok` · 🌐 tier 0 + real node | ✅ suite · 🌐 hardware |
| Outbound | ✅ e2e + PUBACK-gated `DeliveryTracker` | ✅ `test_delivered_when_any_member_succeeds` · 🌐 | ✅ `test_send_success_records_loop_guard` · 🌐 | ✅ send suite · 🌐 real downlink | ✅ suite · 🌐 hardware |
| Replies (round-trip) | ✅ e2e round-trip · 🌐 tier 0 | 🌐 field-tested | 🌐 tier 2 | 🌐 real node | 🌐 hardware |
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
