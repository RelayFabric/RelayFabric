use chrono::Duration as CDuration;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;

pub static INGRESS: AtomicU64 = AtomicU64::new(0);
pub static EGRESS: AtomicU64 = AtomicU64::new(0);
pub static DROPPED: AtomicU64 = AtomicU64::new(0);
pub static DUPLICATES: AtomicU64 = AtomicU64::new(0);
pub static POLICY_DENIALS: AtomicU64 = AtomicU64::new(0);
pub static RATELIMITED: AtomicU64 = AtomicU64::new(0);
pub static QUEUE_REJECTED: AtomicU64 = AtomicU64::new(0);
pub static BUDGET_DEFERRED: AtomicU64 = AtomicU64::new(0);
pub static LINKS_VERIFIED: AtomicU64 = AtomicU64::new(0);
// design §6 (cycle F): federation ingress/egress/rejected counters. EGRESS
// is staged (nothing increments it until Task 5's fed dispatch lands in
// `engine::process_due`) but is rendered from day one, the same
// zero-until-wired posture `fed/sign.rs`/`fed/wire.rs` used at the module
// level — a counter that's always read (in `render`, below) is never
// flagged dead_code even before anything increments it.
pub static FED_INGRESS: AtomicU64 = AtomicU64::new(0);
pub static FED_EGRESS: AtomicU64 = AtomicU64::new(0);
pub static FED_REJECTED: AtomicU64 = AtomicU64::new(0);
// RFDP discovery (design §6, cycle G): advert exchange counters, same
// zero-until-wired posture as the FED_* trio above -- `fed::conn` is the
// sole incrementer (ADVERT_TX on every signed advert this daemon sends,
// ADVERT_RX on every one it verifies+stores, ADVERT_REJECTED on every one
// it drops pre-storage: oversized, third-party node_id, bad signature,
// invalid shape, stale/scope-denied).
pub static ADVERT_RX: AtomicU64 = AtomicU64::new(0);
pub static ADVERT_TX: AtomicU64 = AtomicU64::new(0);
pub static ADVERT_REJECTED: AtomicU64 = AtomicU64::new(0);
// Sealed routing (design §4/§6, SPEC §113.4, cycle H, Task 4): sealed fed
// egress counter, same zero-until-wired posture as FED_*/ADVERT_* above.
// `engine::process_due_fed`'s `security_mode: sealed` branch is the sole
// incrementer, on every `Fed::Sealed` frame actually handed to a live
// connection's channel (mirrors `FED_EGRESS`'s own bump point exactly, one
// security_mode over). SEALED_INGRESS/SEALED_REJECTED (design §6) are
// defined below, near DELIVERY_LATENCY_*, since Task 5 landed the ingress
// side that increments them.
pub static SEALED_EGRESS: AtomicU64 = AtomicU64::new(0);

// Sealed routing ingress (design §5/§6, SPEC §113.2/§113.5, cycle H, Task
// 5): `engine::fed_sealed_ingress` is the sole incrementer. SEALED_INGRESS
// bumps once per accepted `Fed::Sealed` frame (mirrors `FED_INGRESS`'s own
// bump point, one security_mode over). SEALED_REJECTED bumps on every gate
// failure that returns a named reason (alg/expiry/bad-seal/bad-binding/
// bad-sig/trust/route/downgrade-refused, via `engine::sealed_reject`) --
// NOT on the two silent-drop categories (`DUPLICATE`/`RATE_LIMITED`), which
// reuse the existing shared `DUPLICATES`/`RATELIMITED` counters instead,
// exactly mirroring `fed_ingress`'s own drop-vs-reject split.
pub static SEALED_INGRESS: AtomicU64 = AtomicU64::new(0);
pub static SEALED_REJECTED: AtomicU64 = AtomicU64::new(0);

// Transport-class policy (design §3, transport-class cycle task 3, spec
// §17/§113.4): `engine::load_attachments` is the sole incrementer, bumped
// once per attachment demoted to a note because the destination's resolved
// `TransportPolicy` forbids its media type (`!allow_images`/`!allow_video`)
// -- never for an ordinary capability/oversize/CAS-miss drop, which already
// have their own note wording and don't touch this counter. Deliberately
// label-free (the design doc's own optional `{plugin,reason}` labels are
// NOT wired this cycle -- a bare count is enough signal for v0.1 and keeps
// the "no content in metrics" invariant trivially true: no filename,
// plugin name, or mime type is ever attached to this counter).
pub static TRANSPORT_DEMOTED: AtomicU64 = AtomicU64::new(0);

// design §3 (cycle D): received_at -> delivered wall-clock latency, accrued
// as a micros sum + count pair (rendered in seconds) rather than a
// histogram — the SHOULD-list ask is a Prometheus summary's _sum/_count,
// not buckets.
pub static DELIVERY_LATENCY_MICROS_SUM: AtomicU64 = AtomicU64::new(0);
pub static DELIVERY_LATENCY_COUNT: AtomicU64 = AtomicU64::new(0);

// design §3: relayfabric_route_messages_total{route=...}, incremented once
// per delivered message. A HashMap (not per-route AtomicU64s) because
// routes are operator-configured and unbounded in principle; LazyLock is
// needed because Mutex::new(HashMap::new()) is not a const fn.
pub static ROUTE_MESSAGES: LazyLock<Mutex<HashMap<String, u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// design §1/§6 (cycle F): latest up/down state per federation connection,
/// keyed the same way `fed::conn::FedState.conns` is (configured peer
/// `name`, or a short `node_id` form for an unconfigured/inbound-only
/// connection — see `fed::display_peer_key`) — same shape/rationale as
/// `ROUTE_MESSAGES` above (operator-configured, unbounded in principle, so
/// a `HashMap` behind a `LazyLock<Mutex<_>>` rather than per-peer
/// `AtomicU64`s). Set on every connect/disconnect by `fed::conn`, never
/// cleared otherwise — a peer removed from config keeps its last-known
/// state rendered until the next daemon restart, matching `ROUTE_MESSAGES`'
/// own "entries never expire" posture.
pub static FEDERATION_PEERS_UP: LazyLock<Mutex<HashMap<String, bool>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn set_federation_peer_up(peer: &str, up: bool) {
    FEDERATION_PEERS_UP
        .lock()
        .unwrap()
        .insert(peer.to_string(), up);
}

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// Records one delivery's received_at -> delivered latency (fabric-internal
/// only; callers must not pass a delta derived from the sender-controlled
/// `created_at`). A negative delta (clock skew) clamps to zero rather than
/// underflowing the unsigned accumulator.
pub fn record_latency(latency: CDuration) {
    let micros = latency.num_microseconds().unwrap_or(0).max(0) as u64;
    DELIVERY_LATENCY_MICROS_SUM.fetch_add(micros, Ordering::Relaxed);
    DELIVERY_LATENCY_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_route(route: &str) {
    *ROUTE_MESSAGES
        .lock()
        .unwrap()
        .entry(route.to_string())
        .or_insert(0) += 1;
}

const MAX_GAUGES_PER_PLUGIN: usize = 32;
const GAUGE_STALE_AFTER: Duration = Duration::from_secs(600);

/// Per-plugin latest-value gauge snapshot (design §3): each `Gauges` IPC
/// frame fully replaces whatever this plugin last reported (not a delta/
/// merge), sanitized and capped on the way in. Lives on `Daemon` (not a
/// process-global static like the counters above) because it's genuinely
/// per-daemon-instance state, not a lifetime-of-the-process counter — and
/// keeping it there keeps its own tests free of the cross-test-interference
/// global statics require careful monotonic (`>`) assertions to avoid.
type GaugeSnapshot = (HashMap<String, f64>, Instant);

pub struct PluginGauges {
    inner: Mutex<HashMap<String, GaugeSnapshot>>,
}

impl Default for PluginGauges {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginGauges {
    pub fn new() -> Self {
        PluginGauges {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Sanitizes gauge names to `[a-z0-9_]` (any other byte -> `_`,
    /// uppercase -> lowercase), drops non-finite values (NaN/+inf/-inf --
    /// a plugin-controlled value that reaches `/metrics` unchecked; NaN/inf
    /// are valid `f64`s so they survive the CBOR wire roundtrip untouched,
    /// but Rust's `Display` spells infinities "inf"/"-inf", not the
    /// Prometheus text-format token, and NaN silently poisons PromQL
    /// threshold comparisons -- both must be stopped at this boundary, not
    /// left for the renderer), keeps at most `MAX_GAUGES_PER_PLUGIN`
    /// entries (excess ignored with one warn for the whole frame), and
    /// stores the result as this plugin's new latest snapshot, stamped with
    /// the current time for staleness eviction at render.
    pub fn record(&self, plugin: &str, gauges: std::collections::BTreeMap<String, f64>) {
        let total = gauges.len();
        let non_finite = gauges.values().filter(|v| !v.is_finite()).count();
        let sanitized: HashMap<String, f64> = gauges
            .into_iter()
            .filter(|(_, value)| value.is_finite())
            .take(MAX_GAUGES_PER_PLUGIN)
            .map(|(name, value)| (sanitize_gauge_name(&name), value))
            .collect();
        if non_finite > 0 {
            warn!(
                plugin,
                non_finite, "gauges frame contained non-finite value(s); dropped"
            );
        }
        if total - non_finite > MAX_GAUGES_PER_PLUGIN {
            warn!(
                plugin,
                total,
                cap = MAX_GAUGES_PER_PLUGIN,
                "gauges frame exceeded per-plugin cap; excess ignored"
            );
        }
        self.inner
            .lock()
            .unwrap()
            .insert(plugin.to_string(), (sanitized, Instant::now()));
    }

    /// Renders every gauge from every plugin whose snapshot is younger than
    /// `GAUGE_STALE_AFTER` relative to `now` (an explicit param, not
    /// `Instant::now()`, so eviction is deterministically testable).
    pub fn render(&self, now: Instant) -> String {
        let store = self.inner.lock().unwrap();
        let mut plugins: Vec<_> = store.iter().collect();
        plugins.sort_by(|a, b| a.0.cmp(b.0));
        let mut out = String::new();
        for (plugin, (gauges, at)) in plugins {
            if now.saturating_duration_since(*at) > GAUGE_STALE_AFTER {
                continue;
            }
            let mut names: Vec<_> = gauges.iter().collect();
            names.sort_by(|a, b| a.0.cmp(b.0));
            for (name, value) in names {
                out.push_str(&format!(
                    "relayfabric_plugin_gauge{{plugin=\"{plugin}\",name=\"{name}\"}} {value}\n"
                ));
            }
        }
        out
    }

    /// Per-plugin gauge snapshot for admin `GET /v1/plugins` (design §2):
    /// `name -> (value, age_secs)`, filtered by the same staleness rule as
    /// `render` (age > `GAUGE_STALE_AFTER` excluded). Staleness is tracked
    /// per SNAPSHOT (i.e. per plugin, matching `record`'s "each frame fully
    /// replaces the last" semantics), not per individual gauge name --
    /// so this returns an empty map for a plugin that never reported
    /// gauges, and also for one whose only snapshot has gone stale, rather
    /// than a partial/mixed-freshness result.
    pub fn for_plugin(&self, plugin: &str, now: Instant) -> BTreeMap<String, (f64, u64)> {
        let store = self.inner.lock().unwrap();
        let Some((gauges, at)) = store.get(plugin) else {
            return BTreeMap::new();
        };
        let age = now.saturating_duration_since(*at);
        if age > GAUGE_STALE_AFTER {
            return BTreeMap::new();
        }
        gauges
            .iter()
            .map(|(name, value)| (name.clone(), (*value, age.as_secs())))
            .collect()
    }
}

fn sanitize_gauge_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            let lower = c.to_ascii_lowercase();
            if lower.is_ascii_lowercase() || lower.is_ascii_digit() || lower == '_' {
                lower
            } else {
                '_'
            }
        })
        .collect()
}

fn render_latency(sum_micros: u64, count: u64) -> String {
    format!(
        "# TYPE relayfabric_delivery_latency_seconds summary\n\
         relayfabric_delivery_latency_seconds_sum {:.6}\n\
         relayfabric_delivery_latency_seconds_count {count}\n",
        sum_micros as f64 / 1_000_000.0
    )
}

fn render_routes(routes: &HashMap<String, u64>) -> String {
    let mut out = String::new();
    out.push_str("# TYPE relayfabric_route_messages_total counter\n");
    let mut entries: Vec<_> = routes.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (route, n) in entries {
        out.push_str(&format!(
            "relayfabric_route_messages_total{{route=\"{route}\"}} {n}\n"
        ));
    }
    out
}

pub fn render(
    queue_counts: &[(String, i64)],
    plugin_up: &[(String, bool)],
    gauges: &PluginGauges,
) -> String {
    let mut out = String::new();
    let counters = [
        ("relayfabric_messages_ingress_total", &INGRESS),
        ("relayfabric_messages_egress_total", &EGRESS),
        ("relayfabric_messages_dropped_total", &DROPPED),
        ("relayfabric_duplicate_messages_total", &DUPLICATES),
        ("relayfabric_policy_denials_total", &POLICY_DENIALS),
        ("relayfabric_ratelimited_total", &RATELIMITED),
        ("relayfabric_queue_rejected_total", &QUEUE_REJECTED),
        ("relayfabric_budget_deferred_total", &BUDGET_DEFERRED),
        ("relayfabric_links_verified_total", &LINKS_VERIFIED),
        ("relayfabric_federation_ingress_total", &FED_INGRESS),
        ("relayfabric_federation_egress_total", &FED_EGRESS),
        ("relayfabric_federation_rejected_total", &FED_REJECTED),
        ("relayfabric_advert_rx_total", &ADVERT_RX),
        ("relayfabric_advert_tx_total", &ADVERT_TX),
        ("relayfabric_advert_rejected_total", &ADVERT_REJECTED),
        ("relayfabric_sealed_egress_total", &SEALED_EGRESS),
        ("relayfabric_sealed_ingress_total", &SEALED_INGRESS),
        ("relayfabric_sealed_rejected_total", &SEALED_REJECTED),
        ("relayfabric_transport_demoted_total", &TRANSPORT_DEMOTED),
    ];
    for (name, c) in counters {
        out.push_str(&format!(
            "# TYPE {name} counter\n{name} {}\n",
            c.load(Ordering::Relaxed)
        ));
    }
    out.push_str("# TYPE relayfabric_queue_depth gauge\n");
    for (state, n) in queue_counts {
        out.push_str(&format!(
            "relayfabric_queue_depth{{state=\"{state}\"}} {n}\n"
        ));
    }
    out.push_str("# TYPE relayfabric_plugin_up gauge\n");
    for (plugin, up) in plugin_up {
        out.push_str(&format!(
            "relayfabric_plugin_up{{plugin=\"{plugin}\"}} {}\n",
            u8::from(*up)
        ));
    }
    out.push_str("# TYPE relayfabric_federation_peer_up gauge\n");
    {
        let peers = FEDERATION_PEERS_UP.lock().unwrap();
        let mut entries: Vec<_> = peers.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        for (peer, up) in entries {
            out.push_str(&format!(
                "relayfabric_federation_peer_up{{peer=\"{peer}\"}} {}\n",
                u8::from(*up)
            ));
        }
    }
    out.push_str(&render_latency(
        DELIVERY_LATENCY_MICROS_SUM.load(Ordering::Relaxed),
        DELIVERY_LATENCY_COUNT.load(Ordering::Relaxed),
    ));
    out.push_str(&render_routes(&ROUTE_MESSAGES.lock().unwrap()));
    out.push_str("# TYPE relayfabric_plugin_gauge gauge\n");
    out.push_str(&gauges.render(Instant::now()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        inc(&INGRESS);
        let out = render(
            &[("pending".into(), 3), ("dead_letter".into(), 1)],
            &[("mqtt".into(), true), ("mocka".into(), false)],
            &PluginGauges::new(),
        );
        assert!(out.contains("relayfabric_messages_ingress_total "));
        assert!(out.contains("relayfabric_queue_depth{state=\"pending\"} 3"));
        assert!(out.contains("relayfabric_queue_depth{state=\"dead_letter\"} 1"));
        assert!(out.contains("relayfabric_plugin_up{plugin=\"mqtt\"} 1"));
        assert!(out.contains("relayfabric_plugin_up{plugin=\"mocka\"} 0"));
        // presence only: other tests in the same process may bump counters
        assert!(out.contains("relayfabric_policy_denials_total"));
        assert!(out.contains("relayfabric_ratelimited_total"));
        assert!(out.contains("relayfabric_queue_rejected_total"));
        assert!(out.contains("relayfabric_budget_deferred_total"));
        assert!(out.contains("relayfabric_links_verified_total"));
        assert!(out.contains("relayfabric_delivery_latency_seconds_sum"));
        assert!(out.contains("relayfabric_delivery_latency_seconds_count"));
        assert!(out.contains("relayfabric_route_messages_total"));
        assert!(out.contains("relayfabric_plugin_gauge"));
        assert!(out.contains("relayfabric_federation_ingress_total"));
        assert!(out.contains("relayfabric_federation_egress_total"));
        assert!(out.contains("relayfabric_federation_rejected_total"));
        assert!(out.contains("relayfabric_federation_peer_up"));
        assert!(out.contains("relayfabric_advert_rx_total"));
        assert!(out.contains("relayfabric_advert_tx_total"));
        assert!(out.contains("relayfabric_advert_rejected_total"));
        assert!(out.contains("relayfabric_sealed_egress_total"));
        assert!(out.contains("relayfabric_sealed_ingress_total"));
        assert!(out.contains("relayfabric_sealed_rejected_total"));
        assert!(out.contains("relayfabric_transport_demoted_total"));
    }

    // ---- federation peer up/down gauge --------------------------------

    #[test]
    fn set_federation_peer_up_renders_the_latest_state_per_peer() {
        let key = "test-only-fed-peer-unique-7c2e";
        set_federation_peer_up(key, true);
        let out = render(&[], &[], &PluginGauges::new());
        assert!(out.contains(&format!(
            "relayfabric_federation_peer_up{{peer=\"{key}\"}} 1"
        )));

        set_federation_peer_up(key, false);
        let out = render(&[], &[], &PluginGauges::new());
        assert!(
            out.contains(&format!(
                "relayfabric_federation_peer_up{{peer=\"{key}\"}} 0"
            )),
            "a fresh set_federation_peer_up call must replace the prior state: {out}"
        );
    }

    // ---- delivery latency ------------------------------------------------

    #[test]
    fn render_latency_formats_micros_as_seconds() {
        // Pure function, no shared global state -- exact-value assertions
        // here are safe under any parallelism.
        let out = render_latency(2_500_000, 3);
        assert!(out.contains("relayfabric_delivery_latency_seconds_sum 2.500000"));
        assert!(out.contains("relayfabric_delivery_latency_seconds_count 3"));
    }

    #[test]
    fn record_latency_clamps_negative_deltas_to_zero() {
        let before_sum = DELIVERY_LATENCY_MICROS_SUM.load(Ordering::Relaxed);
        let before_count = DELIVERY_LATENCY_COUNT.load(Ordering::Relaxed);
        record_latency(CDuration::seconds(-5));
        let after_sum = DELIVERY_LATENCY_MICROS_SUM.load(Ordering::Relaxed);
        let after_count = DELIVERY_LATENCY_COUNT.load(Ordering::Relaxed);
        // DELIVERY_LATENCY_MICROS_SUM/COUNT are process-globals shared with
        // every other test in this binary's parallel run (like INGRESS
        // above), so only monotonic ">" checks are safe here -- an exact
        // before+1/before+N delta would flake against any concurrent
        // record_latency call landing between this test's own before/after
        // loads. The exact micros-per-call math is proven instead by the
        // global-state-free render_latency_formats_micros_as_seconds test
        // above.
        assert!(after_count > before_count);
        assert!(
            after_sum >= before_sum,
            "a clamped-to-zero latency must never decrease the sum"
        );
    }

    // ---- route counter -----------------------------------------------

    #[test]
    fn render_routes_formats_counts_sorted_by_route() {
        let mut m = HashMap::new();
        m.insert("bravo".to_string(), 2u64);
        m.insert("alpha".to_string(), 5u64);
        let out = render_routes(&m);
        let a_pos = out.find("route=\"alpha\"").unwrap();
        let b_pos = out.find("route=\"bravo\"").unwrap();
        assert!(a_pos < b_pos, "routes must render sorted: {out}");
        assert!(out.contains("relayfabric_route_messages_total{route=\"alpha\"} 5"));
        assert!(out.contains("relayfabric_route_messages_total{route=\"bravo\"} 2"));
    }

    #[test]
    fn inc_route_increments_the_named_route() {
        // A key unique to this test avoids collision with any other test
        // (or concurrent production code, in the real daemon) touching the
        // same process-global ROUTE_MESSAGES map, so an exact +1 is safe.
        let key = "test-only-route-inc-route-unique-9f3a";
        let before = ROUTE_MESSAGES
            .lock()
            .unwrap()
            .get(key)
            .copied()
            .unwrap_or(0);
        inc_route(key);
        let after = ROUTE_MESSAGES
            .lock()
            .unwrap()
            .get(key)
            .copied()
            .unwrap_or(0);
        assert_eq!(after, before + 1);
    }

    // ---- plugin gauges -----------------------------------------------

    #[test]
    fn sanitize_gauge_name_lowercases_and_replaces_invalid_chars() {
        assert_eq!(sanitize_gauge_name("RSSI"), "rssi");
        assert_eq!(sanitize_gauge_name("battery.pct"), "battery_pct");
        assert_eq!(sanitize_gauge_name("snr-db"), "snr_db");
        assert_eq!(sanitize_gauge_name("queue_depth_0"), "queue_depth_0");
    }

    #[test]
    fn gauges_record_and_render_roundtrip() {
        let g = PluginGauges::new();
        let mut vals = std::collections::BTreeMap::new();
        vals.insert("RSSI".to_string(), -71.0);
        g.record("meshtastic", vals);
        let out = g.render(Instant::now());
        assert_eq!(
            out,
            "relayfabric_plugin_gauge{plugin=\"meshtastic\",name=\"rssi\"} -71\n"
        );
    }

    #[test]
    fn gauges_render_sorts_plugins_and_names() {
        let g = PluginGauges::new();
        let mut a = std::collections::BTreeMap::new();
        a.insert("snr".to_string(), 1.0);
        a.insert("rssi".to_string(), 2.0);
        g.record("zzz-plugin", a);
        let mut b = std::collections::BTreeMap::new();
        b.insert("queue_depth".to_string(), 3.0);
        g.record("aaa-plugin", b);
        let out = g.render(Instant::now());
        let aaa = out.find("aaa-plugin").unwrap();
        let zzz = out.find("zzz-plugin").unwrap();
        let rssi = out.find("name=\"rssi\"").unwrap();
        let snr = out.find("name=\"snr\"").unwrap();
        assert!(aaa < zzz, "plugins must render sorted: {out}");
        assert!(rssi < snr, "gauge names must render sorted: {out}");
    }

    #[test]
    fn gauges_render_skips_stale_entries() {
        let g = PluginGauges::new();
        let mut vals = std::collections::BTreeMap::new();
        vals.insert("rssi".to_string(), -80.0);
        g.record("mqtt", vals);
        let far_future = Instant::now() + GAUGE_STALE_AFTER + Duration::from_secs(1);
        let out = g.render(far_future);
        assert!(
            !out.contains("mqtt"),
            "a 10min+-stale gauge must not render: {out}"
        );
    }

    #[test]
    fn gauges_render_keeps_entries_just_under_the_stale_window() {
        let g = PluginGauges::new();
        let mut vals = std::collections::BTreeMap::new();
        vals.insert("rssi".to_string(), -80.0);
        g.record("mqtt", vals);
        let almost_stale = Instant::now() + GAUGE_STALE_AFTER - Duration::from_secs(1);
        let out = g.render(almost_stale);
        assert!(
            out.contains("mqtt"),
            "a gauge just under the stale window must still render: {out}"
        );
    }

    #[test]
    fn gauges_record_caps_at_32_per_plugin() {
        let g = PluginGauges::new();
        let mut vals = std::collections::BTreeMap::new();
        for i in 0..40 {
            vals.insert(format!("g{i:02}"), i as f64);
        }
        g.record("chatty", vals);
        let out = g.render(Instant::now());
        let count = out.matches("plugin=\"chatty\"").count();
        assert_eq!(
            count, 32,
            "excess gauges beyond the 32 cap must be ignored: {out}"
        );
    }

    #[test]
    fn gauges_record_drops_non_finite_values() {
        // NaN/+inf/-inf are valid f64s that survive the CBOR wire roundtrip
        // untouched (a plugin-controlled value, e.g. meshtastic's rssi/snr
        // sourced from attacker-influenced MQTT gateway JSON) -- they must
        // never reach /metrics: Rust's Display spells infinities
        // "inf"/"-inf" (not the Prometheus text-format token), and NaN
        // silently poisons PromQL threshold comparisons.
        let g = PluginGauges::new();
        let mut vals = std::collections::BTreeMap::new();
        vals.insert("nan_gauge".to_string(), f64::NAN);
        vals.insert("pos_inf_gauge".to_string(), f64::INFINITY);
        vals.insert("neg_inf_gauge".to_string(), f64::NEG_INFINITY);
        vals.insert("finite_gauge".to_string(), -71.0);
        g.record("meshtastic", vals);

        let out = g.render(Instant::now());
        assert_eq!(
            out, "relayfabric_plugin_gauge{plugin=\"meshtastic\",name=\"finite_gauge\"} -71\n",
            "only the finite value may survive record(): {out}"
        );
        assert!(
            !out.to_lowercase().contains("inf"),
            "no inf/-inf token may reach render output: {out}"
        );
        assert!(
            !out.to_lowercase().contains("nan"),
            "no NaN token may reach render output: {out}"
        );
    }

    // ---- per-plugin gauge accessor (design §2: admin GET /v1/plugins) ----

    #[test]
    fn for_plugin_returns_values_with_age_secs() {
        let g = PluginGauges::new();
        let mut vals = std::collections::BTreeMap::new();
        vals.insert("rssi".to_string(), -71.5);
        g.record("mocka", vals);
        let now = Instant::now() + Duration::from_secs(5);
        let out = g.for_plugin("mocka", now);
        assert_eq!(out.get("rssi"), Some(&(-71.5, 5)), "out was: {out:?}");
    }

    #[test]
    fn for_plugin_returns_empty_for_a_plugin_that_never_reported_gauges() {
        let g = PluginGauges::new();
        assert!(g.for_plugin("never-reported", Instant::now()).is_empty());
    }

    #[test]
    fn for_plugin_excludes_a_stale_snapshot() {
        let g = PluginGauges::new();
        let mut vals = std::collections::BTreeMap::new();
        vals.insert("rssi".to_string(), -71.5);
        g.record("mocka", vals);
        let far_future = Instant::now() + GAUGE_STALE_AFTER + Duration::from_secs(1);
        assert!(g.for_plugin("mocka", far_future).is_empty());
    }

    #[test]
    fn for_plugin_keeps_a_snapshot_just_under_the_stale_window() {
        let g = PluginGauges::new();
        let mut vals = std::collections::BTreeMap::new();
        vals.insert("rssi".to_string(), -71.5);
        g.record("mocka", vals);
        let almost_stale = Instant::now() + GAUGE_STALE_AFTER - Duration::from_secs(1);
        assert!(!g.for_plugin("mocka", almost_stale).is_empty());
    }

    #[test]
    fn gauges_record_replaces_previous_snapshot_entirely() {
        let g = PluginGauges::new();
        let mut first = std::collections::BTreeMap::new();
        first.insert("rssi".to_string(), -80.0);
        first.insert("snr".to_string(), 5.0);
        g.record("mqtt", first);

        let mut second = std::collections::BTreeMap::new();
        second.insert("queue_depth".to_string(), 2.0);
        g.record("mqtt", second);

        let out = g.render(Instant::now());
        assert!(
            !out.contains("name=\"rssi\""),
            "a fresh frame must fully replace the old one: {out}"
        );
        assert!(!out.contains("name=\"snr\""));
        assert!(out.contains("name=\"queue_depth\""));
    }
}
