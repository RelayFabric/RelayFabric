#![allow(dead_code)] // consumed by engine wiring (Task 9); remove allow when used

use std::sync::atomic::{AtomicU64, Ordering};

pub static INGRESS: AtomicU64 = AtomicU64::new(0);
pub static EGRESS: AtomicU64 = AtomicU64::new(0);
pub static DROPPED: AtomicU64 = AtomicU64::new(0);
pub static DUPLICATES: AtomicU64 = AtomicU64::new(0);
pub static POLICY_DENIALS: AtomicU64 = AtomicU64::new(0);

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub fn render(queue_counts: &[(String, i64)], plugin_up: &[(String, bool)]) -> String {
    let mut out = String::new();
    let counters = [
        ("relayfabric_messages_ingress_total", &INGRESS),
        ("relayfabric_messages_egress_total", &EGRESS),
        ("relayfabric_messages_dropped_total", &DROPPED),
        ("relayfabric_duplicate_messages_total", &DUPLICATES),
        ("relayfabric_policy_denials_total", &POLICY_DENIALS),
    ];
    for (name, c) in counters {
        out.push_str(&format!("# TYPE {name} counter\n{name} {}\n", c.load(Ordering::Relaxed)));
    }
    out.push_str("# TYPE relayfabric_queue_depth gauge\n");
    for (state, n) in queue_counts {
        out.push_str(&format!("relayfabric_queue_depth{{state=\"{state}\"}} {n}\n"));
    }
    out.push_str("# TYPE relayfabric_plugin_up gauge\n");
    for (plugin, up) in plugin_up {
        out.push_str(&format!(
            "relayfabric_plugin_up{{plugin=\"{plugin}\"}} {}\n", u8::from(*up)));
    }
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
        );
        assert!(out.contains("relayfabric_messages_ingress_total "));
        assert!(out.contains("relayfabric_queue_depth{state=\"pending\"} 3"));
        assert!(out.contains("relayfabric_queue_depth{state=\"dead_letter\"} 1"));
        assert!(out.contains("relayfabric_plugin_up{plugin=\"mqtt\"} 1"));
        assert!(out.contains("relayfabric_plugin_up{plugin=\"mocka\"} 0"));
        // presence only: other tests in the same process may bump counters
        assert!(out.contains("relayfabric_policy_denials_total"));
    }
}
