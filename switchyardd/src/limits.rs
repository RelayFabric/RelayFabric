//! Quota enforcement primitives (spec §45 backpressure): sliding-window
//! counters that gate ingress before it ever reaches storage.
//!
//! Both limiters here are in-memory only: a restart just gives every key a
//! fresh window -- that's an acceptable reset for a rate limiter (nobody is
//! owed a persisted quota across a daemon bounce), so there's no sqlite
//! table backing this, unlike `dedup`'s TTL cache which shares the same
//! "in-memory, prune on access" shape for the same reason.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);

/// Per-sender sliding-window limiter: `messages_per_minute` and
/// `bytes_per_hour` are independent dimensions, each with its own window
/// length, checked against the same per-key history of `(Instant, bytes)`
/// entries.
pub struct SenderLimiter {
    messages_per_minute: u32,
    bytes_per_hour: u64,
    windows: HashMap<String, VecDeque<(Instant, u64)>>,
}

impl SenderLimiter {
    pub fn new(messages_per_minute: u32, bytes_per_hour: u64) -> SenderLimiter {
        SenderLimiter { messages_per_minute, bytes_per_hour, windows: HashMap::new() }
    }

    /// True (and records the message against `key`'s history) if both
    /// configured dimensions have room; false (nothing recorded) if either
    /// is exhausted. A dimension whose limit is 0 is unlimited and never
    /// gates. With both dimensions 0 (the all-zero default config) this
    /// returns true before touching `self.windows` at all, so zero-config
    /// senders never accumulate any per-key state.
    pub fn allow(&mut self, key: &str, bytes: u64, now: Instant) -> bool {
        if self.messages_per_minute == 0 && self.bytes_per_hour == 0 {
            return true;
        }
        // Global prune-on-access over the *whole* map on every call, not
        // just the key being touched right now — same "in-memory, prune on
        // access" shape `dedup.rs`'s TTL cache uses (see the module doc
        // comment). Per-key pruning alone only trims a key's own history
        // when that same key is looked up again; a key that's never
        // revisited would otherwise keep its now-stale VecDeque, and the
        // map entry itself, alive forever. That's exactly the abuse case
        // this limiter exists to stop: a hostile sender on a public node
        // minting a fresh native_ref per message would grow `self.windows`
        // without bound. O(keys) global prune per call; fine at gateway
        // volumes — move to a scheduled sweep if key counts ever grow large.
        //
        // Horizon matches whichever dimension is actually configured: an
        // hour only when `bytes_per_hour` is in play (its window needs
        // entries that old); a config with only `messages_per_minute` set
        // has no use for anything past a minute, so pruning at the minute
        // horizon there keeps stale entries from lingering 60x longer than
        // any check will ever look back.
        let horizon = if self.bytes_per_hour > 0 { HOUR } else { MINUTE };
        self.windows.retain(|_, entries| {
            entries.retain(|(t, _)| now.duration_since(*t) < horizon);
            !entries.is_empty()
        });

        // Read-only lookup first (not `entry().or_default()`): a call that
        // ends up denying below must not leave a freshly-inserted empty
        // entry for `key` sitting in the map — that would defeat the sweep
        // above for a key that's denied on every call it's ever seen on.
        let existing = self.windows.get(key);
        if self.messages_per_minute > 0 {
            let count_in_minute = existing
                .map(|e| e.iter().filter(|(t, _)| now.duration_since(*t) < MINUTE).count())
                .unwrap_or(0);
            if count_in_minute as u32 >= self.messages_per_minute {
                return false;
            }
        }
        if self.bytes_per_hour > 0 {
            let bytes_in_hour: u64 =
                existing.map(|e| e.iter().map(|(_, b)| b).sum()).unwrap_or(0);
            if bytes_in_hour + bytes > self.bytes_per_hour {
                return false;
            }
        }
        self.windows.entry(key.to_string()).or_default().push_back((now, bytes));
        true
    }
}

/// Per-protocol sliding-window limiter used for transport egress budgets
/// (spec §4/§45 / config `transport_budgets`). Shares `SenderLimiter`'s
/// window-math shape; checked in the delivery pump (`engine::process_due`)
/// right before a Send goes out, with priority-0 (emergency) deliveries
/// bypassing it entirely.
#[derive(Default)]
pub struct BudgetLimiter {
    windows: HashMap<String, VecDeque<Instant>>,
}

impl BudgetLimiter {
    pub fn new() -> BudgetLimiter {
        BudgetLimiter::default()
    }

    /// True (and records) if `protocol` has sent fewer than `per_minute`
    /// messages in the trailing minute; false (nothing recorded) otherwise.
    /// `per_minute` of 0 always allows and never touches `self.windows`.
    pub fn allow(&mut self, protocol: &str, per_minute: u32, now: Instant) -> bool {
        if per_minute == 0 {
            return true;
        }
        let entry = self.windows.entry(protocol.to_string()).or_default();
        entry.retain(|t| now.duration_since(*t) < MINUTE);
        if entry.len() as u32 >= per_minute {
            return false;
        }
        entry.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_config_always_allows_and_accumulates_no_per_key_state() {
        let mut lim = SenderLimiter::new(0, 0);
        let now = Instant::now();
        for _ in 0..5 {
            assert!(lim.allow("k", 1_000_000, now));
        }
        assert!(lim.windows.is_empty(), "zero config must never allocate per-key state");
    }

    #[test]
    fn message_count_allows_n_then_denies() {
        let mut lim = SenderLimiter::new(2, 0);
        let now = Instant::now();
        assert!(lim.allow("k", 10, now));
        assert!(lim.allow("k", 10, now));
        assert!(!lim.allow("k", 10, now), "third message within the minute must be denied");
    }

    #[test]
    fn message_count_window_expiry_reallows() {
        let mut lim = SenderLimiter::new(1, 0);
        let t0 = Instant::now();
        assert!(lim.allow("k", 1, t0));
        assert!(!lim.allow("k", 1, t0 + Duration::from_secs(30)),
            "still inside the same 1-minute window");
        assert!(lim.allow("k", 1, t0 + Duration::from_secs(61)),
            "a full minute has passed, window must have rolled over");
    }

    #[test]
    fn bytes_budget_denies_even_when_message_count_is_unlimited() {
        let mut lim = SenderLimiter::new(0, 100);
        let now = Instant::now();
        assert!(lim.allow("k", 60, now));
        assert!(!lim.allow("k", 60, now),
            "60 + 60 exceeds the 100-byte budget even though message count is unlimited");
    }

    #[test]
    fn message_count_denies_even_when_bytes_are_tiny() {
        let mut lim = SenderLimiter::new(1, 0);
        let now = Instant::now();
        assert!(lim.allow("k", 1, now));
        assert!(!lim.allow("k", 1, now),
            "message count is exhausted even though the byte budget (unlimited) has room");
    }

    #[test]
    fn bytes_window_is_an_hour_independent_of_the_minute_message_window() {
        let mut lim = SenderLimiter::new(0, 100);
        let t0 = Instant::now();
        assert!(lim.allow("k", 60, t0));
        // 90s later: the message-count window (a minute) would have rolled
        // over, but the byte budget's window is an hour, so the earlier 60
        // bytes must still count.
        assert!(!lim.allow("k", 60, t0 + Duration::from_secs(90)));
        // a full hour later, the byte window has rolled over too.
        assert!(lim.allow("k", 60, t0 + Duration::from_secs(3601)));
    }

    #[test]
    fn different_keys_have_independent_windows() {
        let mut lim = SenderLimiter::new(1, 0);
        let now = Instant::now();
        assert!(lim.allow("a", 1, now));
        assert!(lim.allow("b", 1, now), "a different sender key must have its own budget");
        assert!(!lim.allow("a", 1, now));
    }

    /// Regression guard for unbounded memory growth: a key that's allowed
    /// once and never revisited must not keep its map entry alive forever.
    /// This is the abuse case the global prune-on-access sweep exists for —
    /// a hostile sender on a public node minting a fresh native_ref (key)
    /// per message.
    #[test]
    fn stale_keys_are_pruned_from_the_map_not_just_their_own_windows() {
        let mut lim = SenderLimiter::new(0, 100);
        let t0 = Instant::now();
        for i in 0..50 {
            assert!(lim.allow(&format!("churn-{i}"), 1, t0));
        }
        assert_eq!(lim.windows.len(), 50);

        // one more call, from a brand-new key, over an hour later: every
        // churned key's window has expired, and this fresh key is the only
        // one touched at t1, so the whole map must collapse to just it.
        let t1 = t0 + Duration::from_secs(3_601);
        assert!(lim.allow("fresh", 1, t1));
        assert_eq!(lim.windows.len(), 1, "stale keys must be pruned, not just their windows");
        assert!(lim.windows.contains_key("fresh"));
    }

    /// Regression guard: a messages-per-minute-only config (no byte budget)
    /// must prune stale entries at the minute horizon, not linger on the
    /// hour horizon the byte dimension needs — a stale key must age out
    /// within a bit over a minute, not sit in the map for up to an hour
    /// doing nothing useful.
    #[test]
    fn message_only_config_prunes_at_the_minute_horizon_not_the_hour() {
        let mut lim = SenderLimiter::new(1, 0);
        let t0 = Instant::now();
        assert!(lim.allow("stale", 1, t0));
        assert_eq!(lim.windows.len(), 1);

        // just past a minute (well short of an hour): the stale key's only
        // entry is older than the minute horizon and must be pruned away
        // on the very next call, even though a different key is the one
        // actually being looked up.
        let t1 = t0 + Duration::from_secs(61);
        assert!(lim.allow("fresh", 1, t1));
        assert_eq!(lim.windows.len(), 1, "the message-only config must not wait a full hour to prune");
        assert!(lim.windows.contains_key("fresh"));
    }

    /// A key denied on its very first call (nothing to prune yet, because
    /// nothing was ever recorded for it) must not leave a freshly-inserted,
    /// permanently-empty entry sitting in the map — that would defeat the
    /// point of the prune sweep for a key that never once gets through.
    #[test]
    fn a_denied_call_does_not_insert_an_empty_entry_for_a_brand_new_key() {
        let mut lim = SenderLimiter::new(0, 10); // bytes-only, tiny budget
        let now = Instant::now();
        assert!(!lim.allow("too-big", 20, now),
            "20 bytes exceeds the 10-byte budget on the very first call");
        assert!(lim.windows.is_empty(),
            "a key denied on its first-ever call must never appear in the map");
    }

    #[test]
    fn budget_limiter_allows_n_then_denies_then_reallows_after_expiry() {
        let mut lim = BudgetLimiter::new();
        let t0 = Instant::now();
        assert!(lim.allow("mqtt", 2, t0));
        assert!(lim.allow("mqtt", 2, t0));
        assert!(!lim.allow("mqtt", 2, t0), "third send within the minute must be denied");
        assert!(lim.allow("mqtt", 2, t0 + Duration::from_secs(61)),
            "window must have rolled over after a minute");
    }

    #[test]
    fn budget_limiter_zero_per_minute_always_allows() {
        let mut lim = BudgetLimiter::new();
        let now = Instant::now();
        for _ in 0..5 {
            assert!(lim.allow("mqtt", 0, now));
        }
        assert!(lim.windows.is_empty(), "zero config must never allocate per-key state");
    }
}
