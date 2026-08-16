//! Quota enforcement primitives (spec §45 backpressure): sliding-window
//! counters that gate ingress before it ever reaches storage.
//!
//! Both limiters here are in-memory only. // ponytail: a restart just gives
//! every key a fresh window -- that's an acceptable reset for a rate limiter
//! (nobody is owed a persisted quota across a daemon bounce), so there's no
//! sqlite table backing this, unlike `dedup`'s TTL cache which shares the
//! same "in-memory, prune on access" shape for the same reason.

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
        let entry = self.windows.entry(key.to_string()).or_default();
        // Prune to the longer of the two windows up front (prune-on-access,
        // no background sweep); the per-minute message count below then
        // filters this same pruned history down further for its own,
        // shorter window.
        entry.retain(|(t, _)| now.duration_since(*t) < HOUR);

        if self.messages_per_minute > 0 {
            let count_in_minute =
                entry.iter().filter(|(t, _)| now.duration_since(*t) < MINUTE).count();
            if count_in_minute as u32 >= self.messages_per_minute {
                return false;
            }
        }
        if self.bytes_per_hour > 0 {
            let bytes_in_hour: u64 = entry.iter().map(|(_, b)| b).sum();
            if bytes_in_hour + bytes > self.bytes_per_hour {
                return false;
            }
        }
        entry.push_back((now, bytes));
        true
    }
}

/// Per-protocol sliding-window limiter used for transport egress budgets
/// (spec §45 / config `transport_budgets`). Defined here (Task 3) because it
/// shares `SenderLimiter`'s window-math shape; wired into the delivery pump
/// by Task 4.
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
    #[allow(dead_code)] // consumed by transport budget scheduling (Task 4); remove allow when used
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
