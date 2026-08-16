use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub fn key(
    protocol: &str,
    sender: &str,
    endpoint: &str,
    body: &str,
    created_at: Option<DateTime<Utc>>,
    attachment_shas: &[String],
) -> String {
    let ts = created_at.map(|t| t.timestamp().to_string()).unwrap_or_default();
    // sorted so the same set of attachments, resent with the shas in a
    // different order (e.g. a plugin that doesn't preserve ordering),
    // still dedups against the original.
    let mut sorted: Vec<&str> = attachment_shas.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let shas = sorted.join(",");
    hex::encode(Sha256::digest(
        format!("{protocol}|{sender}|{endpoint}|{ts}|{body}|{shas}").as_bytes(),
    ))
}

pub struct Dedup {
    ttl: Duration,
    seen: HashMap<String, Instant>,
}

impl Dedup {
    pub fn new(ttl: Duration) -> Dedup {
        Dedup { ttl, seen: HashMap::new() }
    }

    /// True if `key` has already been seen within the TTL. Prunes expired
    /// entries but never inserts: callers that only want to peek (e.g. to
    /// decide whether to short-circuit before a rate-limit check) must not
    /// have that peek itself count as "seen" for a message that ends up
    /// rate-limited and dropped.
    pub fn is_duplicate(&mut self, key: &str, now: Instant) -> bool {
        // O(n) prune per call, in-memory only (restart forgets the
        // cache). Fine at gateway volumes; move to the sqlite dedup table if
        // restart-replay ever bites.
        self.seen.retain(|_, t| now.duration_since(*t) < self.ttl);
        self.seen.contains_key(key)
    }

    /// Records `key` as seen as of `now`. Call once a message has cleared
    /// whatever gates (e.g. rate limiting) must not themselves be dedup'd
    /// away on retry.
    pub fn record(&mut self, key: &str, now: Instant) {
        self.seen.insert(key.to_string(), now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn first_seen_is_new_repeat_is_duplicate() {
        let mut d = Dedup::new(Duration::from_secs(60));
        let now = Instant::now();
        assert!(!d.is_duplicate("k1", now));
        d.record("k1", now);
        assert!(d.is_duplicate("k1", now));
        assert!(!d.is_duplicate("k2", now));
    }

    #[test]
    fn entries_expire_after_ttl() {
        let mut d = Dedup::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(!d.is_duplicate("k", t0));
        d.record("k", t0);
        assert!(d.is_duplicate("k", t0 + Duration::from_secs(59)));
        assert!(!d.is_duplicate("k", t0 + Duration::from_secs(61)));
    }

    #[test]
    fn peek_alone_does_not_record() {
        // is_duplicate must be a pure peek: calling it without a matching
        // record() must never itself mark the key as seen (this is the
        // property the rate-limit-before-record ordering in engine.rs
        // depends on).
        let mut d = Dedup::new(Duration::from_secs(60));
        let now = Instant::now();
        assert!(!d.is_duplicate("k", now));
        assert!(!d.is_duplicate("k", now));
        assert!(!d.is_duplicate("k", now));
    }

    /// Regression guard for the peek/record split: replays engine.rs's exact
    /// `handle_inbound` sequence (peek dedup -> rate-limit check -> record
    /// only on accept) against a 1-message-per-minute sender limit. Before
    /// the split, `record` happened up front alongside the peek, so a
    /// rate-limited message's key was recorded as "seen" for the full dedup
    /// TTL — its retransmission after the rate-limit window rolled over
    /// would be silently swallowed as a duplicate instead of going through.
    #[test]
    fn rate_limited_message_is_not_recorded_so_a_later_retry_is_accepted() {
        use crate::limits::SenderLimiter;

        let mut dedup = Dedup::new(Duration::from_secs(3600));
        let mut limiter = SenderLimiter::new(1, 0);
        let sender_key = "plugin|sender";
        let key_a = "message-a";
        let key_b = "message-b";

        // Message A fills the sender's 1-per-minute budget.
        let t0 = Instant::now();
        assert!(!dedup.is_duplicate(key_a, t0));
        assert!(limiter.allow(sender_key, 0, t0), "message A has budget");
        dedup.record(key_a, t0);

        // Message B (distinct content, distinct dedup key) arrives right
        // after: not a duplicate, but the sender's budget is exhausted, so
        // the limiter denies it. Per the fixed ordering, engine.rs must NOT
        // call `record` for a denied message.
        assert!(!dedup.is_duplicate(key_b, t0), "message B is new content, not a duplicate");
        assert!(!limiter.allow(sender_key, 0, t0), "message B is denied: budget exhausted");
        // (no dedup.record(key_b, ..) here — this is the fix under test)

        // A full minute later (rate-limit window rolled over), the sender
        // retransmits the SAME message B. Because the earlier, rate-limited
        // attempt was never recorded, the dedup peek must still read it as
        // fresh, and the limiter (window elapsed) must now allow it: the
        // retry is accepted end to end.
        let t1 = t0 + Duration::from_secs(61);
        assert!(!dedup.is_duplicate(key_b, t1),
            "message B was rate-limited, never recorded, so must not dedup-collide on retry");
        assert!(limiter.allow(sender_key, 0, t1), "rate-limit window has rolled over");
        dedup.record(key_b, t1);
        assert!(dedup.is_duplicate(key_b, t1), "the accepted retry is now recorded as seen");
    }

    #[test]
    fn key_varies_by_every_component() {
        let base = key("p", "s", "e", "b", None, &[]);
        assert_ne!(base, key("q", "s", "e", "b", None, &[]));
        assert_ne!(base, key("p", "t", "e", "b", None, &[]));
        assert_ne!(base, key("p", "s", "f", "b", None, &[]));
        assert_ne!(base, key("p", "s", "e", "c", None, &[]));
        assert_eq!(base, key("p", "s", "e", "b", None, &[]));
    }

    #[test]
    fn key_is_sensitive_to_attachment_shas_but_order_independent() {
        let none = key("p", "s", "e", "b", None, &[]);
        let one = key("p", "s", "e", "b", None, &["sha1".to_string()]);
        let two = key("p", "s", "e", "b", None, &["sha1".to_string(), "sha2".to_string()]);
        assert_ne!(none, one, "attaching a file must change the key");
        assert_ne!(one, two, "a different set of attachments must change the key");

        // same set, different order on the wire: must dedup to the same key
        let forward = key("p", "s", "e", "b", None,
            &["sha1".to_string(), "sha2".to_string()]);
        let reversed = key("p", "s", "e", "b", None,
            &["sha2".to_string(), "sha1".to_string()]);
        assert_eq!(forward, reversed, "attachment order must not affect the key");
    }
}
