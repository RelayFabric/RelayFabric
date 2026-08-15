use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[allow(dead_code)] // consumed by engine wiring (Task 9); remove allow when used
pub fn key(
    protocol: &str,
    sender: &str,
    endpoint: &str,
    body: &str,
    created_at: Option<DateTime<Utc>>,
) -> String {
    let ts = created_at.map(|t| t.timestamp().to_string()).unwrap_or_default();
    hex::encode(Sha256::digest(
        format!("{protocol}|{sender}|{endpoint}|{ts}|{body}").as_bytes(),
    ))
}

#[allow(dead_code)] // consumed by engine wiring (Task 9); remove allow when used
pub struct Dedup {
    ttl: Duration,
    seen: HashMap<String, Instant>,
}

#[allow(dead_code)] // consumed by engine wiring (Task 9); remove allow when used
impl Dedup {
    pub fn new(ttl: Duration) -> Dedup {
        Dedup { ttl, seen: HashMap::new() }
    }

    /// True if new (and records it), false if already seen.
    pub fn check(&mut self, key: &str, now: Instant) -> bool {
        // ponytail: O(n) prune per call, in-memory only (restart forgets the
        // cache). Fine at gateway volumes; move to the sqlite dedup table if
        // restart-replay ever bites.
        self.seen.retain(|_, t| now.duration_since(*t) < self.ttl);
        if self.seen.contains_key(key) {
            return false;
        }
        self.seen.insert(key.to_string(), now);
        true
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
        assert!(d.check("k1", now));
        assert!(!d.check("k1", now));
        assert!(d.check("k2", now));
    }

    #[test]
    fn entries_expire_after_ttl() {
        let mut d = Dedup::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(d.check("k", t0));
        assert!(!d.check("k", t0 + Duration::from_secs(59)));
        assert!(d.check("k", t0 + Duration::from_secs(61)));
    }

    #[test]
    fn key_varies_by_every_component() {
        let base = key("p", "s", "e", "b", None);
        assert_ne!(base, key("q", "s", "e", "b", None));
        assert_ne!(base, key("p", "t", "e", "b", None));
        assert_ne!(base, key("p", "s", "f", "b", None));
        assert_ne!(base, key("p", "s", "e", "c", None));
        assert_eq!(base, key("p", "s", "e", "b", None));
    }
}
