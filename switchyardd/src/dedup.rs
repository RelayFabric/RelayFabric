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

    /// True if new (and records it), false if already seen.
    pub fn check(&mut self, key: &str, now: Instant) -> bool {
        // O(n) prune per call, in-memory only (restart forgets the
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
