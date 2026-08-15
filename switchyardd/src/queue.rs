use std::time::Duration;

#[allow(dead_code)] // consumed by engine wiring (Task 9); remove allow when used
pub const MAX_ATTEMPTS: u32 = 8;

/// Exponential-ish backoff per spec §42: 5s, 30s, 2m, 10m, then 1h forever.
#[allow(dead_code)] // consumed by engine wiring (Task 9); remove allow when used
pub fn backoff(attempt: u32) -> Duration {
    Duration::from_secs(match attempt {
        0 | 1 => 5,
        2 => 30,
        3 => 120,
        4 => 600,
        _ => 3600,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn backoff_schedule_matches_spec() {
        assert_eq!(backoff(1), Duration::from_secs(5));
        assert_eq!(backoff(2), Duration::from_secs(30));
        assert_eq!(backoff(3), Duration::from_secs(120));
        assert_eq!(backoff(4), Duration::from_secs(600));
        assert_eq!(backoff(5), Duration::from_secs(3600));
        assert_eq!(backoff(99), Duration::from_secs(3600));
    }
}
