use rand::Rng;

/// Generates a 6-digit verification code using OS randomness.
/// Uses rand::rngs::OsRng for cryptographically secure randomness.
// engine::initiate_link is its only caller, and that function's own caller
// (the admin API) doesn't land until Task 4 — unreachable from `main` in a
// non-test build until then; remove allow when admin.rs wires initiate_link.
#[allow(dead_code)]
pub fn generate_code() -> String {
    let mut rng = rand::rngs::OsRng;
    let code: u32 = rng.gen_range(0..=999_999);
    format!("{:06}", code)
}

/// Masks a reference by keeping first 2 and last 4 chars for refs longer than 8,
/// otherwise returns "****".
///
/// Operates on chars, not bytes, to safely handle multi-byte UTF-8 sequences.
///
/// Examples:
/// - "signal:+14155551234" (18 chars) -> "si****1234"
/// - "lxmf:aabbccdd" (12 chars) -> "lx****ccdd"
/// - "short" (5 chars) -> "****"
pub fn mask_ref(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() > 8 {
        let first: String = chars[..2].iter().collect();
        let last: String = chars[chars.len() - 4..].iter().collect();
        format!("{}****{}", first, last)
    } else {
        "****".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_code_returns_6_digits() {
        for _ in 0..100 {
            let code = generate_code();
            assert_eq!(code.len(), 6, "code should be exactly 6 characters");
            assert!(code.chars().all(|c| c.is_numeric()), "code should contain only digits");
        }
    }

    #[test]
    fn generate_code_range_is_000000_to_999999() {
        let mut min = u32::MAX;
        let mut max = u32::MIN;
        for _ in 0..1000 {
            let code = generate_code();
            let num = code.parse::<u32>().unwrap();
            min = min.min(num);
            max = max.max(num);
        }
        // With 1000 samples, we expect to see values spread across the range.
        // Very loose check: just verify we see both small and large values.
        assert!(min < 100_000, "should see some codes in lower range");
        assert!(max > 900_000, "should see some codes in upper range");
    }

    #[test]
    fn mask_ref_long_strings() {
        assert_eq!(mask_ref("signal:+14155551234"), "si****1234");
        assert_eq!(mask_ref("lxmf:aabbccdd"), "lx****ccdd");
        assert_eq!(mask_ref("protocol:reference_data"), "pr****data");
    }

    #[test]
    fn mask_ref_short_strings() {
        assert_eq!(mask_ref("short"), "****");
        assert_eq!(mask_ref("1234567"), "****");
        assert_eq!(mask_ref("12345678"), "****");
        assert_eq!(mask_ref(""), "****");
        assert_eq!(mask_ref("a"), "****");
    }

    #[test]
    fn mask_ref_exactly_9_chars() {
        // Exactly 9 chars is > 8, so should be masked (first 2 + last 4)
        assert_eq!(mask_ref("123456789"), "12****6789");
    }

    #[test]
    fn mask_ref_non_ascii_char_boundary_safety() {
        // Test with non-ASCII at char boundaries. These would panic with byte-slicing at char boundaries.
        // "aαbcdefgh" is 9 chars: a(1 byte) α(2 bytes) b-h(1 byte each)
        // Byte slicing [..2] would hit middle of α, causing panic; char-safe slicing works.
        assert_eq!(mask_ref("aαbcdefgh"), "aα****efgh");

        // Test with emoji that takes 4 bytes. 9 chars total: "😀12345678"
        // First 2 chars: "😀1", last 4: "5678"
        assert_eq!(mask_ref("😀12345678"), "😀1****5678");

        // Test with mixed: ASCII + multi-byte. 10 chars: "signal:abc😀"
        // First 2 chars: "si", last 4: "abc😀"
        let result = mask_ref("signal:abc😀");
        assert_eq!(result, "si****abc😀");
    }
}
