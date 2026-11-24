//! Generated-input tests of the two truncation rules, on the daemon's real
//! `transform.rs`. They reach the sizes and the `Some(tag)` arm of `render`
//! that the Kani proofs in `src/lib.rs` cannot. See `VERIFY.md`.
//!
//! A pass here is a test result and not a proof: it covers exactly the
//! inputs that these loops generate.

use switchyardd_verify_transform::transform::{render, truncate_body};

/// One char of each UTF-8 width: 1, 2, 3, and 4 bytes.
const ALPHABET: [char; 4] = ['a', 'é', 'あ', '😀'];

/// Calls `f` with every string of 0 to `max_chars` chars over `ALPHABET`.
fn every_string(max_chars: usize, f: &mut impl FnMut(&str)) {
    fn grow(s: &mut String, left: usize, f: &mut impl FnMut(&str)) {
        f(s);
        if left == 0 {
            return;
        }
        for c in ALPHABET {
            s.push(c);
            grow(s, left - 1, f);
            s.pop();
        }
    }
    grow(&mut String::new(), max_chars, f);
}

/// What `render` did with one input, told from the outside.
#[derive(Default, Debug)]
struct RenderRuns {
    fits: u64,
    small_limit_cut_at_limit: u64,
    small_limit_walked_back: u64,
    marker_cut_at_budget: u64,
    marker_walked_back: u64,
}

impl RenderRuns {
    /// Asserts rule `payload-limit` for one call and records which branch of
    /// `render` it took.
    fn check(&mut self, tag: Option<&str>, body: &str, limit: usize) {
        let full_len = match tag {
            Some(t) => t.len() + body.len() + 3, // "[" + tag + "]\n" + body
            None => body.len(),
        };
        let out = render(tag, body, Some(limit));
        assert!(
            out.len() <= limit,
            "render returned {} bytes for max_payload {limit}: tag {tag:?}, body {body:?}",
            out.len()
        );
        if full_len <= limit {
            assert_eq!(out.len(), full_len, "a string that fits must not change");
            self.fits += 1;
        } else if limit < 3 {
            if out.len() == limit {
                self.small_limit_cut_at_limit += 1;
            } else {
                self.small_limit_walked_back += 1;
            }
        } else if out.len() == limit {
            self.marker_cut_at_budget += 1;
        } else {
            self.marker_walked_back += 1;
        }
    }

    /// A pass is empty if a branch never ran.
    fn assert_every_branch_ran(&self) {
        assert!(
            self.fits > 0
                && self.small_limit_cut_at_limit > 0
                && self.small_limit_walked_back > 0
                && self.marker_cut_at_budget > 0
                && self.marker_walked_back > 0,
            "a branch of render never ran: {self:?}"
        );
    }
}

/// Asserts rule `body-limit` for one call. Returns true if the body was cut.
fn check_truncate_body(body: &str, max_chars: u32) -> bool {
    let out = truncate_body(body, max_chars);
    let got = out.chars().count();
    assert!(
        got <= max_chars as usize,
        "truncate_body returned {got} chars for max_chars {max_chars}: body {body:?}"
    );
    out != body
}

#[test]
fn truncate_body_every_small_string_and_limit() {
    let (mut cut, mut unchanged) = (0u64, 0u64);
    // 349,525 bodies of 0 to 9 chars (0 to 36 bytes), each with every limit
    // from 1 to two past the longest.
    every_string(9, &mut |body| {
        for max_chars in 1..=11 {
            if check_truncate_body(body, max_chars) {
                cut += 1;
            } else {
                unchanged += 1;
            }
        }
    });
    println!("truncate_body, small strings: {cut} cut, {unchanged} unchanged");
    assert!(
        cut > 0 && unchanged > 0,
        "a branch of truncate_body never ran"
    );
}

#[test]
fn render_every_small_string_tag_and_limit() {
    // 22 tags: none, and every string of 0 to 2 chars.
    let mut tags: Vec<Option<String>> = vec![None];
    every_string(2, &mut |t| tags.push(Some(t.to_string())));
    let mut runs = RenderRuns::default();
    // 21,845 bodies of 0 to 7 chars (0 to 28 bytes), with each tag, and
    // every limit from 0 to one past the length of the assembled string.
    every_string(7, &mut |body| {
        for tag in &tags {
            let full_len = tag.as_ref().map_or(0, |t| t.len() + 3) + body.len();
            for limit in 0..=full_len + 1 {
                runs.check(tag.as_deref(), body, limit);
            }
        }
    });
    println!("render, small strings: {runs:?}");
    runs.assert_every_branch_ran();
}

/// A small fixed-seed generator (xorshift64*), so that every run makes the
/// same inputs and the crate needs no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// Any Unicode scalar value, with each UTF-8 width equally likely.
    fn any_char(&mut self) -> char {
        let (lo, hi): (u32, u32) = match self.below(4) {
            0 => (0x00, 0x7F),
            1 => (0x80, 0x7FF),
            2 => (0x800, 0xFFFF),
            _ => (0x1_0000, 0x10_FFFF),
        };
        loop {
            let code = lo + self.below(u64::from(hi - lo) + 1) as u32;
            // The surrogates D800..=DFFF are not chars: draw again.
            if let Some(c) = char::from_u32(code) {
                return c;
            }
        }
    }

    fn any_string(&mut self, max_chars: u64) -> String {
        let n = self.below(max_chars + 1);
        (0..n).map(|_| self.any_char()).collect()
    }
}

#[test]
fn long_generated_inputs() {
    let mut rng = Rng(0x5EED_CAFE_F00D_0001);
    let mut runs = RenderRuns::default();
    let (mut cut, mut unchanged, mut longest) = (0u64, 0u64, 0usize);
    for _ in 0..4000 {
        // Bodies of 0 to 2,500 chars of any width: thousands of bytes, far
        // past the 32 bytes where `str::chars().count()` changes its
        // algorithm.
        let body = rng.any_string(2500);
        longest = longest.max(body.len());
        let chars = body.chars().count() as u64;
        let limits = [
            1,
            2,
            chars.saturating_sub(1).max(1),
            chars.max(1),
            chars + 1,
            1 + rng.below(chars + 2),
            u64::from(u32::MAX),
        ];
        for max_chars in limits {
            if check_truncate_body(&body, max_chars as u32) {
                cut += 1;
            } else {
                unchanged += 1;
            }
        }

        let tag = match rng.below(3) {
            0 => None,
            _ => Some(rng.any_string(40)),
        };
        let full_len = tag.as_ref().map_or(0, |t| t.len() + 3) + body.len();
        let mut limits = vec![
            full_len.saturating_sub(1),
            full_len,
            full_len + 1,
            usize::MAX,
        ];
        limits.extend(0..=8);
        for _ in 0..8 {
            limits.push(rng.below(full_len as u64 + 2) as usize);
        }
        for limit in limits {
            runs.check(tag.as_deref(), &body, limit);
        }
    }
    println!("long inputs: longest body {longest} bytes; truncate_body {cut} cut, {unchanged} unchanged; render {runs:?}");
    assert!(
        cut > 0 && unchanged > 0,
        "a branch of truncate_body never ran"
    );
    assert!(
        longest >= 32,
        "no body reached the chunked char count of std"
    );
    runs.assert_every_branch_ran();
}

/// FINDING, not a passing test: `truncate_body` breaks rule `body-limit`
/// when `max_chars` is 0. It fails on the current code, so it is behind the
/// `findings` feature and the default run passes.
#[cfg(feature = "findings")]
#[test]
fn finding_truncate_body_limit_zero() {
    check_truncate_body("x", 0);
}
