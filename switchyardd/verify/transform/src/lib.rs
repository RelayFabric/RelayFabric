//! Checks that the two truncation stages of the daemon never return more
//! than their limit. Read `VERIFY.md` in this folder before you change
//! anything here or in `switchyardd/src/transform.rs`.
//!
//! This crate compiles the daemon's real `transform.rs` by path, so every
//! check runs the code that ships and not a copy of it.

#[path = "../../../src/transform.rs"]
pub mod transform;

/// Bounded proofs, run by `cargo kani`. Each harness covers every string of
/// one exact byte length: with a length that the solver sees as a constant
/// it finishes in seconds, and with a symbolic length it does not finish.
#[cfg(kani)]
mod proofs {
    use super::transform::{render, truncate_body};

    /// Any valid UTF-8 string of exactly `N` bytes: every char, of every
    /// encoded width, in every position that fits.
    fn any_str<const N: usize>(buf: &[u8; N]) -> &str {
        kani::assume(core::str::from_utf8(buf).is_ok());
        // SAFETY: the line above keeps only byte arrays that std accepts as
        // UTF-8. The str is built from the array and not taken out of the
        // `Result` of `from_utf8`, because that hides the length from the
        // solver.
        unsafe { core::str::from_utf8_unchecked(buf) }
    }

    /// The number of chars in valid UTF-8: every byte that does not continue
    /// a char (`10xxxxxx`) starts one. `char_count_matches_std_*` proves that
    /// this agrees with `str::chars().count()`. The harnesses count this way
    /// because the solver cannot finish `chars()` over a heap string.
    fn char_count(s: &str) -> usize {
        let mut n = 0;
        for b in s.as_bytes() {
            if (*b & 0xC0) != 0x80 {
                n += 1;
            }
        }
        n
    }

    fn char_count_matches_std<const N: usize>() {
        let buf: [u8; N] = kani::any();
        let s = any_str(&buf);
        assert!(char_count(s) == s.chars().count());
    }

    /// Rule `body-limit` for one body length and one limit: `truncate_body`
    /// returns at most `max_chars` chars.
    fn truncate_body_fits_limit<const N: usize>(max_chars: u32) {
        let buf: [u8; N] = kani::any();
        let body = any_str(&buf);
        let out = truncate_body(body, max_chars);
        assert!(
            char_count(&out) <= max_chars as usize,
            "truncate_body returned more chars than max_chars"
        );
        // Both branches of `truncate_body` must be reachable in this harness.
        kani::cover!(char_count(body) > max_chars as usize, "the body is cut");
        kani::cover!(
            char_count(body) <= max_chars as usize,
            "the body fits and is returned unchanged"
        );
    }

    /// Rule `body-limit` for every limit from the byte length of the body
    /// up: the body fits, so it comes back with its `N` bytes. A string has
    /// at most as many chars as bytes, so that is at most `max_chars` chars.
    fn truncate_body_keeps_what_fits<const N: usize>() {
        let buf: [u8; N] = kani::any();
        let body = any_str(&buf);
        let max_chars: u32 = kani::any();
        kani::assume(max_chars >= 1 && max_chars as usize >= N);
        let out = truncate_body(body, max_chars);
        assert!(
            out.len() == N,
            "truncate_body changed a body that fits in max_chars"
        );
    }

    /// Rule `body-limit` for the empty body, which is the only string of 0
    /// bytes, with every limit from 1 up. It is written as a literal because
    /// a symbolic array of length 0 costs the solver three minutes here.
    fn truncate_body_keeps_empty() {
        let max_chars: u32 = kani::any();
        kani::assume(max_chars >= 1);
        let out = truncate_body("", max_chars);
        assert!(out.is_empty(), "truncate_body changed an empty body");
    }

    /// Rule `payload-limit`: `render` returns at most `max_payload` bytes.
    /// `tag` is `None`, so `body` here is the whole assembled string that
    /// `render` truncates. The `Some(tag)` arm is taken by the harnesses of
    /// `render_tagged_fits_limit` below, at smaller sizes.
    fn render_fits_limit<const N: usize>() {
        let buf: [u8; N] = kani::any();
        let full = any_str(&buf);
        let limit: usize = kani::any();
        let out = render(None, full, Some(limit));
        assert!(
            out.len() <= limit,
            "render returned more bytes than max_payload"
        );
    }

    macro_rules! harnesses {
        ($($name:ident, $unwind:literal, $body:expr;)*) => {$(
            #[kani::proof]
            #[kani::unwind($unwind)]
            fn $name() {
                $body
            }
        )*};
    }

    // The unwind bound of each harness is the byte length plus two, and at
    // least six for the loops of std's formatter. Kani fails a harness with
    // "unwinding assertion" when a loop needs more.
    harnesses! {
        char_count_matches_std_4, 6, char_count_matches_std::<4>();
        char_count_matches_std_8, 10, char_count_matches_std::<8>();

        // Every body of 0 to 4 bytes with every max_chars from 1 up.
        truncate_body_0_bytes_any_limit, 6, truncate_body_keeps_empty();
        truncate_body_1_byte_any_limit, 6, truncate_body_keeps_what_fits::<1>();
        truncate_body_2_bytes_limit_1, 6, truncate_body_fits_limit::<2>(1);
        truncate_body_2_bytes_limit_2_up, 6, truncate_body_keeps_what_fits::<2>();
        truncate_body_3_bytes_limit_1, 6, truncate_body_fits_limit::<3>(1);
        truncate_body_3_bytes_limit_2, 6, truncate_body_fits_limit::<3>(2);
        truncate_body_3_bytes_limit_3_up, 6, truncate_body_keeps_what_fits::<3>();
        truncate_body_4_bytes_limit_1, 6, truncate_body_fits_limit::<4>(1);
        truncate_body_4_bytes_limit_2, 6, truncate_body_fits_limit::<4>(2);
        truncate_body_4_bytes_limit_3, 6, truncate_body_fits_limit::<4>(3);
        truncate_body_4_bytes_limit_4_up, 6, truncate_body_keeps_what_fits::<4>();

        // Every assembled string of 0 to 8 bytes with every max_payload.
        render_0_bytes_any_limit, 6, render_fits_limit::<0>();
        render_1_byte_any_limit, 6, render_fits_limit::<1>();
        render_2_bytes_any_limit, 6, render_fits_limit::<2>();
        render_3_bytes_any_limit, 6, render_fits_limit::<3>();
        render_4_bytes_any_limit, 6, render_fits_limit::<4>();
        render_5_bytes_any_limit, 7, render_fits_limit::<5>();
        render_6_bytes_any_limit, 8, render_fits_limit::<6>();
        render_7_bytes_any_limit, 9, render_fits_limit::<7>();
        render_8_bytes_any_limit, 10, render_fits_limit::<8>();
    }

    /// Not a rule: shows that the 8-byte `render` harness reaches every
    /// branch of `render`, so that its pass is not an empty one. Each
    /// `cover!` below must be reported as SATISFIED.
    #[kani::proof]
    #[kani::unwind(10)]
    fn render_reaches_every_branch() {
        let buf: [u8; 8] = kani::any();
        let full = any_str(&buf);
        let limit: usize = kani::any();
        let out = render(None, full, Some(limit));
        let cut = limit < full.len();
        kani::cover!(!cut && out.len() == 8, "it fits: returned unchanged");
        kani::cover!(
            cut && limit < 3 && out.len() == limit,
            "limit under 3: cut at the limit, no marker"
        );
        kani::cover!(
            cut && limit < 3 && out.len() < limit,
            "limit under 3: the cut walked back to a char boundary"
        );
        kani::cover!(
            cut && limit >= 3 && out.len() == limit,
            "limit of 3 or more: cut at limit - 3, plus the marker"
        );
        kani::cover!(
            cut && limit >= 3 && out.len() + 3 == limit,
            "limit of 3 or more: the cut walked back 3 bytes, the most a char allows"
        );
    }

    /// Stands in for `Arguments::estimated_capacity` in the harnesses that
    /// take the `Some(tag)` arm of `render`. `format!` sizes its String with
    /// that function. The solver does not treat its value as a constant, and
    /// from the second piece of output on it explores formatters that the
    /// code never calls, so it does not finish. The capacity is only a hint
    /// for the first allocation: a constant in its place changes no result
    /// of `render`. The lifetime bound makes the signature match the one
    /// that Kani expects of a stub for this method.
    fn no_capacity_hint<'a>(_args: &core::fmt::Arguments<'a>) -> usize
    where
        'a: 'a,
    {
        0
    }

    /// Rule `payload-limit` on the `Some(tag)` arm: every tag of exactly `T`
    /// bytes with every body of exactly `B` bytes and every `max_payload`.
    /// The assembled string is `"[tag]\nbody"`, `T + B + 3` bytes.
    fn render_tagged_fits_limit<const T: usize, const B: usize>() {
        let tag: [u8; T] = kani::any();
        let body: [u8; B] = kani::any();
        let limit: usize = kani::any();
        let out = render(Some(any_str(&tag)), any_str(&body), Some(limit));
        assert!(
            out.len() <= limit,
            "render returned more bytes than max_payload"
        );
        // Both outcomes must be reachable, so that the pass is not an empty one.
        kani::cover!(out.len() < T + B + 3, "render truncated a tagged string");
        kani::cover!(
            out.len() == T + B + 3,
            "render returned a tagged string whole"
        );
    }

    // These need `-Z stubbing` on the Kani command line.
    macro_rules! tagged_harnesses {
        ($($name:ident: $t:literal, $b:literal;)*) => {$(
            #[kani::proof]
            #[kani::unwind(12)]
            #[kani::stub(std::fmt::Arguments::estimated_capacity, no_capacity_hint)]
            fn $name() {
                render_tagged_fits_limit::<$t, $b>()
            }
        )*};
    }

    // Every tag of 1 to 2 bytes with every body of 2 to 3 bytes and every
    // max_payload.
    tagged_harnesses! {
        render_tag_1_body_2_any_limit: 1, 2;
        render_tag_1_body_3_any_limit: 1, 3;
        render_tag_2_body_2_any_limit: 2, 2;
        render_tag_2_body_3_any_limit: 2, 3;
    }

    /// FINDING, not a passing check: `truncate_body` breaks rule `body-limit`
    /// when `max_chars` is 0. This harness fails on the current code. It is
    /// behind the `findings` feature so that the default run passes.
    #[cfg(feature = "findings")]
    #[kani::proof]
    #[kani::unwind(6)]
    fn finding_truncate_body_limit_zero() {
        let buf: [u8; 1] = kani::any();
        let body = any_str(&buf);
        let out = truncate_body(body, 0);
        assert!(
            char_count(&out) == 0,
            "truncate_body returned a char although max_chars is 0"
        );
    }
}
