/// Route-level truncation (design §4, `RouteConfig::render.max_chars`):
/// counts Unicode *characters*, not bytes, so multibyte text truncates
/// predictably regardless of encoding width. `s.chars().count() <=
/// max_chars` is left unchanged (including the boundary case, which must
/// NOT gain an ellipsis it doesn't need); otherwise the first `max_chars -
/// 1` chars are kept and a single `…` appended, landing at exactly
/// `max_chars` chars total. Building the result from `.chars()` rather than
/// a byte index means a multibyte char sitting right at the cut point can
/// never be split. Callers treat `max_chars == 0` as "disabled" and skip
/// calling this at all (see `render` below).
fn truncate_chars(s: &str, max_chars: u32) -> String {
    let max_chars = max_chars as usize;
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let budget = max_chars.saturating_sub(1);
    let mut out: String = s.chars().take(budget).collect();
    out.push('…');
    out
}

/// Render the destination-facing body: origin tag + payload, with two
/// independent, stackable truncation stages (design §4, spec §17/§83):
/// route-level `max_chars` (a Unicode character count, operator-configured
/// per route) runs FIRST; transport-level `max_payload` (a byte count, the
/// destination's hard wire cap) runs SECOND and always wins if the result
/// is still over after the route-level pass -- it is the floor a route can
/// never truncate past.
///
/// `tag: None` means the caller's route opted out of the `[tag]\n` prefix
/// entirely (`RouteConfig::render.tag == "none"`) -- this covers BOTH the
/// HMAC alias and, in linked mode, a verified link's display_name, since
/// the caller has already decided what the tag *would* have been before
/// this function ever sees it; passing `None` here is what actually
/// suppresses it.
pub fn render(tag: Option<&str>, body: &str, max_chars: Option<u32>, max_payload: Option<usize>) -> String {
    let full = match tag {
        Some(t) => format!("[{t}]\n{body}"),
        None => body.to_string(),
    };
    let full = match max_chars {
        Some(mc) if mc > 0 => truncate_chars(&full, mc),
        _ => full,
    };
    let Some(limit) = max_payload else { return full };
    if full.len() <= limit {
        return full;
    }

    // For limits < 3 (ellipsis size), truncate without ellipsis
    if limit < 3 {
        let mut cut = limit;
        while cut > 0 && !full.is_char_boundary(cut) {
            cut -= 1;
        }
        return full[..cut].to_string();
    }

    // Normal case: truncate to limit-3 bytes + ellipsis
    let budget = limit - 3;
    let mut cut = budget;
    while cut > 0 && !full.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &full[..cut])
}

/// Builds one gateway-style note line per entry in `dropped`, meant to be
/// appended to the outgoing body so the recipient sees *why* an attachment
/// didn't arrive (notes are message content, never log content).
///
/// `reason` selects the wording:
/// - `"omitted"`: a destination-wide strip (capability missing, or policy
///   rejects attachments outright) — every line reads `[attachment
///   omitted]`, independent of `dropped`'s name/size, so a blanket strip
///   never reveals which files existed.
/// - anything else: treated as the "over ..." clause of a byte-cap drop —
///   each line reads `[dropped <name>: <N> B over <reason>]`. Callers pass
///   e.g. `"1000 B limit"` as `reason` to produce the exact
///   `[dropped <name>: <N> B over <limit> B limit]` wording used for both
///   the per-attachment policy cap and the cumulative frame-size guard.
pub fn attachment_notes(dropped: &[(String, u64)], reason: &str) -> String {
    let mut notes = String::new();
    if reason == "omitted" {
        for _ in dropped {
            notes.push_str("\n[attachment omitted]");
        }
    } else {
        for (name, size) in dropped {
            notes.push_str(&format!("\n[dropped {name}: {size} B over {reason}]"));
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_alias_tag() {
        assert_eq!(render(Some("MESH-7F21"), "hello", None, None), "[MESH-7F21]\nhello");
    }

    #[test]
    fn truncates_on_char_boundary_with_marker() {
        let out = render(Some("A-0000"), "héllo wörld this is long", None, Some(20));
        assert!(out.len() <= 20, "len {} > 20", out.len());
        assert!(out.ends_with('…'));
        assert!(out.starts_with("[A-0000]\n"));
    }

    #[test]
    fn no_truncation_when_it_fits() {
        assert_eq!(render(Some("A-0000"), "hi", None, Some(200)), "[A-0000]\nhi");
    }

    #[test]
    fn tiny_limits_never_exceed_budget() {
        for limit in 0..=4 {
            let out = render(Some("A"), "hello world", None, Some(limit));
            assert!(out.len() <= limit, "limit {limit} produced {} bytes", out.len());
        }
    }

    // ---- design §4: route render knobs (tag suppression, max_chars) -------

    #[test]
    fn tag_none_omits_the_prefix_entirely() {
        assert_eq!(render(None, "hello", None, None), "hello");
    }

    #[test]
    fn tag_none_still_applies_max_payload_truncation() {
        let out = render(None, "hello world this is long", None, Some(8));
        assert!(out.len() <= 8, "len {} > 8", out.len());
        assert!(out.ends_with('…'));
        assert!(!out.contains('['), "tag: none must never reintroduce a [tag] prefix: {out}");
    }

    #[test]
    fn max_chars_exact_fit_is_unchanged_with_no_ellipsis() {
        // "[A]\nhi" is exactly 6 Unicode chars: [ A ] \n h i
        let out = render(Some("A"), "hi", Some(6), None);
        assert_eq!(out, "[A]\nhi");
        assert!(!out.contains('…'));
    }

    #[test]
    fn max_chars_one_over_truncates_with_ellipsis_at_exactly_max_chars() {
        // "[A]\nhi" is 6 chars; max_chars 5 is one under, so the budget is
        // 4 original chars + 1 ellipsis char = exactly 5 chars total.
        let out = render(Some("A"), "hi", Some(5), None);
        assert_eq!(out, "[A]\n…");
        assert_eq!(out.chars().count(), 5);
    }

    #[test]
    fn max_chars_cuts_cleanly_even_when_the_boundary_char_is_multibyte() {
        // "[A]\nhéllo wörld" -- cutting to max_chars 7 lands the boundary
        // right after the multibyte 'é' (a 2-byte UTF-8 char), which a
        // byte-index-based cut could split; a chars()-based cut cannot.
        let out = render(Some("A"), "héllo wörld", Some(7), None);
        assert_eq!(out, "[A]\nhé…");
        assert_eq!(out.chars().count(), 7);
    }

    #[test]
    fn max_chars_truncation_runs_before_max_payload_and_both_apply() {
        // Body is all 3-byte-per-char multibyte text so char-count and
        // byte-count truncation land at very different points -- proves
        // the route-level (char) pass runs first and the transport-level
        // (byte) pass still re-truncates afterward as the hard floor.
        let body = "あ".repeat(30); // 30 chars, 90 bytes
        let out = render(Some("A"), &body, Some(20), Some(30));
        assert!(out.len() <= 30, "transport cap violated: {} bytes: {out:?}", out.len());
        assert!(out.starts_with("[A]\n"));
        assert!(out.ends_with('…'));
        // exactly one ellipsis marker: the transport-level pass must have
        // replaced the route-level one, not appended a second.
        assert_eq!(out.matches('…').count(), 1);
    }

    #[test]
    fn attachment_notes_empty_dropped_list_is_empty_string() {
        assert_eq!(attachment_notes(&[], "omitted"), "");
        assert_eq!(attachment_notes(&[], "1000 B limit"), "");
    }

    #[test]
    fn attachment_notes_omitted_ignores_name_and_size() {
        let dropped = [("a.bin".to_string(), 5u64), ("b.bin".to_string(), 10u64)];
        assert_eq!(
            attachment_notes(&dropped, "omitted"),
            "\n[attachment omitted]\n[attachment omitted]"
        );
    }

    #[test]
    fn attachment_notes_byte_cap_names_the_file_and_the_limit() {
        let dropped = [("big.bin".to_string(), 500u64)];
        assert_eq!(
            attachment_notes(&dropped, "200 B limit"),
            "\n[dropped big.bin: 500 B over 200 B limit]"
        );
    }

    #[test]
    fn attachment_notes_byte_cap_handles_multiple_drops() {
        let dropped = [("a.bin".to_string(), 500u64), ("b.bin".to_string(), 900u64)];
        assert_eq!(
            attachment_notes(&dropped, "200 B limit"),
            "\n[dropped a.bin: 500 B over 200 B limit]\n[dropped b.bin: 900 B over 200 B limit]"
        );
    }
}
