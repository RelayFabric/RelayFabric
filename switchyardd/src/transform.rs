/// Route-level truncation (design §4, `RouteConfig::render.max_chars`;
/// fix round 1): truncates the MESSAGE BODY only, counting Unicode
/// *characters*, not bytes, so multibyte text truncates predictably
/// regardless of encoding width. The sender tag is NEVER counted or
/// touched here -- callers MUST call this on the body BEFORE assembling it
/// with the tag (see `render` below), so a tag of any length (including an
/// unbounded linked `display_name`) always survives intact. Fix round 1
/// replaced an earlier ruling that truncated the ASSEMBLED `"[tag]\nbody"`
/// string, which let a long tag eat the entire budget and silently drop
/// the body -- `render(Some("VeryLongDisplayName"), "hi", Some(16), None)`
/// used to produce `"[VeryLongDispla…"`.
///
/// `s.chars().count() <= max_chars` is left unchanged (including the
/// boundary case, which must NOT gain an ellipsis it doesn't need);
/// otherwise the first `max_chars - 1` chars are kept and a single `…`
/// appended, landing at exactly `max_chars` chars total. Building the
/// result from `.chars()` rather than a byte index means a multibyte char
/// sitting right at the cut point can never be split. Callers treat
/// `max_chars == 0` as "disabled" and skip calling this at all (see
/// `engine::process_due`).
pub fn truncate_body(body: &str, max_chars: u32) -> String {
    let max_chars = max_chars as usize;
    if body.chars().count() <= max_chars {
        return body.to_string();
    }
    let budget = max_chars.saturating_sub(1);
    let mut out: String = body.chars().take(budget).collect();
    out.push('…');
    out
}

/// Render the destination-facing body: origin tag + payload, truncated to
/// `max_payload` bytes on a char boundary with a visible marker (spec §17,
/// §83). This is the transport-level, hard-floor truncation stage --
/// operates on the ASSEMBLED `"[tag]\nbody"` string and, unlike
/// `truncate_body`'s route-level pass, MAY still truncate into the tag if
/// `max_payload` is tight enough (pre-existing v0.1 behavior: the
/// destination's wire cap is the one truncation stage that isn't a
/// route-level courtesy knob, so it always wins). Callers that want
/// route-level body-only truncation MUST call `truncate_body` on `body`
/// (and append any notes) BEFORE calling this function -- see
/// `engine::process_due`'s two-stage pipeline.
///
/// `tag: None` means the caller's route opted out of the `[tag]\n` prefix
/// entirely (`RouteConfig::render.tag == "none"`) -- this covers BOTH the
/// HMAC alias and, in linked mode, a verified link's display_name, since
/// the caller has already decided what the tag *would* have been before
/// this function ever sees it; passing `None` here is what actually
/// suppresses it.
pub fn render(tag: Option<&str>, body: &str, max_payload: Option<usize>) -> String {
    let full = match tag {
        Some(t) => format!("[{t}]\n{body}"),
        None => body.to_string(),
    };
    let Some(limit) = max_payload else {
        return full;
    };
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
        assert_eq!(
            render(Some("MESH-7F21"), "hello", None),
            "[MESH-7F21]\nhello"
        );
    }

    #[test]
    fn truncates_on_char_boundary_with_marker() {
        let out = render(Some("A-0000"), "héllo wörld this is long", Some(20));
        assert!(out.len() <= 20, "len {} > 20", out.len());
        assert!(out.ends_with('…'));
        assert!(out.starts_with("[A-0000]\n"));
    }

    #[test]
    fn no_truncation_when_it_fits() {
        assert_eq!(render(Some("A-0000"), "hi", Some(200)), "[A-0000]\nhi");
    }

    #[test]
    fn tiny_limits_never_exceed_budget() {
        for limit in 0..=4 {
            let out = render(Some("A"), "hello world", Some(limit));
            assert!(
                out.len() <= limit,
                "limit {limit} produced {} bytes",
                out.len()
            );
        }
    }

    // ---- design §4: route render knobs (tag suppression, max_chars) -------

    #[test]
    fn tag_none_omits_the_prefix_entirely() {
        assert_eq!(render(None, "hello", None), "hello");
    }

    #[test]
    fn tag_none_still_applies_max_payload_truncation() {
        let out = render(None, "hello world this is long", Some(8));
        assert!(out.len() <= 8, "len {} > 8", out.len());
        assert!(out.ends_with('…'));
        assert!(
            !out.contains('['),
            "tag: none must never reintroduce a [tag] prefix: {out}"
        );
    }

    // ---- fix round 1: max_chars is BODY-ONLY, never eats the tag ----------
    //
    // Original ruling (assembled "[tag]\nbody" truncation) let a long tag --
    // e.g. an unbounded linked display_name -- eat the entire max_chars
    // budget and silently drop the body:
    // `render(Some("VeryLongDisplayName"), "hi", Some(16), None)` used to
    // produce `"[VeryLongDispla…"`, 100% body loss with the tag itself cut
    // mid-word. `truncate_body` is now a separate, caller-invoked function
    // that truncates ONLY the message body, called BEFORE the tag is
    // assembled -- the tag can never be shortened by it, no matter how long.

    #[test]
    fn truncate_body_exact_fit_is_unchanged_with_no_ellipsis() {
        assert_eq!(truncate_body("hi", 2), "hi");
        assert!(!truncate_body("hi", 2).contains('…'));
    }

    #[test]
    fn truncate_body_one_over_truncates_with_ellipsis_at_exactly_max_chars() {
        // "hello" is 5 chars; max_chars 4 is one under, so the budget is 3
        // original chars + 1 ellipsis char = exactly 4 chars total.
        let out = truncate_body("hello", 4);
        assert_eq!(out, "hel…");
        assert_eq!(out.chars().count(), 4);
    }

    #[test]
    fn truncate_body_cuts_cleanly_even_when_the_boundary_char_is_multibyte() {
        // "héllo wörld" -- cutting to max_chars 3 lands the boundary right
        // after the multibyte 'é' (a 2-byte UTF-8 char), which a
        // byte-index-based cut could split; a chars()-based cut cannot.
        let out = truncate_body("héllo wörld", 3);
        assert_eq!(out, "hé…");
        assert_eq!(out.chars().count(), 3);
    }

    #[test]
    fn max_chars_truncates_the_body_only_never_the_tag_even_when_the_tag_is_long() {
        // The exact regression from the original ruling: a tag much longer
        // than max_chars must still come through fully intact, and the
        // body must still get truncated (not silently dropped, not
        // silently left untruncated either).
        let tag = "VeryLongDisplayName"; // 20 chars, longer than max_chars below
        let body = truncate_body("this body is much longer than the max_chars budget", 16);
        let out = render(Some(tag), &body, None);
        assert!(
            out.starts_with("[VeryLongDisplayName]\n"),
            "the tag must survive fully intact regardless of its own length: {out}"
        );
        assert!(
            out.ends_with('…'),
            "the body must still be truncated: {out}"
        );
        assert_eq!(body.chars().count(), 16);
    }

    #[test]
    fn body_char_truncate_then_assemble_then_transport_byte_cap_both_apply() {
        // Body is all 3-byte-per-char multibyte text so char-count and
        // byte-count truncation land at very different points -- proves the
        // caller-orchestrated pipeline (truncate_body, THEN render) still
        // stacks: the route-level (char) pass runs first, and the
        // transport-level (byte) pass in `render` still re-truncates the
        // ASSEMBLED "[tag]\nbody" afterward as the hard floor -- which, per
        // the fix round 1 ruling, is pre-existing v0.1 behavior and MAY
        // still eat into the tag if the transport cap is tight enough
        // (unlike max_chars, `max_payload` is not a route-level courtesy
        // knob, it's what the destination's wire actually enforces).
        let body = "あ".repeat(30); // 30 chars, 90 bytes
        let truncated = truncate_body(&body, 20);
        let out = render(Some("A"), &truncated, Some(30));
        assert!(
            out.len() <= 30,
            "transport cap violated: {} bytes: {out:?}",
            out.len()
        );
        assert!(out.starts_with("[A]\n"));
        assert!(out.ends_with('…'));
        // exactly one ellipsis marker: the transport-level pass must have
        // replaced the body-level one, not appended a second.
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
