/// Render the destination-facing body: origin tag + payload, truncated to
/// max_payload bytes on a char boundary with a visible marker (spec §17, §83).
pub fn render(alias: &str, body: &str, max_payload: Option<usize>) -> String {
    let full = format!("[{alias}]\n{body}");
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
        assert_eq!(render("MESH-7F21", "hello", None), "[MESH-7F21]\nhello");
    }

    #[test]
    fn truncates_on_char_boundary_with_marker() {
        let out = render("A-0000", "héllo wörld this is long", Some(20));
        assert!(out.len() <= 20, "len {} > 20", out.len());
        assert!(out.ends_with('…'));
        assert!(out.starts_with("[A-0000]\n"));
    }

    #[test]
    fn no_truncation_when_it_fits() {
        assert_eq!(render("A-0000", "hi", Some(200)), "[A-0000]\nhi");
    }

    #[test]
    fn tiny_limits_never_exceed_budget() {
        for limit in 0..=4 {
            let out = render("A", "hello world", Some(limit));
            assert!(out.len() <= limit, "limit {limit} produced {} bytes", out.len());
        }
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
