/// Render the destination-facing body: origin tag + payload, truncated to
/// max_payload bytes on a char boundary with a visible marker (spec §17, §83).
#[allow(dead_code)] // consumed by engine wiring (Task 9); remove allow when used
pub fn render(alias: &str, body: &str, max_payload: Option<usize>) -> String {
    let full = format!("[{alias}]\n{body}");
    let Some(limit) = max_payload else { return full };
    if full.len() <= limit {
        return full;
    }
    let budget = limit.saturating_sub('…'.len_utf8());
    let mut cut = budget.min(full.len());
    while cut > 0 && !full.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &full[..cut])
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
}
