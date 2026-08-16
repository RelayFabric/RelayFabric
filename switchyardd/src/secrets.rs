//! Config secret references (design §2 / SPEC §51, §59): `${env:NAME}` and
//! `${file:/abs/path}`. A value matches only when the ENTIRE string is one
//! of these two forms -- exact-match only, no interpolation inside a
//! longer string (YAGNI, and it keeps redaction unambiguous: a config
//! string is either exactly a secret reference or it is ordinary literal
//! text, never a mix).
//!
//! `parse_ref` recognizes the syntax; `resolve` reads the real value.
//! Callers (see `config::resolve_secrets`) MUST keep the two forms
//! separate: the resolved value goes into the runtime `Config` that gets
//! forwarded to plugins over IPC, while every other consumer (admin API,
//! logs, `--check-config` output, error strings) must only ever see the
//! `${...}` form via `SecretRef::display_form` -- see the redaction tests
//! in `config.rs` and `admin.rs`.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    Env(String),
    File(PathBuf),
}

impl SecretRef {
    /// The canonical unresolved `${...}` form -- the only representation of
    /// a secret reference allowed outside the resolved runtime config
    /// (error messages, admin display, `--check-config` output).
    pub fn display_form(&self) -> String {
        match self {
            SecretRef::Env(name) => format!("${{env:{name}}}"),
            SecretRef::File(path) => format!("${{file:{}}}", path.display()),
        }
    }
}

/// Parses `s` as a secret reference only if the ENTIRE string is
/// `${env:NAME}` or `${file:/abs/path}`. Anything else -- including a
/// reference embedded inside a longer string -- returns `None`, and the
/// caller must treat `s` as an ordinary literal value.
pub fn parse_ref(s: &str) -> Option<SecretRef> {
    let inner = s.strip_prefix("${")?.strip_suffix('}')?;
    // A stray `}` (or `{`) left in `inner` means the real closing brace
    // came earlier and `s` had trailing (or nested) content after it --
    // e.g. "${env:FOO}extra}" -- so this was not a whole-string match.
    if inner.contains('}') || inner.contains('{') {
        return None;
    }
    if let Some(name) = inner.strip_prefix("env:") {
        return (!name.is_empty()).then(|| SecretRef::Env(name.to_string()));
    }
    if let Some(path) = inner.strip_prefix("file:") {
        return (!path.is_empty()).then(|| SecretRef::File(PathBuf::from(path)));
    }
    None
}

/// Resolves a parsed reference to its real value. Errors name the
/// reference's `${...}` form, never any value -- the caller (config load)
/// propagates these verbatim into `--check-config`/startup error output.
pub fn resolve(r: &SecretRef) -> Result<String, String> {
    match r {
        SecretRef::Env(name) => match std::env::var(name) {
            Ok(v) if !v.is_empty() => Ok(v),
            _ => Err(format!("secret reference {} is unset or empty", r.display_form())),
        },
        SecretRef::File(path) => {
            // design §2 syntax is `${file:/abs/path}` -- a relative path
            // would resolve against the daemon's CWD, which is neither
            // documented nor stable across how the daemon is launched
            // (systemd unit vs. interactive shell), so it's rejected here
            // rather than silently read from wherever the process happens
            // to be running.
            if !path.is_absolute() {
                return Err(format!(
                    "secret reference {} must use an absolute path", r.display_form()));
            }
            let raw = std::fs::read_to_string(path).map_err(|e| {
                format!("secret reference {} is unreadable: {e}", r.display_form())
            })?;
            let trimmed = raw.trim().to_string();
            if trimmed.is_empty() {
                // symmetric with the env arm above: an empty/whitespace-only
                // secret file is exactly as unusable as an unset/empty env
                // var, and silently resolving to "" would hand plugins an
                // empty token instead of failing loudly at config load.
                return Err(format!("secret reference {} is empty or unset", r.display_form()));
            }
            if let Some(warning) = permission_warning(path) {
                // eprintln, not tracing::warn!: this runs inside
                // `config::load`, which happens before `main` initializes
                // `tracing_subscriber` (and never initializes it at all on
                // the `--check-config` path) -- same rationale as
                // `config::warn_if_public_with_no_limits`.
                eprintln!("warning: {warning}");
            }
            Ok(trimmed)
        }
    }
}

/// A config value that is whole-string `${...}`-shaped but that
/// `parse_ref` didn't recognize (empty/unknown scheme, wrong case, stray
/// braces, ...) almost certainly means the operator *intended* a secret
/// reference and typo'd it, rather than coincidentally writing ordinary
/// literal text shaped like one. `resolve_value` still leaves it as a
/// literal (no behavior change -- a plugin that expects a real token would
/// otherwise fail confusingly downstream instead of here), but silence
/// would be worse: this returns the warning to print, naming the value's
/// `${...}` FORM (safe to print -- it never resolved to a secret, it's just
/// the literal config text) and the two supported schemes. Split out from
/// the `eprintln!` call site so the message is unit-testable without
/// capturing stderr, mirroring `permission_warning` above. Self-contained
/// (re-checks `parse_ref` internally) so it's correct to call standalone,
/// not just from `resolve_value`'s `None` branch. Returns `None` for
/// anything not ref-shaped at all, or that DOES parse -- an ordinary
/// literal or a real reference, left alone silently, same as always.
pub fn malformed_ref_warning(s: &str) -> Option<String> {
    if !(s.starts_with("${") && s.ends_with('}') && s.len() >= 3) {
        return None;
    }
    if parse_ref(s).is_some() {
        return None;
    }
    Some(format!(
        "config value {s} looks like a secret reference but matches neither \
         supported scheme (${{env:NAME}} or ${{file:/abs/path}}); using it as a literal value"
    ))
}

/// Group/world-readable secret files are a footgun, not an error (design
/// §2): still resolves, just warns. Split out from the `eprintln!` call
/// site so the message content -- which must name only the path, never the
/// file's contents -- is unit-testable without capturing stderr. Mirrors
/// `alias.rs`'s 0o600 permission style (`std::os::unix::fs`).
fn permission_warning(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    if mode & 0o077 != 0 {
        Some(format!(
            "secret file {} is group/world-readable (mode {:o}); consider chmod 600",
            path.display(), mode & 0o777,
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // ---- parse_ref matrix --------------------------------------------

    #[test]
    fn parses_env_ref() {
        assert_eq!(parse_ref("${env:TOKEN}"), Some(SecretRef::Env("TOKEN".into())));
    }

    #[test]
    fn parses_file_ref() {
        assert_eq!(
            parse_ref("${file:/etc/relayfabric/secret}"),
            Some(SecretRef::File(PathBuf::from("/etc/relayfabric/secret"))),
        );
    }

    #[test]
    fn rejects_plain_string() {
        assert_eq!(parse_ref("just a value"), None);
    }

    #[test]
    fn rejects_ref_embedded_with_leading_text() {
        assert_eq!(parse_ref("prefix ${env:TOKEN}"), None);
    }

    #[test]
    fn rejects_ref_embedded_with_trailing_text() {
        assert_eq!(parse_ref("${env:TOKEN} suffix"), None);
    }

    #[test]
    fn rejects_ref_immediately_followed_by_junk_before_the_real_close() {
        // ends with '}' but the *real* close is earlier -- not a whole-string match
        assert_eq!(parse_ref("${env:TOKEN}extra}"), None);
    }

    #[test]
    fn rejects_ref_embedded_in_the_middle() {
        assert_eq!(parse_ref("a${env:TOKEN}b"), None);
    }

    #[test]
    fn rejects_empty_env_name() {
        assert_eq!(parse_ref("${env:}"), None);
    }

    #[test]
    fn rejects_empty_file_path() {
        assert_eq!(parse_ref("${file:}"), None);
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert_eq!(parse_ref("${vault:secret/token}"), None);
    }

    #[test]
    fn rejects_missing_braces() {
        assert_eq!(parse_ref("env:TOKEN"), None);
        assert_eq!(parse_ref("${env:TOKEN"), None);
        assert_eq!(parse_ref("env:TOKEN}"), None);
    }

    #[test]
    fn display_form_renders_canonical_syntax() {
        assert_eq!(SecretRef::Env("TOKEN".into()).display_form(), "${env:TOKEN}");
        assert_eq!(
            SecretRef::File(PathBuf::from("/a/b")).display_form(),
            "${file:/a/b}",
        );
    }

    // ---- resolve: env --------------------------------------------------

    #[test]
    fn resolve_env_returns_value_when_set() {
        std::env::set_var("RF_SECRETS_TEST_ENV_SET", "sentinel-value-123");
        let got = resolve(&SecretRef::Env("RF_SECRETS_TEST_ENV_SET".into())).unwrap();
        assert_eq!(got, "sentinel-value-123");
        std::env::remove_var("RF_SECRETS_TEST_ENV_SET");
    }

    #[test]
    fn resolve_env_errors_naming_ref_when_unset() {
        std::env::remove_var("RF_SECRETS_TEST_ENV_UNSET");
        let err = resolve(&SecretRef::Env("RF_SECRETS_TEST_ENV_UNSET".into())).unwrap_err();
        assert!(err.contains("${env:RF_SECRETS_TEST_ENV_UNSET}"), "err was: {err}");
    }

    #[test]
    fn resolve_env_errors_naming_ref_when_empty() {
        std::env::set_var("RF_SECRETS_TEST_ENV_EMPTY", "");
        let err = resolve(&SecretRef::Env("RF_SECRETS_TEST_ENV_EMPTY".into())).unwrap_err();
        assert!(err.contains("${env:RF_SECRETS_TEST_ENV_EMPTY}"), "err was: {err}");
        std::env::remove_var("RF_SECRETS_TEST_ENV_EMPTY");
    }

    // ---- resolve: file ---------------------------------------------------

    #[test]
    fn resolve_file_returns_trimmed_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "  sentinel-file-value\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let got = resolve(&SecretRef::File(path)).unwrap();
        assert_eq!(got, "sentinel-file-value");
    }

    #[test]
    fn resolve_file_errors_naming_ref_when_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.txt");
        let err = resolve(&SecretRef::File(path.clone())).unwrap_err();
        assert!(err.contains(&format!("${{file:{}}}", path.display())), "err was: {err}");
    }

    /// Symmetric with `resolve_env_errors_naming_ref_when_empty`: a file
    /// that exists but is empty (or whitespace-only, since content is
    /// trimmed) is exactly as unusable as an unset env var and must error,
    /// not silently resolve to `""`.
    #[test]
    fn resolve_file_errors_naming_ref_when_empty_after_trim() {
        let dir = tempfile::tempdir().unwrap();
        for (label, contents) in [("empty", ""), ("whitespace-only", "   \n\t \n")] {
            let path = dir.path().join(format!("{label}.txt"));
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let err = match resolve(&SecretRef::File(path.clone())) {
                Err(e) => e,
                Ok(v) => panic!("{label} file should error, not resolve to {v:?}"),
            };
            assert!(err.contains(&format!("${{file:{}}}", path.display())), "err was: {err}");
        }
    }

    /// Design §2's syntax is `${file:/abs/path}` -- a relative path must be
    /// rejected loudly at resolve time rather than silently read relative
    /// to whatever the daemon's CWD happens to be.
    #[test]
    fn resolve_file_errors_naming_ref_for_relative_path() {
        let err = resolve(&SecretRef::File(PathBuf::from("relative/secret.txt"))).unwrap_err();
        assert!(err.contains("${file:relative/secret.txt}"), "err was: {err}");
    }

    /// `parse_ref` is purely syntactic (design: exact-match shape only) --
    /// it still recognizes a relative-looking `${file:...}` as a
    /// `SecretRef::File`; the absolute-path requirement is enforced by
    /// `resolve`, not `parse_ref`, so this stays `Some`.
    #[test]
    fn parse_ref_accepts_relative_file_syntax_rejection_happens_at_resolve() {
        assert_eq!(
            parse_ref("${file:relative/secret.txt}"),
            Some(SecretRef::File(PathBuf::from("relative/secret.txt"))),
        );
    }

    // ---- permission warning ----------------------------------------------

    #[test]
    fn permission_warning_none_for_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(permission_warning(&path), None);
    }

    #[test]
    fn permission_warning_present_for_group_or_world_readable_and_never_names_content() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o640u32, 0o604, 0o644, 0o660, 0o666] {
            let path = dir.path().join(format!("secret-{mode:o}.txt"));
            std::fs::write(&path, "super-secret-contents").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let msg = permission_warning(&path)
                .unwrap_or_else(|| panic!("mode {mode:o} should warn"));
            assert!(msg.contains(&path.display().to_string()), "msg was: {msg}");
            assert!(!msg.contains("super-secret-contents"), "msg leaked contents: {msg}");
        }
    }

    #[test]
    fn resolve_file_warns_but_still_resolves_when_group_or_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "sentinel-permissive").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let got = resolve(&SecretRef::File(path)).unwrap();
        assert_eq!(got, "sentinel-permissive");
    }

    // ---- malformed_ref_warning ------------------------------------------

    #[test]
    fn malformed_ref_warning_none_for_ordinary_literal() {
        assert_eq!(malformed_ref_warning("just a value"), None);
    }

    #[test]
    fn malformed_ref_warning_none_for_a_ref_that_actually_parses() {
        // A value parse_ref already handles must not also get the
        // "malformed" warning -- resolve_value only calls this helper in
        // parse_ref's None branch, but the helper itself should agree.
        assert!(parse_ref("${env:TOKEN}").is_some());
        assert_eq!(malformed_ref_warning("${env:TOKEN}"), None);
    }

    #[test]
    fn malformed_ref_warning_fires_for_unknown_scheme() {
        assert_eq!(parse_ref("${vault:x}"), None);
        let msg = malformed_ref_warning("${vault:x}").unwrap();
        assert!(msg.contains("${vault:x}"), "msg was: {msg}");
        assert!(msg.contains("${env:NAME}"), "msg was: {msg}");
        assert!(msg.contains("${file:/abs/path}"), "msg was: {msg}");
    }

    #[test]
    fn malformed_ref_warning_fires_for_empty_env_name() {
        assert_eq!(parse_ref("${env:}"), None);
        let msg = malformed_ref_warning("${env:}").unwrap();
        assert!(msg.contains("${env:}"), "msg was: {msg}");
    }

    #[test]
    fn malformed_ref_warning_fires_for_wrong_case_scheme() {
        assert_eq!(parse_ref("${Env:X}"), None);
        let msg = malformed_ref_warning("${Env:X}").unwrap();
        assert!(msg.contains("${Env:X}"), "msg was: {msg}");
    }

    #[test]
    fn malformed_ref_warning_none_for_a_ref_embedded_in_a_longer_string() {
        // Not whole-string ${...}-shaped -- ordinary literal text that
        // happens to contain a reference-looking substring, same as
        // parse_ref's own embedded-ref rejection. Must stay silent.
        assert_eq!(malformed_ref_warning("prefix ${env:TOKEN}"), None);
        assert_eq!(malformed_ref_warning("${env:TOKEN} suffix"), None);
    }
}
