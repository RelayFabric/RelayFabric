//! Thin client for the switchyardd admin API.
// hand-rolled HTTP/1.0 over UnixStream — zero client deps, and the
// server closes the connection after each response.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

/// Maps CLI args to an HTTP method, path, and (for POST/PUT) a body.
/// `display_name` for `link` may contain spaces — everything after
/// `<requester> <target>` is joined with a single space. `config validate`/
/// `config apply` read their `<file>` argument from THIS machine's
/// filesystem and POST/PUT its raw text as the body — the daemon resolves
/// any `${env:...}` secret references against ITS OWN environment when it
/// receives that text (see `admin.rs::config_validate`'s doc comment), which
/// is exactly the check an operator wants: "would this apply cleanly on the
/// running daemon," not "on my workstation."
fn request_for(args: &[String]) -> Result<(&'static str, String, Option<String>), String> {
    match args.first().map(String::as_str) {
        Some("status") => Ok(("GET", "/v1/status".into(), None)),
        Some("plugins") => Ok(("GET", "/v1/plugins".into(), None)),
        Some("routes") => Ok(("GET", "/v1/routes".into(), None)),
        Some("queue") => Ok(("GET", "/v1/queue".into(), None)),
        Some("trace") => match args.get(1) {
            Some(id) => Ok(("GET", format!("/v1/messages/{id}"), None)),
            None => Err("usage: switchyardctl trace <message-id>".into()),
        },
        Some("identities") => Ok(("GET", "/v1/identities".into(), None)),
        Some("link") => {
            let (requester, target, name_parts) = (args.get(1), args.get(2), args.get(3..));
            match (requester, target, name_parts) {
                (Some(requester), Some(target), Some(parts)) if !parts.is_empty() => {
                    let body = serde_json::json!({
                        "requester": requester,
                        "target": target,
                        "display_name": parts.join(" "),
                    }).to_string();
                    Ok(("POST", "/v1/identities/link".into(), Some(body)))
                }
                _ => Err("usage: switchyardctl link <requester> <target> <display_name...>".into()),
            }
        }
        Some("unlink") => match args.get(1) {
            Some(id) => Ok(("DELETE", format!("/v1/identities/link/{id}"), None)),
            None => Err("usage: switchyardctl unlink <id>".into()),
        },
        Some("config") => match args.get(1).map(String::as_str) {
            Some("show") => Ok(("GET", "/v1/config".into(), None)),
            Some("validate") => match args.get(2) {
                Some(file) => Ok(("POST", "/v1/config/validate".into(), Some(read_config_file(file)?))),
                None => Err("usage: switchyardctl config validate <file>".into()),
            },
            Some("apply") => match args.get(2) {
                Some(file) => Ok(("PUT", "/v1/config".into(), Some(read_config_file(file)?))),
                None => Err("usage: switchyardctl config apply <file>".into()),
            },
            Some("rollback") => Ok(("POST", "/v1/config/rollback".into(), None)),
            _ => Err("usage: switchyardctl config show|validate <file>|apply <file>|rollback".into()),
        },
        _ => Err("usage: switchyardctl [--socket <path>] \
                  status|plugins|routes|queue|trace <id>|identities|\
                  link <requester> <target> <display_name...>|unlink <id>|\
                  config show|validate <file>|apply <file>|rollback".into()),
    }
}

fn read_config_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
}

/// The status a successful response is expected to carry — keyed by
/// (method, path) rather than method alone, since `POST` alone now covers
/// three different success codes: a link `POST` is 202 (accepted, see
/// admin.rs), `config validate`/`config rollback` are both 200. `GET`/`PUT`
/// are always 200, `DELETE` always 204 (no content). Anything else is an
/// error, body included.
fn expected_status(method: &str, path: &str) -> &'static str {
    match (method, path) {
        ("POST", "/v1/identities/link") => "202",
        ("DELETE", _) => "204",
        _ => "200",
    }
}

fn body_of(raw: &str, expected: &str) -> Result<String, String> {
    let (head, body) = raw.split_once("\r\n\r\n").ok_or("malformed HTTP response")?;
    let status = head.split_whitespace().nth(1).unwrap_or("0");
    if status != expected {
        return Err(format!("HTTP {status}: {body}"));
    }
    Ok(body.to_string())
}

/// The two config-mutation endpoints take raw YAML text, not JSON —
/// everything else in this CLI sends JSON (or no body at all).
fn content_type_for(path: &str) -> &'static str {
    match path {
        "/v1/config" | "/v1/config/validate" => "text/yaml",
        _ => "application/json",
    }
}

/// Sends `method path HTTP/1.0` over the admin socket, with `body` (if any)
/// framed via `Content-Length`/`Content-Type` (`content_type_for`), and
/// returns the parsed response body on `expected_status`, or an error
/// otherwise.
fn fetch(
    socket: &str, method: &str, path: &str, body: Option<&str>, expected: &str,
) -> Result<String, String> {
    let mut s = UnixStream::connect(socket)
        .map_err(|e| format!("cannot connect to {socket}: {e}"))?;
    let mut head = format!("{method} {path} HTTP/1.0\r\nhost: localhost\r\n");
    match body {
        Some(b) => {
            head.push_str(&format!(
                "content-type: {}\r\ncontent-length: {}\r\n\r\n{b}",
                content_type_for(path), b.len(),
            ));
        }
        None => head.push_str("\r\n"),
    }
    write!(s, "{head}").map_err(|e| e.to_string())?;
    let mut raw = String::new();
    s.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    body_of(&raw, expected)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = String::from("/var/lib/relayfabric/admin.sock");
    if args.first().map(String::as_str) == Some("--socket") {
        args.remove(0);
        socket = if args.is_empty() { socket } else { args.remove(0) };
    }
    let (method, path, body) = match request_for(&args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    match fetch(&socket, method, &path, body.as_deref(), expected_status(method, &path)) {
        Ok(body) if body.trim().is_empty() => println!("ok"),
        Ok(body) => {
            let pretty = serde_json::from_str::<serde_json::Value>(&body)
                .and_then(|v| serde_json::to_string_pretty(&v))
                .unwrap_or(body);
            println!("{pretty}");
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_commands_to_paths() {
        assert_eq!(request_for(&["status".into()]).unwrap(), ("GET", "/v1/status".into(), None));
        assert_eq!(request_for(&["plugins".into()]).unwrap(), ("GET", "/v1/plugins".into(), None));
        assert_eq!(request_for(&["routes".into()]).unwrap(), ("GET", "/v1/routes".into(), None));
        assert_eq!(request_for(&["queue".into()]).unwrap(), ("GET", "/v1/queue".into(), None));
        assert_eq!(
            request_for(&["trace".into(), "01890000-0000-7000-8000-000000000000".into()]).unwrap(),
            ("GET", "/v1/messages/01890000-0000-7000-8000-000000000000".into(), None)
        );
        assert_eq!(request_for(&["identities".into()]).unwrap(),
            ("GET", "/v1/identities".into(), None));
        assert!(request_for(&[]).is_err());
        assert!(request_for(&["trace".into()]).is_err());
        assert!(request_for(&["bogus".into()]).is_err());
    }

    #[test]
    fn link_builds_a_post_with_json_body_and_joins_multi_word_display_name() {
        let (method, path, body) = request_for(&[
            "link".into(), "lxmf:abc123".into(), "signal:+15551234567".into(),
            "Jascha".into(), "Dub".into(),
        ]).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/v1/identities/link");
        let v: serde_json::Value = serde_json::from_str(&body.unwrap()).unwrap();
        assert_eq!(v["requester"], "lxmf:abc123");
        assert_eq!(v["target"], "signal:+15551234567");
        assert_eq!(v["display_name"], "Jascha Dub");
    }

    #[test]
    fn link_requires_requester_target_and_at_least_one_display_name_word() {
        assert!(request_for(&["link".into()]).is_err());
        assert!(request_for(&["link".into(), "a:b".into()]).is_err());
        assert!(request_for(&["link".into(), "a:b".into(), "c:d".into()]).is_err(),
            "missing display_name must be a usage error");
    }

    #[test]
    fn unlink_builds_a_delete_with_no_body() {
        assert_eq!(request_for(&["unlink".into(), "42".into()]).unwrap(),
            ("DELETE", "/v1/identities/link/42".into(), None));
        assert!(request_for(&["unlink".into()]).is_err());
    }

    #[test]
    fn expected_status_by_method_and_path() {
        assert_eq!(expected_status("GET", "/v1/status"), "200");
        assert_eq!(expected_status("POST", "/v1/identities/link"), "202");
        assert_eq!(expected_status("DELETE", "/v1/identities/link/1"), "204");
        assert_eq!(expected_status("GET", "/v1/config"), "200");
        assert_eq!(expected_status("PUT", "/v1/config"), "200");
        assert_eq!(expected_status("POST", "/v1/config/validate"), "200");
        assert_eq!(expected_status("POST", "/v1/config/rollback"), "200");
    }

    #[test]
    fn content_type_by_path() {
        assert_eq!(content_type_for("/v1/config"), "text/yaml");
        assert_eq!(content_type_for("/v1/config/validate"), "text/yaml");
        assert_eq!(content_type_for("/v1/identities/link"), "application/json");
        assert_eq!(content_type_for("/v1/config/rollback"), "application/json");
    }

    #[test]
    fn config_show_builds_a_get_with_no_body() {
        assert_eq!(request_for(&["config".into(), "show".into()]).unwrap(),
            ("GET", "/v1/config".into(), None));
    }

    #[test]
    fn config_validate_reads_the_local_file_and_posts_its_text() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("candidate.yaml");
        std::fs::write(&file, "node:\n  name: t\n  data_dir: /tmp/x\n").unwrap();

        let (method, path, body) =
            request_for(&["config".into(), "validate".into(), file.display().to_string()]).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/v1/config/validate");
        assert_eq!(body.unwrap(), "node:\n  name: t\n  data_dir: /tmp/x\n");
    }

    #[test]
    fn config_validate_requires_a_file_argument_and_errors_on_a_missing_file() {
        assert!(request_for(&["config".into(), "validate".into()]).is_err());
        assert!(request_for(&["config".into(), "validate".into(),
            "/nonexistent/relayfabric-ctl-test.yaml".into()]).is_err());
    }

    #[test]
    fn config_apply_reads_the_local_file_and_puts_its_text() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("candidate.yaml");
        std::fs::write(&file, "node:\n  name: applied\n  data_dir: /tmp/y\n").unwrap();

        let (method, path, body) =
            request_for(&["config".into(), "apply".into(), file.display().to_string()]).unwrap();
        assert_eq!(method, "PUT");
        assert_eq!(path, "/v1/config");
        assert_eq!(body.unwrap(), "node:\n  name: applied\n  data_dir: /tmp/y\n");
    }

    #[test]
    fn config_apply_requires_a_file_argument() {
        assert!(request_for(&["config".into(), "apply".into()]).is_err());
    }

    #[test]
    fn config_rollback_builds_a_post_with_no_body() {
        assert_eq!(request_for(&["config".into(), "rollback".into()]).unwrap(),
            ("POST", "/v1/config/rollback".into(), None));
    }

    #[test]
    fn config_with_unknown_subcommand_or_none_is_a_usage_error() {
        assert!(request_for(&["config".into()]).is_err());
        assert!(request_for(&["config".into(), "bogus".into()]).is_err());
    }

    #[test]
    fn strips_http_response_headers() {
        let raw = "HTTP/1.0 200 OK\r\ncontent-type: application/json\r\n\r\n{\"a\":1}";
        assert_eq!(body_of(raw, "200").unwrap(), "{\"a\":1}");
        assert!(body_of("HTTP/1.0 404 Not Found\r\n\r\n{}", "200").is_err());
    }

    #[test]
    fn body_of_accepts_only_the_expected_status() {
        let raw = "HTTP/1.0 202 Accepted\r\n\r\n{\"challenge_id\":1}";
        assert_eq!(body_of(raw, "202").unwrap(), "{\"challenge_id\":1}");
        assert!(body_of(raw, "200").is_err(), "202 must not satisfy a 200 expectation");
    }

    #[test]
    fn body_of_accepts_204_with_empty_body() {
        let raw = "HTTP/1.0 204 No Content\r\n\r\n";
        assert_eq!(body_of(raw, "204").unwrap(), "");
    }
}
