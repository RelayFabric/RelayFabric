//! Thin client for the switchyardd admin API.
// hand-rolled HTTP/1.0 over UnixStream — zero client deps, and the
// server closes the connection after each response.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

/// Maps CLI args to an HTTP method, path, and (for POST) a JSON body.
/// `display_name` for `link` may contain spaces — everything after
/// `<requester> <target>` is joined with a single space.
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
        _ => Err("usage: switchyardctl [--socket <path>] \
                  status|plugins|routes|queue|trace <id>|identities|\
                  link <requester> <target> <display_name...>|unlink <id>".into()),
    }
}

/// The status a successful response is expected to carry for each method —
/// `GET` always 200, a link `POST` 202 (accepted, see admin.rs), an `unlink`
/// `DELETE` 204 (no content). Anything else is an error, body included.
fn expected_status(method: &str) -> &'static str {
    match method {
        "POST" => "202",
        "DELETE" => "204",
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

/// Sends `method path HTTP/1.0` over the admin socket, with `body` (if any)
/// framed via `Content-Length`/`Content-Type: application/json`, and returns
/// the parsed response body on `expected_status`, or an error otherwise.
fn fetch(
    socket: &str, method: &str, path: &str, body: Option<&str>, expected: &str,
) -> Result<String, String> {
    let mut s = UnixStream::connect(socket)
        .map_err(|e| format!("cannot connect to {socket}: {e}"))?;
    let mut head = format!("{method} {path} HTTP/1.0\r\nhost: localhost\r\n");
    match body {
        Some(b) => {
            head.push_str(&format!(
                "content-type: application/json\r\ncontent-length: {}\r\n\r\n{b}", b.len(),
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
    match fetch(&socket, method, &path, body.as_deref(), expected_status(method)) {
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
    fn expected_status_by_method() {
        assert_eq!(expected_status("GET"), "200");
        assert_eq!(expected_status("POST"), "202");
        assert_eq!(expected_status("DELETE"), "204");
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
