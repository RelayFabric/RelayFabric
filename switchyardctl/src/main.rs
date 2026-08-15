//! Thin client for the switchyardd admin API.
// ponytail: hand-rolled HTTP/1.0 over UnixStream — zero client deps, and the
// server closes the connection after each response. Swap for a real client
// only when the API needs POSTs with bodies.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

fn path_for(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("status") => Ok("/v1/status".into()),
        Some("plugins") => Ok("/v1/plugins".into()),
        Some("routes") => Ok("/v1/routes".into()),
        Some("queue") => Ok("/v1/queue".into()),
        Some("trace") => match args.get(1) {
            Some(id) => Ok(format!("/v1/messages/{id}")),
            None => Err("usage: switchyardctl trace <message-id>".into()),
        },
        _ => Err("usage: switchyardctl [--socket <path>] \
                  status|plugins|routes|queue|trace <id>".into()),
    }
}

fn body_of(raw: &str) -> Result<String, String> {
    let (head, body) = raw.split_once("\r\n\r\n").ok_or("malformed HTTP response")?;
    let status = head.split_whitespace().nth(1).unwrap_or("0");
    if status != "200" {
        return Err(format!("HTTP {status}: {body}"));
    }
    Ok(body.to_string())
}

fn fetch(socket: &str, path: &str) -> Result<String, String> {
    let mut s = UnixStream::connect(socket)
        .map_err(|e| format!("cannot connect to {socket}: {e}"))?;
    write!(s, "GET {path} HTTP/1.0\r\nhost: localhost\r\n\r\n").map_err(|e| e.to_string())?;
    let mut raw = String::new();
    s.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    body_of(&raw)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = String::from("/var/lib/relayfabric/admin.sock");
    if args.first().map(String::as_str) == Some("--socket") {
        args.remove(0);
        socket = if args.is_empty() { socket } else { args.remove(0) };
    }
    let path = match path_for(&args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    match fetch(&socket, &path) {
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
        assert_eq!(path_for(&["status".into()]).unwrap(), "/v1/status");
        assert_eq!(path_for(&["plugins".into()]).unwrap(), "/v1/plugins");
        assert_eq!(path_for(&["routes".into()]).unwrap(), "/v1/routes");
        assert_eq!(path_for(&["queue".into()]).unwrap(), "/v1/queue");
        assert_eq!(
            path_for(&["trace".into(), "01890000-0000-7000-8000-000000000000".into()]).unwrap(),
            "/v1/messages/01890000-0000-7000-8000-000000000000"
        );
        assert!(path_for(&[]).is_err());
        assert!(path_for(&["trace".into()]).is_err());
        assert!(path_for(&["bogus".into()]).is_err());
    }

    #[test]
    fn strips_http_response_headers() {
        let raw = "HTTP/1.0 200 OK\r\ncontent-type: application/json\r\n\r\n{\"a\":1}";
        assert_eq!(body_of(raw).unwrap(), "{\"a\":1}");
        assert!(body_of("HTTP/1.0 404 Not Found\r\n\r\n{}").is_err());
    }
}
