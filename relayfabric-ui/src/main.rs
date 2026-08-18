//! relayfabric-ui — a thin web front end for `switchyardd`.
//!
//! The daemon's admin API is a Unix-domain socket with no TCP listener and no
//! authentication (see docs/security.md). A browser cannot reach a Unix
//! socket, so this binary serves the static admin UI over TCP and
//! transparently reverse-proxies `/v1/*`, `/metrics`, and `/docs/*` to the
//! admin socket, preserving streaming so the `/v1/events` SSE feed works.
//!
//! It adds NO authentication of its own yet — bind it to loopback (the
//! default) or place it behind an authenticating reverse proxy. This is the
//! seam where the deferred RBAC/auth layer will live.
//!
//! Because it fronts an unauthenticated admin API, it defends against the
//! browser-borne attacks that reach even a loopback listener:
//!   * a **Host allowlist** rejects requests whose Host is not a loopback
//!     literal or an operator-approved name — the DNS-rebinding defense that
//!     stops a malicious site from resolving its own domain to 127.0.0.1;
//!   * an **Origin check** rejects cross-site state-changing requests (CSRF);
//!   * **hop-by-hop headers** are stripped before forwarding (no smuggling).
//!
//!   relayfabric-ui --socket /run/relayfabric/admin.sock \
//!                  --listen 127.0.0.1:8087 --web-dir relayfabric-ui/web \
//!                  [--allowed-host relayfabric.internal]

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use hyper_util::rt::TokioIo;

#[derive(Clone)]
struct AppState {
    socket: PathBuf,
    web_dir: PathBuf,
    /// Lower-cased host names/IPs (no port) permitted in the Host and Origin
    /// headers. Anything else is rejected — this is the DNS-rebinding and
    /// CSRF boundary in front of an unauthenticated admin API.
    allowed_hosts: Vec<String>,
}

/// Headers that must not be forwarded to the upstream (RFC 7230 §6.1) plus
/// the framing headers hyper recomputes itself — forwarding a client-supplied
/// Content-Length / Transfer-Encoding is a request-smuggling vector.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
];

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut socket: Option<PathBuf> = None;
    let mut listen = "127.0.0.1:8087".to_string();
    let mut web_dir = PathBuf::from("relayfabric-ui/web");
    let mut extra_hosts: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = args.next().map(PathBuf::from),
            "--listen" => listen = args.next().unwrap_or(listen),
            "--web-dir" => web_dir = args.next().map(PathBuf::from).unwrap_or(web_dir),
            "--allowed-host" => {
                if let Some(h) = args.next() {
                    extra_hosts.push(h.to_ascii_lowercase());
                }
            }
            "-h" | "--help" => {
                eprintln!(
                    "relayfabric-ui --socket <admin.sock> [--listen 127.0.0.1:8087] \
                     [--web-dir DIR] [--allowed-host NAME]..."
                );
                return;
            }
            other => {
                eprintln!("relayfabric-ui: unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let socket = socket.unwrap_or_else(|| {
        eprintln!("relayfabric-ui: --socket <admin.sock> is required");
        std::process::exit(2);
    });

    // Always allow the loopback literals and "localhost"; also allow the host
    // portion of --listen (so binding an explicit IP still works), and any
    // operator-supplied --allowed-host (e.g. a name a fronting proxy sets).
    let mut allowed_hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "[::1]".to_string(),
    ];
    allowed_hosts.push(host_of(&listen).to_ascii_lowercase());
    allowed_hosts.extend(extra_hosts);
    allowed_hosts.sort();
    allowed_hosts.dedup();

    let state = AppState {
        socket,
        web_dir,
        allowed_hosts,
    };

    let app = Router::new()
        .route("/v1/{*rest}", any(proxy))
        .route("/metrics", any(proxy))
        // Swagger UI's HTML uses relative asset refs (./swagger-ui.css), which
        // only resolve when the page is loaded at /docs/ (with the trailing
        // slash); the daemon serves /docs without redirecting, so send the
        // browser to /docs/ ourselves.
        .route("/docs", any(|| async { axum::response::Redirect::permanent("/docs/") }))
        .route("/docs/", any(proxy))
        .route("/docs/{*rest}", any(proxy))
        .fallback(static_file)
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| {
            eprintln!("relayfabric-ui: cannot bind {listen}: {e}");
            std::process::exit(1);
        });
    tracing::info!(
        listen = %listen,
        socket = %state.socket.display(),
        web_dir = %state.web_dir.display(),
        allowed_hosts = ?state.allowed_hosts,
        "relayfabric-ui serving"
    );
    axum::serve(listener, app).await.expect("serve");
}

/// Clickjacking, MIME-sniffing, and referrer defenses on every response. The
/// admin UI is same-origin only; framing it or content-sniffing its types
/// serves no legitimate purpose.
async fn security_headers(req: Request, next: axum::middleware::Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    resp
}

/// Reverse-proxy one request to the admin Unix socket over HTTP/1, after the
/// Host/Origin guards, streaming the response body straight back.
async fn proxy(State(st): State<AppState>, req: Request) -> Response {
    if !host_allowed(req.headers(), &st.allowed_hosts) {
        return (StatusCode::FORBIDDEN, "host not allowed").into_response();
    }
    // CSRF: a state-changing request carrying a cross-site Origin is refused.
    if is_state_changing(req.method()) && !origin_allowed(req.headers(), &st.allowed_hosts) {
        return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
    }
    match forward(&st.socket, req).await {
        Ok(resp) => resp,
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            format!("relayfabric-ui: admin socket unreachable: {e}"),
        )
            .into_response(),
    }
}

async fn forward(
    socket: &Path,
    req: Request,
) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
    let (parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    let stream = tokio::net::UnixStream::connect(socket).await?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder()
        .method(parts.method)
        .uri(path_and_query);
    if let Some(headers) = builder.headers_mut() {
        for (k, v) in parts.headers.iter() {
            if HOP_BY_HOP.contains(&k.as_str()) {
                continue;
            }
            headers.insert(k, v.clone());
        }
        // The admin server only needs a syntactically valid Host for HTTP/1.1.
        headers.insert(header::HOST, HeaderValue::from_static("localhost"));
    }
    let out_req = builder.body(body)?;

    let upstream = sender.send_request(out_req).await?;
    let (rparts, rbody) = upstream.into_parts();
    let mut resp = Response::new(Body::new(rbody));
    *resp.status_mut() = rparts.status;
    *resp.headers_mut() = rparts.headers;
    Ok(resp)
}

/// Serve a static asset from the web dir. `/` maps to index.html; an unknown
/// extension-less path also falls back to index.html (single-page app), while
/// a missing asset (has an extension) is a real 404.
async fn static_file(State(st): State<AppState>, req: Request) -> Response {
    if !host_allowed(req.headers(), &st.allowed_hosts) {
        return (StatusCode::FORBIDDEN, "host not allowed").into_response();
    }
    let path = req.uri().path();
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    if rel.split('/').any(|seg| seg == ".." || seg.is_empty()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let full = st.web_dir.join(rel);
    match tokio::fs::read(&full).await {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, content_type(&full))],
            bytes,
        )
            .into_response(),
        Err(_) if !rel.contains('.') => match tokio::fs::read(st.web_dir.join("index.html")).await {
            Ok(bytes) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], bytes)
                .into_response(),
            Err(_) => StatusCode::NOT_FOUND.into_response(),
        },
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

fn is_state_changing(m: &Method) -> bool {
    matches!(*m, Method::POST | Method::PUT | Method::DELETE | Method::PATCH)
}

/// The Host header (or a bare authority) with any `:port` removed, lower-cased
/// by the caller. Handles the `[::1]:port` IPv6 form.
fn host_of(value: &str) -> &str {
    if let Some(rest) = value.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &value[..end + 2]; // keep the bracketed literal "[::1]"
        }
    }
    match value.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => value,
    }
}

fn host_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    match headers.get(header::HOST).and_then(|h| h.to_str().ok()) {
        Some(h) => {
            let host = host_of(h).to_ascii_lowercase();
            allowed.iter().any(|a| a.as_str() == host)
        }
        // HTTP/1.1 requires a Host; a request without one is rejected.
        None => false,
    }
}

/// CSRF check: if an Origin header is present, its host must be allowed; a
/// missing Origin (same-origin navigations, `switchyardctl`, curl) passes.
fn origin_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    match headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()) {
        None => true,
        Some("null") => false,
        Some(o) => match origin_host(o) {
            Some(host) => allowed.iter().any(|a| a.as_str() == host),
            None => false,
        },
    }
}

/// Extract the lower-cased host from an Origin like `http://127.0.0.1:8087`.
fn origin_host(origin: &str) -> Option<String> {
    let after_scheme = origin.split_once("://").map(|(_, rest)| rest)?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    Some(host_of(authority).to_ascii_lowercase())
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("png") => "image/png",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdrs(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn host_of_strips_port_and_keeps_ipv6() {
        assert_eq!(host_of("127.0.0.1:8087"), "127.0.0.1");
        assert_eq!(host_of("localhost"), "localhost");
        assert_eq!(host_of("[::1]:8087"), "[::1]");
        assert_eq!(host_of("[::1]"), "[::1]");
        assert_eq!(host_of("evil.com:80"), "evil.com");
    }

    #[test]
    fn host_allowlist_blocks_rebinding() {
        let allowed = vec!["127.0.0.1".to_string(), "localhost".to_string()];
        assert!(host_allowed(&hdrs(&[("host", "127.0.0.1:8087")]), &allowed));
        assert!(host_allowed(&hdrs(&[("host", "localhost:8087")]), &allowed));
        // a rebinding attacker's own domain, resolved to 127.0.0.1, is refused
        assert!(!host_allowed(&hdrs(&[("host", "attacker.example:8087")]), &allowed));
        // no Host at all is refused
        assert!(!host_allowed(&hdrs(&[]), &allowed));
    }

    #[test]
    fn origin_check_blocks_cross_site_and_allows_same_and_missing() {
        let allowed = vec!["127.0.0.1".to_string()];
        assert!(origin_allowed(&hdrs(&[("origin", "http://127.0.0.1:8087")]), &allowed));
        assert!(origin_allowed(&hdrs(&[]), &allowed)); // no Origin (curl/ctl)
        assert!(!origin_allowed(&hdrs(&[("origin", "https://evil.example")]), &allowed));
        assert!(!origin_allowed(&hdrs(&[("origin", "null")]), &allowed));
    }
}
