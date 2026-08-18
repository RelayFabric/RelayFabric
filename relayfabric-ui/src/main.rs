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
//!   relayfabric-ui --socket /run/relayfabric/admin.sock \
//!                  --listen 127.0.0.1:8087 --web-dir relayfabric-ui/web

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use hyper_util::rt::TokioIo;

#[derive(Clone)]
struct AppState {
    socket: PathBuf,
    web_dir: PathBuf,
}

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
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = args.next().map(PathBuf::from),
            "--listen" => listen = args.next().unwrap_or(listen),
            "--web-dir" => web_dir = args.next().map(PathBuf::from).unwrap_or(web_dir),
            "-h" | "--help" => {
                eprintln!(
                    "relayfabric-ui --socket <admin.sock> [--listen 127.0.0.1:8087] [--web-dir DIR]"
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

    let state = AppState { socket, web_dir };

    let app = Router::new()
        .route("/v1/{*rest}", any(proxy))
        .route("/metrics", any(proxy))
        .route("/docs", any(proxy))
        .route("/docs/", any(proxy))
        .route("/docs/{*rest}", any(proxy))
        .fallback(static_file)
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
        "relayfabric-ui serving"
    );
    axum::serve(listener, app).await.expect("serve");
}

/// Reverse-proxy one request to the admin Unix socket over HTTP/1, streaming
/// the response body straight back (so SSE and large payloads never buffer).
async fn proxy(State(st): State<AppState>, req: Request) -> Response {
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
            if k == header::HOST {
                continue;
            }
            headers.insert(k, v.clone());
        }
        // axum serves over a real TCP host; the admin server only needs a
        // syntactically valid Host for HTTP/1.1.
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

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        _ => "application/octet-stream",
    }
}
