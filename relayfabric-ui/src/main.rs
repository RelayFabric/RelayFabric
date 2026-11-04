//! relayfabric-ui — a thin web front end for `switchyardd`.
//!
//! The daemon's admin API is a Unix-domain socket with no TCP listener and no
//! authentication (see docs/security.md). A browser cannot reach a Unix
//! socket, so this binary serves the static admin UI over TCP and
//! transparently reverse-proxies `/v1/*`, `/metrics`, and `/docs/*` to the
//! admin socket, preserving streaming so the `/v1/events` SSE feed works.
//!
//! Authentication (v0.4 cycle E): passkeys (WebAuthn) with scoped roles —
//! see `auth.rs`. On first start the console prints a one-time setup token;
//! open the UI and register the first passkey with it (it becomes
//! `administrator`). Remote (non-localhost) use REQUIRES fronting TLS: the
//! browser only offers WebAuthn in a secure context. `--no-auth` disables
//! the gate for loopback development, loudly.
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

mod auth;

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
    /// Lower-cased host names/IPs (no port) permitted in the Host header.
    /// Anything else is rejected — this is the DNS-rebinding boundary in
    /// front of an unauthenticated admin API.
    allowed_hosts: Vec<String>,
    /// Lower-cased full origins (`scheme://host[:port]`) permitted in the
    /// Origin header of state-changing requests — the CSRF boundary. Full
    /// origins, not hosts: `SameSite` cookies ignore the port, so a page on
    /// another port of an allowed host could otherwise POST with the
    /// session cookie attached.
    allowed_origins: Vec<String>,
    /// Passkey auth + roles (v0.4 cycle E). `None` only with `--no-auth`.
    auth: Option<std::sync::Arc<auth::Auth>>,
}

/// Headers that must not be forwarded to the upstream (RFC 7230 §6.1) plus
/// the framing headers hyper recomputes itself — forwarding a client-supplied
/// Content-Length / Transfer-Encoding is a request-smuggling vector.
/// See `forward`: how long one proxied `/v1/events` stream may live before
/// the client has to reconnect (and be re-authenticated).
const SSE_MAX_LIFETIME: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Applied to the UI's own HTML only (the proxied Swagger UI under /docs
/// needs inline script). Styles stay 'unsafe-inline' because the app sets
/// inline `style=` attributes; the two CDNs are the icon font and web font.
const CSP: &str = "default-src 'self'; script-src 'self'; \
    style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com; \
    font-src 'self' https://unpkg.com https://fonts.gstatic.com; \
    img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; \
    base-uri 'none'; form-action 'self'";

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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut socket: Option<PathBuf> = None;
    let mut listen = "127.0.0.1:8087".to_string();
    let mut web_dir = PathBuf::from("relayfabric-ui/web");
    let mut extra_hosts: Vec<String> = Vec::new();
    let mut extra_origins: Vec<String> = Vec::new();
    let mut state_dir = PathBuf::from("relayfabric-ui-state");
    let mut rp_id: Option<String> = None;
    let mut no_auth = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = args.next().map(PathBuf::from),
            "--listen" => listen = args.next().unwrap_or(listen),
            "--web-dir" => web_dir = args.next().map(PathBuf::from).unwrap_or(web_dir),
            "--state-dir" => state_dir = args.next().map(PathBuf::from).unwrap_or(state_dir),
            "--rp-id" => rp_id = args.next(),
            "--no-auth" => no_auth = true,
            "--allowed-host" => {
                if let Some(h) = args.next() {
                    extra_hosts.push(h.to_ascii_lowercase());
                }
            }
            "--origin" => {
                if let Some(o) = args.next() {
                    let o = o.trim_end_matches('/').to_ascii_lowercase();
                    if !o.contains("://") {
                        eprintln!("relayfabric-ui: --origin wants scheme://host[:port], got {o}");
                        std::process::exit(2);
                    }
                    extra_origins.push(o);
                }
            }
            "-h" | "--help" => {
                eprintln!(
                    "relayfabric-ui --socket <admin.sock> [--listen 127.0.0.1:8087] \
                     [--web-dir DIR] [--state-dir DIR] [--rp-id NAME] [--no-auth] \
                     [--allowed-host NAME]... [--origin scheme://host[:port]]..."
                );
                eprintln!(
                    "  --allowed-host NAME   accept Host: NAME and https://NAME origins \
                     (the TLS proxy's public name)\n  --origin ORIGIN       \
                     additionally accept this exact browser origin (e.g. a \
                     non-default https port)"
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
    allowed_hosts.extend(extra_hosts.iter().cloned());
    allowed_hosts.sort();
    allowed_hosts.dedup();
    // Origins are exact: plain HTTP only on the loopback names at the port
    // we listen on; HTTPS (default port) for every operator-named host;
    // anything else must be spelled out with --origin.
    let port = listen.rsplit_once(':').map(|(_, p)| p).unwrap_or("80");
    let http_port = if port == "80" {
        String::new()
    } else {
        format!(":{port}")
    };
    let mut allowed_origins: Vec<String> = ["localhost", "127.0.0.1", "[::1]"]
        .iter()
        .map(|h| format!("http://{h}{http_port}"))
        .collect();
    allowed_origins.extend(extra_hosts.iter().map(|h| format!("https://{h}")));
    allowed_origins.extend(extra_origins);
    allowed_origins.sort();
    allowed_origins.dedup();

    let auth_state = if no_auth {
        tracing::warn!(
            "--no-auth: the admin API is exposed WITHOUT authentication; \
             loopback development only"
        );
        None
    } else {
        // The RP id defaults to the first non-IP allowed host, else
        // "localhost" — WebAuthn RP ids are DNS names, not IPs.
        let rp = rp_id.unwrap_or_else(|| {
            allowed_hosts
                .iter()
                .find(|h| h.chars().any(|c| c.is_ascii_alphabetic()) && *h != "localhost")
                .cloned()
                .unwrap_or_else(|| "localhost".to_string())
        });
        let a = auth::Auth::open(state_dir, rp, allowed_origins.clone()).unwrap_or_else(|e| {
            eprintln!("relayfabric-ui: cannot open auth state: {e}");
            std::process::exit(1);
        });
        if !a.has_credentials() {
            tracing::warn!(
                setup_token_file = %a.setup_token_path.display(),
                "no passkeys registered yet — open the UI and register the \
                 first (administrator) passkey with the one-time setup token \
                 in this file"
            );
        }
        Some(std::sync::Arc::new(a))
    };

    let state = AppState {
        socket,
        web_dir,
        allowed_hosts,
        allowed_origins,
        auth: auth_state,
    };

    let app = Router::new()
        .route("/auth/{*rest}", any(auth_endpoint))
        .route("/v1/{*rest}", any(proxy))
        .route("/metrics", any(proxy))
        // Swagger UI's HTML uses relative asset refs (./swagger-ui.css), which
        // only resolve when the page is loaded at /docs/ (with the trailing
        // slash); the daemon serves /docs without redirecting, so send the
        // browser to /docs/ ourselves.
        .route(
            "/docs",
            any(|| async { axum::response::Redirect::permanent("/docs/") }),
        )
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
        allowed_origins = ?state.allowed_origins,
        "relayfabric-ui serving"
    );
    axum::serve(listener, app).await.expect("serve");
}

/// Clickjacking, MIME-sniffing, and referrer defenses on every response. The
/// admin UI is same-origin only; framing it or content-sniffing its types
/// serves no legitimate purpose.
async fn security_headers(req: Request, next: axum::middleware::Next) -> Response {
    let p = req.uri().path();
    let api = p.starts_with("/v1/") || p.starts_with("/auth/") || p == "/metrics";
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if api {
        // Config YAML and session responses must not land in a disk cache.
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    resp
}

/// The `/auth/*` surface (v0.4 cycle E). Registration is authorized either
/// by an administrator session (adding credentials) or — only while the
/// store is EMPTY — by the one-time setup token the console printed at
/// startup (bootstrap; the first credential is always administrator).
async fn auth_endpoint(State(st): State<AppState>, req: Request) -> Response {
    if !host_allowed(req.headers(), &st.allowed_hosts) {
        return (StatusCode::FORBIDDEN, "host not allowed").into_response();
    }
    if is_state_changing(req.method()) && !origin_allowed(req.headers(), &st.allowed_origins) {
        return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
    }
    let Some(a) = st.auth.clone() else {
        return axum::Json(serde_json::json!({
            "authenticated": true, "no_auth": true, "role": "administrator"
        }))
        .into_response();
    };

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let session = session_token(req.headers()).and_then(|t| a.session_info(&t).map(|i| (t, i)));
    let is_admin = matches!(&session, Some((_, (_, auth::Role::Administrator))));
    let setup_header = req
        .headers()
        .get("x-setup-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let token = session_token(req.headers());
    let secure = if cookie_secure(req.headers()) {
        "; Secure"
    } else {
        ""
    };

    let body = match axum::body::to_bytes(req.into_body(), 1 << 20).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response(),
    };

    match (method.as_str(), path.as_str()) {
        ("GET", "/auth/session") => {
            let resp = match &session {
                Some((_, (cred_id, role))) => serde_json::json!({
                    "authenticated": true, "role": role, "credential": cred_id,
                    "setup_required": false,
                }),
                None => serde_json::json!({
                    "authenticated": false, "setup_required": !a.has_credentials(),
                }),
            };
            axum::Json(resp).into_response()
        }
        ("POST", "/auth/login/options") => {
            let (tok, challenge) = a.new_challenge(auth::Purpose::Login);
            axum::Json(serde_json::json!({
                "challenge_token": tok, "challenge": challenge, "rp_id": a.rp_id,
            }))
            .into_response()
        }
        ("POST", "/auth/login") => {
            #[derive(serde::Deserialize)]
            struct Login {
                challenge_token: String,
                id: String,
                client_data_json: String,
                authenticator_data: String,
                signature: String,
            }
            let Ok(l) = serde_json::from_slice::<Login>(&body) else {
                return (StatusCode::BAD_REQUEST, "malformed login body").into_response();
            };
            let (Some(cdj), Some(ad), Some(sig)) = (
                auth::b64url_decode(&l.client_data_json),
                auth::b64url_decode(&l.authenticator_data),
                auth::b64url_decode(&l.signature),
            ) else {
                return (StatusCode::BAD_REQUEST, "malformed base64url field").into_response();
            };
            match a.login(&l.challenge_token, &l.id, &cdj, &ad, &sig) {
                Ok((token, role)) => {
                    let cookie = format!(
                        "{}={token}; HttpOnly{secure}; SameSite=Strict; Path=/; Max-Age=43200",
                        auth::SESSION_COOKIE
                    );
                    (
                        [(header::SET_COOKIE, cookie)],
                        axum::Json(serde_json::json!({ "role": role })),
                    )
                        .into_response()
                }
                Err(e) => (StatusCode::UNAUTHORIZED, e).into_response(),
            }
        }
        ("POST", "/auth/register/options") => {
            let bootstrap = !a.has_credentials()
                && setup_header
                    .as_deref()
                    .is_some_and(|h| ct_eq(h.as_bytes(), a.setup_token.as_bytes()));
            if !is_admin && !bootstrap {
                return (StatusCode::FORBIDDEN, "registration requires administrator")
                    .into_response();
            }
            let (tok, challenge) = a.new_challenge(auth::Purpose::Register);
            axum::Json(serde_json::json!({
                "challenge_token": tok, "challenge": challenge, "rp_id": a.rp_id,
            }))
            .into_response()
        }
        ("POST", "/auth/register") => {
            let bootstrap = !a.has_credentials()
                && setup_header
                    .as_deref()
                    .is_some_and(|h| ct_eq(h.as_bytes(), a.setup_token.as_bytes()));
            if !is_admin && !bootstrap {
                return (StatusCode::FORBIDDEN, "registration requires administrator")
                    .into_response();
            }
            #[derive(serde::Deserialize)]
            struct Register {
                challenge_token: String,
                client_data_json: String,
                attestation_object: String,
                #[serde(default)]
                role: Option<auth::Role>,
                #[serde(default)]
                label: String,
            }
            let Ok(r) = serde_json::from_slice::<Register>(&body) else {
                return (StatusCode::BAD_REQUEST, "malformed register body").into_response();
            };
            let (Some(cdj), Some(ao)) = (
                auth::b64url_decode(&r.client_data_json),
                auth::b64url_decode(&r.attestation_object),
            ) else {
                return (StatusCode::BAD_REQUEST, "malformed base64url field").into_response();
            };
            // bootstrap credential is ALWAYS administrator; later ones take
            // the admin-chosen role (default viewer).
            let role = if bootstrap {
                auth::Role::Administrator
            } else {
                r.role.unwrap_or(auth::Role::Viewer)
            };
            match a.register(&r.challenge_token, &cdj, &ao, role, r.label, bootstrap) {
                Ok(id) => axum::Json(serde_json::json!({ "id": id, "role": role })).into_response(),
                Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
            }
        }
        ("POST", "/auth/logout") => {
            if let Some(t) = token {
                a.logout(&t);
            }
            let clear = format!(
                "{}=; HttpOnly{secure}; SameSite=Strict; Path=/; Max-Age=0",
                auth::SESSION_COOKIE
            );
            ([(header::SET_COOKIE, clear)], StatusCode::NO_CONTENT).into_response()
        }
        ("GET", "/auth/credentials") => {
            if !is_admin {
                return (StatusCode::FORBIDDEN, "administrator only").into_response();
            }
            let list: Vec<_> = a
                .credentials()
                .into_iter()
                .map(|c| serde_json::json!({ "id": c.id, "role": c.role, "label": c.label }))
                .collect();
            axum::Json(serde_json::json!({ "credentials": list })).into_response()
        }
        ("DELETE", p2) if p2.starts_with("/auth/credentials/") => {
            if !is_admin {
                return (StatusCode::FORBIDDEN, "administrator only").into_response();
            }
            let id = p2.trim_start_matches("/auth/credentials/");
            match a.remove_credential(id) {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err("unknown credential") => StatusCode::NOT_FOUND.into_response(),
                Err(e @ "cannot persist credential store") => {
                    (StatusCode::INTERNAL_SERVER_ERROR, e).into_response()
                }
                Err(e) => (StatusCode::CONFLICT, e).into_response(),
            }
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// The session cookie's value, if present.
fn session_token(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == auth::SESSION_COOKIE).then(|| v.to_string())
    })
}

/// Reverse-proxy one request to the admin Unix socket over HTTP/1, after the
/// Host/Origin guards and the role gate, streaming the response body back.
async fn proxy(State(st): State<AppState>, req: Request) -> Response {
    if !host_allowed(req.headers(), &st.allowed_hosts) {
        return (StatusCode::FORBIDDEN, "host not allowed").into_response();
    }
    // CSRF: a state-changing request carrying a cross-site Origin is refused.
    if is_state_changing(req.method()) && !origin_allowed(req.headers(), &st.allowed_origins) {
        return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
    }
    // Path canonicality (audit finding): the role gate matches the raw path,
    // and `forward` sends that same raw path upstream. If the two disagreed
    // on decoding (`%69` vs `i`) or traversal (`..`, `//`), a role scope
    // could be dodged. Legitimate admin paths never carry percent-encoding,
    // `..`, or empty segments, so refuse any that do BEFORE gating —
    // gate and upstream then match byte-for-byte, independent of the
    // daemon's own router behavior.
    let path = req.uri().path();
    if path.contains('%')
        || path.split('/').any(|seg| seg == ".." || seg == ".")
        || path.contains("//")
    {
        return (StatusCode::BAD_REQUEST, "non-canonical request path").into_response();
    }
    // Role gate (v0.4 cycle E): every proxied admin request needs a live
    // session whose role permits (method, path).
    if let Some(a) = &st.auth {
        let role = session_token(req.headers()).and_then(|t| a.session_role(&t));
        let Some(role) = role else {
            return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
        };
        if !role.permits(req.method().as_str(), path) {
            return (StatusCode::FORBIDDEN, "role does not permit this action").into_response();
        }
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
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    let driver = tokio::spawn(async move {
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
    // A long-lived event stream is gated only once, at request time. Cap
    // its lifetime so a session revoked mid-stream (logout, credential
    // deletion) stops receiving events within a bounded window; the
    // browser's EventSource reconnects and is re-gated. Aborting the
    // connection driver drops the upstream socket, which ends the body.
    let sse = rparts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/event-stream"));
    if sse {
        tokio::spawn(async move {
            tokio::time::sleep(SSE_MAX_LIFETIME).await;
            driver.abort();
        });
    }
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
    let rel = if path == "/" {
        "index.html"
    } else {
        path.trim_start_matches('/')
    };
    if rel.split('/').any(|seg| seg == ".." || seg.is_empty()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let full = st.web_dir.join(rel);
    let html = |bytes: Vec<u8>| {
        (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CONTENT_SECURITY_POLICY, CSP),
            ],
            bytes,
        )
            .into_response()
    };
    match tokio::fs::read(&full).await {
        Ok(bytes) if content_type(&full).starts_with("text/html") => html(bytes),
        Ok(bytes) => ([(header::CONTENT_TYPE, content_type(&full))], bytes).into_response(),
        Err(_) if !rel.contains('.') => {
            match tokio::fs::read(st.web_dir.join("index.html")).await {
                Ok(bytes) => html(bytes),
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Constant-time byte-slice equality for the one-time setup-token compare
/// (audit finding). Length is not secret; content is.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn is_state_changing(m: &Method) -> bool {
    matches!(
        *m,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
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

/// CSRF check: if an Origin header is present it must equal one of the
/// allowed origins exactly (scheme, host and port); a missing Origin
/// (same-origin navigations, `switchyardctl`, curl) passes. Browsers that
/// send `Sec-Fetch-Site` get a second, independent check: anything but
/// same-origin (or a user-initiated navigation) is refused, which covers
/// the same-site-different-port and scheme-downgrade cases regardless of
/// how the origin list was configured.
fn origin_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|h| h.to_str().ok()) {
        if site != "same-origin" && site != "none" {
            return false;
        }
    }
    match headers.get(header::ORIGIN).and_then(|h| h.to_str().ok()) {
        None => true,
        Some("null") => false,
        Some(o) => {
            let o = o.trim_end_matches('/').to_ascii_lowercase();
            allowed.contains(&o)
        }
    }
}

/// `Secure` on the session cookie, except for a plain-http origin: Safari
/// (unlike Chrome and Firefox) refuses a Secure cookie from http://localhost,
/// which would break the documented SSH-tunnel flow. A plain-http origin only
/// reaches the auth handlers when it is loopback or explicitly `--origin`
/// listed, so the flag is dropped exactly where it could never bite.
fn cookie_secure(headers: &HeaderMap) -> bool {
    !headers
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|o| o.to_ascii_lowercase().starts_with("http://"))
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
        assert!(!host_allowed(
            &hdrs(&[("host", "attacker.example:8087")]),
            &allowed
        ));
        // no Host at all is refused
        assert!(!host_allowed(&hdrs(&[]), &allowed));
    }

    /// Safari refuses a `Secure` cookie from http://localhost (Chrome and
    /// Firefox exempt loopback), so the SSH-tunnel flow drops the flag for a
    /// plain-http origin; every https origin, and a request with no Origin
    /// at all, keeps it.
    #[test]
    fn session_cookie_is_secure_unless_the_origin_is_plain_http() {
        assert!(!cookie_secure(&hdrs(&[(
            "origin",
            "http://localhost:8087"
        )])));
        assert!(cookie_secure(&hdrs(&[(
            "origin",
            "https://relay.example.com"
        )])));
        assert!(cookie_secure(&hdrs(&[(
            "origin",
            "HTTPS://relay.example.com"
        )])));
        assert!(cookie_secure(&hdrs(&[])));
    }

    #[test]
    fn origin_check_blocks_cross_site_and_allows_same_and_missing() {
        let allowed = vec!["http://127.0.0.1:8087".to_string()];
        assert!(origin_allowed(
            &hdrs(&[("origin", "http://127.0.0.1:8087")]),
            &allowed
        ));
        assert!(origin_allowed(
            &hdrs(&[
                ("origin", "HTTP://127.0.0.1:8087/"),
                ("sec-fetch-site", "same-origin")
            ]),
            &allowed
        ));
        assert!(origin_allowed(&hdrs(&[]), &allowed)); // no Origin (curl/ctl)
        assert!(!origin_allowed(
            &hdrs(&[("origin", "https://evil.example")]),
            &allowed
        ));
        assert!(!origin_allowed(&hdrs(&[("origin", "null")]), &allowed));
        // same host, other port: SameSite=Strict would still attach the cookie
        assert!(!origin_allowed(
            &hdrs(&[("origin", "http://127.0.0.1:3000")]),
            &allowed
        ));
        // scheme downgrade of an allowed host
        assert!(!origin_allowed(
            &hdrs(&[("origin", "http://relay.example")]),
            &["https://relay.example".to_string()]
        ));
        // Sec-Fetch-Site is an independent veto even when Origin matches
        assert!(!origin_allowed(
            &hdrs(&[
                ("origin", "http://127.0.0.1:8087"),
                ("sec-fetch-site", "same-site")
            ]),
            &allowed
        ));
        assert!(!origin_allowed(
            &hdrs(&[("sec-fetch-site", "cross-site")]),
            &allowed
        ));
    }
}
