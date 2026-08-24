use crate::config::IDENTITY_ROUTE;
use crate::engine::{self, Daemon};
use crate::events::Event;
use crate::fed::advert::{self, Advert};
use crate::fed::conn::PeerConn;
use crate::identity_links;
use crate::metrics;
use axum::body::Bytes;
use axum::extract::{FromRef, Path as AxPath, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, MethodRouter};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use relay_core::Endpoint;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tracing::warn;
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

/// Admin router state (design §3): grows beyond a bare `Arc<Daemon>` because
/// `PUT /v1/config`/`POST /v1/config/rollback` need to know the daemon's
/// config file PATH, which `main.rs` only otherwise holds transiently as a
/// local var. `Arc<Daemon>` is reachable from any handler via axum's
/// `FromRef` below, so every pre-existing handler (`State(d): State<Arc<
/// Daemon>>`) keeps compiling completely unchanged.
#[derive(Clone)]
pub struct AdminState {
    daemon: Arc<Daemon>,
    config_path: PathBuf,
    /// Serializes `PUT /v1/config` and `POST /v1/config/rollback` against
    /// EACH OTHER end-to-end — file renames plus the `apply_config` call
    /// that follows — so two overlapping requests can never interleave
    /// their renames of the same `<path>`/`<path>.prev` pair.
    /// `Daemon::apply_config`'s own `apply_lock` (engine.rs) only covers
    /// `apply_config`'s body; the file I/O that happens before it is
    /// admin.rs's concern, not the daemon's, hence a separate lock here.
    write_lock: Arc<Mutex<()>>,
}

impl FromRef<AdminState> for Arc<Daemon> {
    fn from_ref(state: &AdminState) -> Arc<Daemon> {
        state.daemon.clone()
    }
}

/// Single source of truth for every admin route (Task 1, design §1
/// completeness test): `router()` below is BUILT from this list rather than
/// a hand-chained sequence of `.route(...)` calls, so the number of paths
/// the live `Router` actually serves is a structural fact
/// (`admin_routes().len()`), not a separately hand-maintained count that
/// could silently drift from reality. `admin::tests::
/// every_admin_route_is_documented_in_the_openapi_spec` cross-checks this
/// same list's paths against `ApiDoc::openapi().paths` -- so a route added
/// here without an accompanying `#[utoipa::path]` (registered in `ApiDoc`'s
/// `paths(...)`) fails that test, and a route documented in `ApiDoc` that
/// isn't ALSO in this list simply never gets registered on the live
/// `Router` (caught by the same test's live-request probe, which sends a
/// request for every method `ApiDoc` documents and would 404).
fn admin_routes() -> Vec<(&'static str, MethodRouter<AdminState>)> {
    vec![
        ("/v1/status", get(status)),
        ("/v1/plugins", get(plugins)),
        ("/v1/routes", get(routes)),
        ("/v1/config", get(config_yaml).put(config_put)),
        ("/v1/config/prev", get(config_prev)),
        ("/v1/config/validate", post(config_validate)),
        ("/v1/config/rollback", post(config_rollback)),
        ("/v1/queue", get(queue)),
        ("/v1/messages/{id}", get(trace)),
        ("/v1/public", get(public)),
        ("/v1/limits", get(limits)),
        ("/v1/identities", get(identities)),
        ("/v1/identities/link", post(create_link)),
        ("/v1/identities/link/{id}", delete(delete_link)),
        ("/v1/identities/challenges", get(challenges)),
        ("/v1/federation", get(federation)),
        ("/v1/discovery", get(discovery)),
        ("/v1/events", get(events_stream)),
        ("/healthz", get(healthz)),
        ("/readyz", get(readyz)),
        ("/metrics", get(metrics_text)),
        ("/v1/openapi.json", get(openapi_json)),
    ]
}

pub fn router(d: Arc<Daemon>, config_path: PathBuf) -> Router {
    let state = AdminState {
        daemon: d,
        config_path,
        write_lock: Arc::new(Mutex::new(())),
    };
    let mut r: Router<AdminState> = Router::new();
    for (path, method_router) in admin_routes() {
        r = r.route(path, method_router);
    }
    // `/docs` (Task 2, design §2) is deliberately NOT in `admin_routes()`:
    // it's the interactive UI, not part of the API contract, so it must
    // never be documented in `ApiDoc`'s `paths(...)` -- if it lived in
    // `admin_routes()`, `every_admin_route_is_documented_in_the_openapi_spec`
    // would demand a matching `#[utoipa::path]` entry for it, which would
    // then wrongly put the UI itself into the OpenAPI contract. Mounted
    // here, after `with_state`, on the fully-built `Router` instead.
    r.with_state(state)
        .route("/docs", get(docs_index))
        .route("/docs/", get(docs_index))
        .route("/docs/{*rest}", get(docs_asset))
}

/// Takes an already-bound listener (bind failures must fail startup loudly in
/// `main`, not silently kill only this background task — see `plugins.sock`).
pub async fn serve(d: Arc<Daemon>, config_path: PathBuf, listener: tokio::net::UnixListener) {
    axum::serve(listener, router(d, config_path))
        .await
        .expect("admin serve");
}

/// A 500 for a storage read that failed, so the control plane surfaces the
/// error instead of returning an empty `200 OK` that reads as "no data" and
/// masks a real DB failure (audit: fail-quiet control plane).
fn storage_error(e: impl std::fmt::Display) -> Response {
    warn!(error = %e, "admin storage read failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": format!("storage error: {e}")})),
    )
        .into_response()
}

fn queue_map(d: &Daemon) -> BTreeMap<String, i64> {
    d.store
        .lock()
        .unwrap()
        .queue_counts()
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// Cfg is read (and dropped) BEFORE `plugins` is locked -- consistent lock
/// order (cfg never held across another Daemon lock acquisition) matters
/// more than which order is chosen, but "cfg first" is what every other
/// call site in this module follows too.
fn plugin_state(d: &Daemon) -> Vec<(String, bool)> {
    let enabled_names: Vec<String> = d.cfg_snapshot(|c| {
        c.plugins
            .iter()
            .filter(|(_, p)| p.enabled)
            .map(|(name, _)| name.clone())
            .collect()
    });
    let connected = d.plugins.lock().unwrap();
    enabled_names
        .into_iter()
        .map(|name| {
            let up = connected.get(&name).map(|h| h.connected).unwrap_or(false);
            (name, up)
        })
        .collect()
}

/// `GET /v1/status` response (Task 1, design §1: promoted from ad-hoc
/// `json!` -- cheap, and the WebUI wants a typed shape). Field order is
/// alphabetical to match byte-for-byte what `serde_json::json!`'s
/// (non-`preserve_order`) `BTreeMap`-backed `Value::Object` already
/// serialized before this promotion -- see `admin::tests::
/// status_response_serializes_byte_identical_to_the_pre_promotion_json_shape`.
#[derive(Serialize, ToSchema)]
struct StatusResponse {
    node: String,
    node_id: String,
    plugins: BTreeMap<String, bool>,
    public: bool,
    queue: BTreeMap<String, i64>,
}

/// Liveness/readiness probe body. `status` is `ok` (healthz), `ready`, or
/// `unavailable` (readyz).
#[derive(Serialize, ToSchema)]
struct HealthResponse {
    status: String,
}

/// `GET /healthz` — liveness. 200 whenever the daemon is serving requests,
/// for container HEALTHCHECK / systemd / uptime monitors. Deliberately checks
/// nothing else (plugin/storage health is `/readyz` and `/v1/status`), so a
/// hung daemon fails it by not answering at all.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "status",
    summary = "Liveness probe",
    description = "200 while the daemon is serving. Checks nothing beyond that — see /readyz for core readiness and /v1/status for plugin state.",
    responses((status = 200, description = "Daemon is alive", body = HealthResponse)),
)]
async fn healthz() -> impl IntoResponse {
    Json(HealthResponse { status: "ok".into() })
}

/// `GET /readyz` — readiness. 200 if core storage is reachable (the node can
/// route), 503 otherwise. A disconnected plugin (e.g. an unplugged radio) is
/// operational state reported by `/v1/status`, NOT a readiness failure, so it
/// does not flip a load balancer / orchestrator away from an otherwise-fine
/// node.
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "status",
    summary = "Readiness probe",
    description = "200 if core storage is reachable (the node can route); 503 if a storage error means it cannot. Plugin connectivity is reported by /v1/status, not here.",
    responses(
        (status = 200, description = "Node is ready to route", body = HealthResponse),
        (status = 503, description = "Core storage unavailable", body = HealthResponse),
    ),
)]
async fn readyz(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    match d.store.lock().unwrap().queue_counts() {
        Ok(_) => (StatusCode::OK, Json(HealthResponse { status: "ready".into() })).into_response(),
        Err(e) => {
            warn!(error = %e, "readiness check failed: core storage unavailable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse { status: "unavailable".into() }),
            )
                .into_response()
        }
    }
}

/// `GET /v1/status` (design §Admin API): node identity, public-mode flag,
/// per-plugin connected state, and aggregate queue counts by state.
#[utoipa::path(
    get,
    path = "/v1/status",
    tag = "status",
    summary = "Node status",
    description = "Node name/id, public-mode flag, per-plugin connected state, and aggregate queue counts by delivery state.",
    responses(
        (status = 200, description = "Current node status", body = StatusResponse),
    ),
)]
async fn status(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let plugins: BTreeMap<_, _> = plugin_state(&d).into_iter().collect();
    let (node_name, public) = d.cfg_snapshot(|c| (c.node.name.clone(), c.node.public));
    Json(StatusResponse {
        node: node_name,
        node_id: d.node_id.clone(),
        plugins,
        public,
        queue: queue_map(&d),
    })
}

/// spec §112.3: which services this node exposes publicly, and their
/// ingress/egress protocol coverage — the WebUI (and, later, RFDP
/// discovery) read this rather than parsing the raw config.
/// One `GET /v1/public` service entry (Task 1: promoted from ad-hoc
/// `json!`). Field order alphabetical -- see `StatusResponse`'s doc comment
/// for why.
#[derive(Serialize, ToSchema)]
struct PublicServiceItem {
    egress: Vec<String>,
    ingress: Vec<String>,
    name: String,
    #[serde(rename = "type")]
    r#type: String,
}

#[derive(Serialize, ToSchema)]
struct PublicResponse {
    public: bool,
    services: Vec<PublicServiceItem>,
}

/// `GET /v1/public` (design §112.3): which services this node exposes
/// publicly, and their ingress/egress protocol coverage.
#[utoipa::path(
    get,
    path = "/v1/public",
    tag = "status",
    summary = "Publicly exposed services",
    description = "Whether this node is in public mode, and (if so) the public_services entries it exposes with their ingress/egress protocol coverage.",
    responses(
        (status = 200, description = "Public-mode flag and configured public services", body = PublicResponse),
    ),
)]
async fn public(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let (public, services) = d.cfg_snapshot(|c| {
        let services: Vec<_> = c
            .public_services
            .iter()
            .map(|s| PublicServiceItem {
                egress: s.egress.clone(),
                ingress: s.ingress.clone(),
                name: s.name.clone(),
                r#type: s.r#type.clone(),
            })
            .collect();
        (c.node.public, services)
    });
    Json(PublicResponse { public, services })
}

/// Configured quotas and transport budgets (spec §112.8/§45/§79) — a config
/// echo, not live counter state: an operator diagnosing "why is this
/// getting rate-limited" starts from what's configured, and the in-memory
/// limiter windows aren't worth exposing (they reset on restart and aren't
/// meaningful without matching request context anyway).
/// `GET /v1/limits` response family (Task 1: promoted from ad-hoc `json!`).
/// Field order alphabetical throughout -- see `StatusResponse`'s doc
/// comment for why.
#[derive(Serialize, ToSchema)]
struct GlobalLimitsItem {
    cas_max_bytes: u64,
    queue_max: u32,
}

#[derive(Serialize, ToSchema)]
struct PerRouteLimitsItem {
    queue_max: u32,
}

#[derive(Serialize, ToSchema)]
struct PerSenderLimitsItem {
    bytes_per_hour: u64,
    messages_per_minute: u32,
}

#[derive(Serialize, ToSchema)]
struct TransportBudgetItem {
    messages_per_minute: u32,
}

#[derive(Serialize, ToSchema)]
struct LimitsResponse {
    global: GlobalLimitsItem,
    per_route: PerRouteLimitsItem,
    per_sender: PerSenderLimitsItem,
    transport_budgets: BTreeMap<String, TransportBudgetItem>,
}

/// `GET /v1/limits` (design §112.8/§45/§79): configured quotas and
/// transport budgets -- a config echo, not live counter state.
#[utoipa::path(
    get,
    path = "/v1/limits",
    tag = "status",
    summary = "Configured quotas and transport budgets",
    description = "Configured per-sender/per-route/global limits and per-transport-protocol egress budgets. A config echo, not live limiter counter state (which resets on restart).",
    responses(
        (status = 200, description = "Configured limits", body = LimitsResponse),
    ),
)]
async fn limits(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    Json(d.cfg_snapshot(|c| {
        let transport_budgets: BTreeMap<_, _> = c
            .transport_budgets
            .iter()
            .map(|(proto, b)| {
                (
                    proto.clone(),
                    TransportBudgetItem {
                        messages_per_minute: b.messages_per_minute,
                    },
                )
            })
            .collect();
        LimitsResponse {
            global: GlobalLimitsItem {
                cas_max_bytes: c.limits.global.cas_max_bytes,
                queue_max: c.limits.global.queue_max,
            },
            per_route: PerRouteLimitsItem {
                queue_max: c.limits.per_route.queue_max,
            },
            per_sender: PerSenderLimitsItem {
                bytes_per_hour: c.limits.per_sender.bytes_per_hour,
                messages_per_minute: c.limits.per_sender.messages_per_minute,
            },
            transport_budgets,
        }
    }))
}

/// `GET /v1/plugins` (design §2): `capabilities` (full `Capabilities`
/// object, `null` when never connected) and `gauges` (latest finite
/// values + age_secs, `{}` when the plugin never reported any or its
/// snapshot has gone stale -- see `PluginGauges::for_plugin`).
///
/// LOCK DISCIPLINE: `connected`/`capabilities` are copied out of the
/// `plugins` guard inside this block, which drops the guard before
/// `d.gauges` (a separate lock) is ever touched -- never hold one Daemon
/// lock while acquiring another.
/// `GET /v1/plugins` response shape, DOCUMENTATION ONLY (Task 1: this type
/// is never constructed or returned by `plugins()` below -- it exists
/// purely so `ApiDoc` has a concrete schema to reference). `capabilities`
/// mirrors `relay_core::Capabilities` (defined in a different workspace
/// crate, `relay-core`, which does not depend on `utoipa` -- adding that
/// dependency there to derive `ToSchema` directly on `Capabilities` was
/// judged out of scope for this task's license-gated, switchyardd-only
/// `utoipa` addition) serialized through `serde_json::to_value`, so it's
/// documented here as a free-form object rather than a `$ref` to the real
/// type. `gauges` values are similarly free-form (arbitrary plugin-reported
/// gauge names). The real handler is unchanged -- still `BTreeMap<String,
/// serde_json::Value>` built ad-hoc -- because typing `capabilities`
/// faithfully would mean either duplicating `Capabilities`' fields here
/// (drifts the moment that struct changes) or reaching into `relay-core`,
/// both worse than an honest free-form schema.
#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct PluginGaugeItemDoc {
    age_secs: u64,
    value: f64,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct PluginEntryDoc {
    /// Mirrors `relay_core::Capabilities` (text/direct_messages/groups/
    /// attachments/location/reactions/receipts/presence: bool,
    /// max_payload: Option<u64>); `null` when the plugin has never
    /// connected.
    capabilities: Option<serde_json::Value>,
    connected: bool,
    /// Keyed by gauge name (plugin-reported, e.g. "queue_depth"); empty
    /// when the plugin never reported gauges or its snapshot has gone
    /// stale.
    gauges: BTreeMap<String, PluginGaugeItemDoc>,
}

/// `GET /v1/plugins` response, DOCUMENTATION ONLY -- see `PluginEntryDoc`.
/// Keyed by plugin name.
#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct PluginsResponseDoc(BTreeMap<String, PluginEntryDoc>);

/// `GET /v1/plugins` (design §2): per-plugin connected state, capabilities
/// (as last reported over the plugin socket; `null` if never connected),
/// and the latest finite gauge values with their age in seconds.
#[utoipa::path(
    get,
    path = "/v1/plugins",
    tag = "status",
    summary = "Per-plugin state and capabilities",
    description = "Enabled plugins keyed by name: connected state, last-reported capabilities (null if never connected), and latest gauge values with age_secs (empty if none reported or stale).",
    responses(
        (status = 200, description = "Per-plugin state", body = PluginsResponseDoc),
    ),
)]
async fn plugins(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let enabled_names: Vec<String> = d.cfg_snapshot(|c| {
        c.plugins
            .iter()
            .filter(|(_, p)| p.enabled)
            .map(|(name, _)| name.clone())
            .collect()
    });
    let states: Vec<(String, bool, Option<serde_json::Value>)> = {
        let handles = d.plugins.lock().unwrap();
        enabled_names
            .into_iter()
            .map(|name| {
                let h = handles.get(&name);
                let connected = h.map(|h| h.connected).unwrap_or(false);
                let capabilities = h.map(|h| serde_json::to_value(&h.capabilities).unwrap());
                (name, connected, capabilities)
            })
            .collect()
    };
    let now = std::time::Instant::now();
    let out: BTreeMap<String, serde_json::Value> = states
        .into_iter()
        .map(|(name, connected, capabilities)| {
            let gauges: BTreeMap<String, serde_json::Value> = d
                .gauges
                .for_plugin(&name, now)
                .into_iter()
                .map(|(gauge_name, (value, age_secs))| {
                    (gauge_name, json!({ "value": value, "age_secs": age_secs }))
                })
                .collect();
            let entry = json!({
                "connected": connected,
                "capabilities": capabilities,
                "gauges": gauges,
            });
            (name, entry)
        })
        .collect();
    Json(out)
}

/// Policy names "applying to" `route`, mirroring `policy::evaluate`'s own
/// per-delivery matching rule: each delivery is evaluated against its
/// single destination endpoint's protocol, so a policy applies to a route
/// if its `match.destination_protocol` is empty (matches every protocol,
/// same "no restriction" reading `policy::evaluate` gives an empty list)
/// or intersects the set of protocols among the route's OWN destinations.
/// Order follows `cfg.policies`' declaration order (same as evaluate's
/// iteration), not `route.destinations`' order.
fn policies_for_route<'a>(
    route: &crate::config::RouteConfig,
    policies: &'a [crate::config::Policy],
) -> Vec<&'a str> {
    let dest_protocols: std::collections::BTreeSet<&str> = route
        .destinations
        .iter()
        .map(|e| e.protocol.as_str())
        .collect();
    policies
        .iter()
        .filter(|p| {
            p.r#match.destination_protocol.is_empty()
                || p.r#match
                    .destination_protocol
                    .iter()
                    .any(|proto| dest_protocols.contains(proto.as_str()))
        })
        .map(|p| p.name.as_str())
        .collect()
}

/// `GET /v1/routes` (design §2): per-route detail beyond name/sources/
/// destinations -- `identity_mode`, `render` knobs, and the policy names
/// that apply (see `policies_for_route`). Source/destination endpoints
/// render as configured: they're operator-written protocol:channel
/// strings (already visible in `/v1/config`), not native user refs, so no
/// masking applies here -- masking (RULING 2's compound form) is reserved
/// for identity refs like `/v1/identities` and `/v1/messages/{id}`
/// deliveries on the `@identity` route.
/// `GET /v1/routes` response family (Task 1: promoted from ad-hoc `json!`).
/// Field order alphabetical -- see `StatusResponse`'s doc comment for why.
#[derive(Serialize, ToSchema)]
struct RouteRenderItem {
    max_chars: u32,
    tag: String,
}

#[derive(Serialize, ToSchema)]
struct RouteItem {
    destinations: Vec<String>,
    identity_mode: String,
    name: String,
    policies: Vec<String>,
    render: RouteRenderItem,
    sources: Vec<String>,
}

#[derive(Serialize, ToSchema)]
struct RoutesResponse {
    routes: Vec<RouteItem>,
}

/// `GET /v1/routes` (design §2): per-route detail beyond name/sources/
/// destinations -- `identity_mode`, `render` knobs, and the policy names
/// that apply.
#[utoipa::path(
    get,
    path = "/v1/routes",
    tag = "status",
    summary = "Configured routes with policy/render detail",
    description = "Every configured route: sources/destinations (rendered as protocol:channel strings), identity_mode, render knobs, and the names of policies that apply to it.",
    responses(
        (status = 200, description = "Configured routes", body = RoutesResponse),
    ),
)]
async fn routes(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    Json(RoutesResponse {
        routes: d.cfg_snapshot(|c| {
            c.routes
                .iter()
                .map(|r| RouteItem {
                    destinations: r.destinations.iter().map(|e| e.to_string()).collect(),
                    identity_mode: r.identity_mode.clone(),
                    name: r.name.clone(),
                    policies: policies_for_route(r, &c.policies)
                        .into_iter()
                        .map(String::from)
                        .collect(),
                    render: RouteRenderItem {
                        max_chars: r.render.max_chars,
                        tag: r.render.tag.clone(),
                    },
                    sources: r.sources.iter().map(|e| e.to_string()).collect(),
                })
                .collect()
        }),
    })
}

/// `GET /v1/config` (design §2): the loaded config as YAML text, secrets
/// UNRESOLVED. Serves `Config.raw_yaml` byte-verbatim -- that field is
/// captured straight from the loaded file's text, before parsing/
/// resolution touch anything, and is never mutated except by
/// `apply_config` storing a newly-applied config's own raw text -- so
/// byte-fidelity to whatever's actually loaded and zero secret exposure
/// both fall out of "just don't re-serialize anything".
#[utoipa::path(
    get,
    path = "/v1/config",
    tag = "config",
    summary = "Loaded config as YAML",
    description = "The currently loaded config file, byte-verbatim, with secret references UNRESOLVED (e.g. `${env:...}`) -- never a resolved secret value.",
    responses(
        (status = 200, description = "Loaded config YAML", content_type = "text/yaml", body = String),
    ),
)]
async fn config_yaml(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let yaml = d.cfg_snapshot(|c| c.raw_yaml.clone());
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/yaml")],
        yaml,
    )
}

/// `?n=` selector for `GET /v1/config/prev`: which retained revision to
/// read, 1 (newest, the default) to `CONFIG_HISTORY` (oldest kept).
#[derive(serde::Deserialize)]
struct PrevQuery {
    n: Option<usize>,
}

/// `GET /v1/config/prev[?n=N]`: a retained previous revision, byte-verbatim
/// from disk with secret references unresolved. `n` selects the revision,
/// 1 (newest, default) to `CONFIG_HISTORY`; `n=1` is what a
/// `POST /v1/config/rollback` would restore. 404 when that slot holds no
/// revision (nothing applied yet, or `n` beyond the kept history). Read
/// straight from the file, not the in-memory config, since these are exactly
/// the files the `PUT`/rollback renames juggle.
#[utoipa::path(
    get,
    path = "/v1/config/prev",
    tag = "config",
    summary = "Previous config revision (.prev, up to 5 kept)",
    description = "A retained previous config revision, byte-verbatim with secret references UNRESOLVED. `?n=` selects which (1 = newest and the default, up to 5 kept — the daemon rotates `.prev`, `.prev.2` … `.prev.5` on each apply). `n=1` is what `POST /v1/config/rollback` would restore. 404 if that slot holds no revision.",
    params(("n" = Option<usize>, Query, description = "Which revision to read: 1 = newest (default) .. 5 = oldest kept")),
    responses(
        (status = 200, description = "Previous config YAML", content_type = "text/yaml", body = String),
        (status = 404, description = "No revision in that slot"),
    ),
)]
async fn config_prev(State(state): State<AdminState>, Query(q): Query<PrevQuery>) -> Response {
    let n = q.n.unwrap_or(1);
    if !(1..=CONFIG_HISTORY).contains(&n) {
        return (StatusCode::NOT_FOUND, "no revision in that slot").into_response();
    }
    let prev = prev_slot_path(&state.config_path, n);
    match std::fs::read_to_string(&prev) {
        Ok(text) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/yaml")],
            text,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "no revision in that slot").into_response(),
    }
}

/// How many previous config revisions to retain. Slot 1 (newest) is
/// `<path>.prev`; slots 2..=CONFIG_HISTORY are `<path>.prev.2`..`.prev.N`.
const CONFIG_HISTORY: usize = 5;

/// `<path>.prev` — the newest previous revision (slot 1), the one
/// `rollback` swaps into and out of. Older revisions live at
/// `prev_slot_path(path, 2..=CONFIG_HISTORY)`.
fn prev_path_for(path: &Path) -> PathBuf {
    prev_slot_path(path, 1)
}

/// History slot `n` (1 = newest). Slot 1 keeps the legacy `<path>.prev`
/// name so pre-existing single-revision backups and `GET /v1/config/prev`
/// keep working unchanged; slots 2.. append the ordinal (`.prev.2`, …).
fn prev_slot_path(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    if n <= 1 {
        s.push(".prev");
    } else {
        s.push(format!(".prev.{n}"));
    }
    PathBuf::from(s)
}

/// Scratch name used to make both file operations below crash-safe: never
/// the target of a reader, only ever a rename source/destination within a
/// single call.
fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

/// `PUT /v1/config`'s file half (design §3): writes `new_text` to a tmp
/// file FIRST (mode 0600 via `OpenOptionsExt`, `alias.rs`'s key-file
/// precedent) — the one genuinely I/O-heavy step, the one that can fail
/// partway (ENOSPC, permissions, …) — and only once that has fully
/// succeeded does it touch `path`/`.prev` at all: rotates the retained
/// history down one slot (dropping the oldest of `CONFIG_HISTORY` kept),
/// renames whatever is currently at `path` to `<path>.prev`, then renames
/// the tmp file into place at `path`. A failure during the write leaves
/// `path` and `.prev`
/// byte-identical to before the call (a stray `.tmp` is harmless — the
/// next attempt overwrites it); a failure during either rename is
/// vanishingly unlikely (same-filesystem directory-entry operations, no
/// data movement). This ordering fixes a real gap in the previous
/// rename-then-write ordering: a failure during the write used to leave
/// NEITHER a `path` NOR a self-recoverable `.prev` (rollback renames
/// `path` first, so it can't recover from `path` already being absent).
/// `rename()` preserves the SOURCE file's mode, not the destination's — so
/// without the explicit `set_permissions` calls below, `.prev` (and, after
/// a later rollback, the live config at `path`) would silently inherit
/// whatever mode the operator's original file had (commonly 644) forever.
/// Caller (`config_put`) is responsible for having already validated
/// `new_text` via `config::load_from_str`; this function only ever moves
/// bytes around.
fn write_config_replacing_current(path: &Path, new_text: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let tmp_path = tmp_path_for(path);
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(new_text.as_bytes())?;
    }
    // Rotate the retained history down by one BEFORE touching the live
    // config: drop the oldest slot, then shift each remaining slot down
    // (`.prev.4`->`.prev.5`, … `.prev`->`.prev.2`). This happens only after
    // the tmp write succeeded, and it never moves `path` itself, so a
    // failure here still leaves the live config byte-identical to before.
    let _ = std::fs::remove_file(prev_slot_path(path, CONFIG_HISTORY));
    for n in (1..CONFIG_HISTORY).rev() {
        let from = prev_slot_path(path, n);
        if from.exists() {
            let to = prev_slot_path(path, n + 1);
            std::fs::rename(&from, &to)?;
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    // The current-config -> slot 1 rename and the tmp -> path rename run
    // back-to-back with nothing fallible between them, so the only crash
    // window where `path` is transiently absent is the gap between those two
    // same-directory rename() calls. The chmods run after both renames: a
    // chmod failure then leaves complete files at final names.
    let had_prev = path.exists();
    let prev_path = prev_path_for(path);
    if had_prev {
        std::fs::rename(path, &prev_path)?;
    }
    std::fs::rename(&tmp_path, path)?;
    if had_prev {
        std::fs::set_permissions(&prev_path, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// `POST /v1/config/rollback`'s file half (design §3): swaps `path` and
/// `<path>.prev` via a temporary third name — `path` -> tmp, `.prev` ->
/// `path`, tmp -> `.prev` — so "current becomes `.prev`" and "`.prev`
/// becomes current" happen together. Each individual rename is atomic
/// (same filesystem), but the three-step sequence as a whole is not a
/// single atomic operation — a crash between steps could leave `.prev`
/// transiently missing with its content sitting in the tmp name — the
/// same limitation any `rename()`-based swap has. `rename()` preserves the
/// SOURCE's mode, not the destination's, so BOTH files landing in a new
/// location get their mode force-set back to 0600 once all renames are
/// done — without this, a rollback would leave the live config at
/// `path` carrying whatever mode the file previously at `.prev` happened
/// to have (which, before Task 3's PUT/rollback ever touched it, could be
/// the operator's original 644). Caller (`config_rollback`) re-validates
/// `.prev`'s content BEFORE calling this, so the file that ends up live at
/// `path` is already known-good.
fn swap_with_prev(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let prev_path = prev_path_for(path);
    let swap_tmp = tmp_path_for(path);
    // All three renames run back-to-back (no fallible call between them);
    // both chmods happen only once every file sits at its final name.
    std::fs::rename(path, &swap_tmp)?;
    std::fs::rename(&prev_path, path)?;
    std::fs::rename(&swap_tmp, &prev_path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::set_permissions(&prev_path, std::fs::Permissions::from_mode(0o600))
}

/// Shared by `config_validate`/`config_put`: both take a raw YAML body and
/// must reject non-UTF-8 bytes the exact same way (422, same shape as any
/// other validation failure) before doing anything else with it.
fn decode_body_or_422(body: &Bytes) -> Result<&str, (StatusCode, Json<serde_json::Value>)> {
    std::str::from_utf8(body).map_err(|_| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"valid": false, "errors": ["request body is not valid UTF-8"]})),
        )
    })
}

/// `POST /v1/config/validate` (design §3): runs the exact same parse +
/// `config::validate` + secret-reference-resolution pipeline `PUT`/startup
/// use (`config::load_from_str`) against the POSTed YAML text, discards the
/// resolved `Config` on success, and returns only a boolean. Resolution
/// happens against the DAEMON's own environment (this handler runs
/// in-process, same env the daemon itself resolves `${env:...}` against) —
/// that's intentional: the point of validating is knowing whether applying
/// this text would actually succeed HERE, not on whatever machine `ctl` is
/// running on. 422 error strings come straight from `load_from_str`/
/// `secrets::resolve`, which name only the `${...}` reference form, never a
/// resolved value (design §2's redaction invariant, upheld here too) — and
/// `load_from_str` runs `validate` BEFORE `resolve_secrets`, so a config
/// that fails validation for an unrelated reason never resolves ANY secret
/// reference in the first place, regardless of whether it would have
/// resolved fine (see `config_validate_returns_422_with_neither_the_
/// sentinel_nor_a_resolved_value_when_validation_fails_for_an_unrelated_
/// reason` below).
/// `POST /v1/config/validate` / `PUT /v1/config` response shapes,
/// DOCUMENTATION ONLY (Task 1: not in the brief's named promote-list;
/// small and asymmetric -- success and failure carry different fields --
/// so a doc-only pair of schemas is clearer than forcing one struct with
/// always-optional fields the handlers never actually emit that way).
#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct ConfigValidateOk {
    valid: bool,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct ConfigValidateError {
    errors: Vec<String>,
    valid: bool,
}

/// `POST /v1/config/validate` (design §3): runs the exact same parse +
/// validate + secret-resolution pipeline `PUT`/startup use against the
/// POSTed YAML text and returns only whether it would apply successfully.
#[utoipa::path(
    post,
    path = "/v1/config/validate",
    tag = "config",
    summary = "Validate a config document without applying it",
    description = "Runs the same parse/validate/secret-resolution pipeline PUT /v1/config uses against the request body, discards the result, and reports only whether it's valid. Never resolves or echoes any secret value.",
    request_body(content = String, content_type = "text/yaml", description = "Candidate config YAML"),
    responses(
        (status = 200, description = "Config is valid", body = ConfigValidateOk),
        (status = 422, description = "Config is invalid (parse/validate error, or not valid UTF-8)", body = ConfigValidateError),
    ),
)]
async fn config_validate(body: Bytes) -> impl IntoResponse {
    let text = match decode_body_or_422(&body) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    match crate::config::load_from_str(text) {
        Ok(_) => (StatusCode::OK, Json(json!({"valid": true}))),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"valid": false, "errors": [e]})),
        ),
    }
}

/// `PUT /v1/config` (design §3): validates the POSTed YAML text first (422,
/// zero filesystem changes, on failure — same pipeline as
/// `config_validate`), then, holding `write_lock` for the rest of the
/// handler (serialized against a racing `config_rollback`), replaces the
/// on-disk config file (`write_config_replacing_current`) and calls
/// `apply_config` (which itself serializes against ANY other `apply_config`
/// caller via its own `apply_lock` — see that method's doc comment).
/// `PUT /v1/config` success response, DOCUMENTATION ONLY (see
/// `ConfigValidateOk`'s doc comment for why this stays a doc-only mirror
/// rather than wiring into the handler).
#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct ConfigApplyOk {
    applied: bool,
    /// Names of enabled plugins whose process must be restarted for this
    /// config change to take full effect (empty if none).
    restart_required: Vec<String>,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct ConfigWriteError {
    error: String,
}

/// Plugin `command`s an admin-API config write is trying to introduce or
/// change, relative to the currently-running config. Executing a plugin
/// command is deferred RCE (the daemon `sh -c`s it), and a command change
/// needs a restart to take effect anyway, so the admin API refuses to be the
/// path that sets one (defense-in-depth: the write socket's safety no longer
/// rests solely on it never being reachable). Setting a command to null,
/// removing a plugin, or leaving a command byte-identical is allowed; only
/// the on-disk config file, edited out of band, may introduce or change a
/// non-null command.
fn rejected_command_changes(
    current: &BTreeMap<String, Option<String>>,
    new: &crate::config::Config,
) -> Vec<String> {
    let mut names: Vec<String> = new
        .plugins
        .iter()
        .filter_map(|(name, p)| {
            p.command.as_ref().and_then(|cmd| {
                let prev = current.get(name).and_then(|c| c.as_ref());
                if prev == Some(cmd) {
                    None
                } else {
                    Some(name.clone())
                }
            })
        })
        .collect();
    names.sort();
    names
}

/// `PUT /v1/config` (design §3): validates the POSTed YAML text (422 on
/// failure, zero filesystem changes), then replaces the on-disk config file
/// and applies it.
#[utoipa::path(
    put,
    path = "/v1/config",
    tag = "config",
    summary = "Replace and apply the config",
    description = "Validates the request body first (no filesystem changes on failure), then writes it as the new config file (keeping the previous one as a single-revision `.prev` backup) and applies it live.",
    request_body(content = String, content_type = "text/yaml", description = "New config YAML"),
    responses(
        (status = 200, description = "Config written and applied", body = ConfigApplyOk),
        (status = 422, description = "Config is invalid, or the body is not valid UTF-8; nothing written", body = ConfigValidateError),
        (status = 500, description = "Config was valid but writing it to disk failed (e.g. ENOSPC, permissions)", body = ConfigWriteError),
    ),
)]
async fn config_put(State(state): State<AdminState>, body: Bytes) -> impl IntoResponse {
    let text = match decode_body_or_422(&body) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let new_cfg = match crate::config::load_from_str(text) {
        Ok(cfg) => cfg,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"valid": false, "errors": [e]})),
            );
        }
    };
    // Defense-in-depth (audit HIGH): the admin API must not be able to set or
    // change a plugin's executable command -- that would be deferred RCE.
    let current_commands: BTreeMap<String, Option<String>> = state.daemon.cfg_snapshot(|c| {
        c.plugins
            .iter()
            .map(|(k, v)| (k.clone(), v.command.clone()))
            .collect()
    });
    let rejected = rejected_command_changes(&current_commands, &new_cfg);
    if !rejected.is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"valid": false, "errors": [format!(
                "plugin command may not be set or changed via the admin API \
                 (edit the config file and restart the daemon instead): {}",
                rejected.join(", ")
            )]})),
        );
    }
    let _write_guard = state.write_lock.lock().unwrap();
    if let Err(e) = write_config_replacing_current(&state.config_path, text) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to write config file: {e}")})),
        );
    }
    let outcome = state.daemon.apply_config(new_cfg);
    (
        StatusCode::OK,
        Json(json!({"applied": true, "restart_required": outcome.restart_required})),
    )
}

/// `POST /v1/config/rollback` (design §3): 404 if no `<path>.prev` exists.
/// Re-validates `.prev`'s content via `config::load_from_str` BEFORE
/// touching any file — unlike a "swap first, validate second, undo on
/// failure" sequence, validating first means an invalid `.prev` (env
/// drift: a secret reference that resolved fine when the file was written
/// no longer does) can never even transiently become the live config file,
/// and "files restored to pre-call state" on the 409 is then true by
/// construction — nothing was ever touched — rather than by an undo step.
/// On success, swaps `path`/`.prev` (`swap_with_prev`: current becomes
/// `.prev`, matching `PUT`'s one-revision-history rule) and applies.
#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct ConfigRollbackNotFound {
    error: String,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct ConfigRollbackConflict {
    errors: Vec<String>,
}

/// `POST /v1/config/rollback` (design §3): re-validates `<path>.prev`
/// before touching any file, then swaps it back in as the live config.
#[utoipa::path(
    post,
    path = "/v1/config/rollback",
    tag = "config",
    summary = "Roll back to the previous config",
    description = "Re-validates the single-revision `.prev` backup before touching any file; on success, swaps it back in as the live config (current becomes the new `.prev`) and applies it.",
    responses(
        (status = 200, description = "Rolled back and applied", body = ConfigApplyOk),
        (status = 404, description = "No previous config to roll back to", body = ConfigRollbackNotFound),
        (status = 409, description = "The previous config no longer validates (e.g. an env-resolved secret reference drifted); nothing was touched", body = ConfigRollbackConflict),
        (status = 500, description = "Reading or swapping the config files failed", body = ConfigWriteError),
    ),
)]
async fn config_rollback(State(state): State<AdminState>) -> impl IntoResponse {
    let prev_path = prev_path_for(&state.config_path);
    let _write_guard = state.write_lock.lock().unwrap();
    if !prev_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no previous config to roll back to"})),
        );
    }
    let prev_text = match std::fs::read_to_string(&prev_path) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("failed to read previous config: {e}")})),
            );
        }
    };
    let new_cfg = match crate::config::load_from_str(&prev_text) {
        Ok(cfg) => cfg,
        Err(e) => return (StatusCode::CONFLICT, Json(json!({"errors": [e]}))),
    };
    if let Err(e) = swap_with_prev(&state.config_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to swap config files: {e}")})),
        );
    }
    let outcome = state.daemon.apply_config(new_cfg);
    (
        StatusCode::OK,
        Json(json!({"applied": true, "restart_required": outcome.restart_required})),
    )
}

/// Query params for `GET /v1/queue` (Finding 2, whole-branch review). Both
/// optional: `state` absent keeps the endpoint's original aggregate-counts
/// shape (compat -- the listing below only activates when it's present);
/// `limit` defaults to 100 and is clamped to [1, 1000] regardless of what's
/// requested, including 0 or an absurdly large value.
#[derive(Deserialize)]
struct QueueParams {
    state: Option<String>,
    limit: Option<usize>,
}

/// `GET /v1/queue` (design §Admin API) / `GET /v1/queue?state=<state>&limit=<n>`
/// (Finding 2, whole-branch review, goal gate). Without `state`, returns the
/// existing `{route: count}`-shaped aggregate UNCHANGED (every pre-existing
/// caller -- `/v1/status`'s own `queue_map` call, `switchyardctl` -- keeps
/// working). With `state`, returns a listing of individual delivery rows in
/// that state instead: `{deliveries: [...]}`, newest first, capped at
/// `limit`. spec §Security invariants: masked per the SAME rule `trace`
/// (`GET /v1/messages/{id}`) uses -- an `@identity`-route row's destination
/// carries the target's RAW native ref (see `enqueue_identity_send`), so it
/// renders in the masked "protocol:masked_ref" compound form; an ordinary
/// route's destination is a route endpoint, not an identity ref, and renders
/// in full. No message body ever appears here (`list_deliveries`'s `SELECT`
/// never even touches `messages.envelope`).
/// One row of `GET /v1/queue?state=...`'s listing shape, DOCUMENTATION ONLY
/// (Task 1: `queue()` below returns one of TWO distinct shapes depending on
/// whether `?state=` is present -- an aggregate `{route: count}` map
/// (default, unchanged since before this task) or this listing -- which
/// doesn't fit a single promoted return type without either changing the
/// wire shape or introducing a runtime-unused enum discriminant; documented
/// via two schemas + prose instead, handler unchanged). `destination` is
/// pre-masked (same "protocol:masked_ref" rule `trace`'s deliveries use for
/// `@identity`-route rows).
#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct QueueDeliveryItemDoc {
    attempts: u32,
    created_at: DateTime<Utc>,
    destination: String,
    message_id: Uuid,
    reason: Option<String>,
    route: String,
    state: String,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct QueueListingDoc {
    deliveries: Vec<QueueDeliveryItemDoc>,
}

/// `GET /v1/queue` / `GET /v1/queue?state=<state>&limit=<n>` (design §Admin
/// API, Finding 2 whole-branch review): without `state`, the pre-existing
/// `{route: count}` aggregate (unchanged, e.g. `switchyardctl`'s own
/// caller); with `state`, a listing of individual delivery rows in that
/// state, newest first, capped at `limit` (default 100, clamped to
/// [1, 1000]).
#[utoipa::path(
    get,
    path = "/v1/queue",
    tag = "status",
    summary = "Queue counts, or a delivery listing when ?state= is given",
    description = "Without `state`: `{route: count}` aggregate counts across every delivery state (the original, still-default shape). With `?state=<state>[&limit=<n>]`: `{\"deliveries\": [...]}`, individual rows in that state, newest first, `limit` clamped to [1, 1000] (default 100).",
    params(
        ("state" = Option<String>, Query, description = "Filter to this delivery state (e.g. dead_letter); switches the response to the listing shape"),
        ("limit" = Option<usize>, Query, description = "Max rows to return when `state` is given; clamped to [1, 1000], default 100"),
    ),
    responses(
        (status = 200, description = "Aggregate counts (default) or a masked delivery listing (with ?state=)", body = QueueListingDoc),
    ),
)]
async fn queue(
    State(d): State<Arc<Daemon>>,
    Query(params): Query<QueueParams>,
) -> impl IntoResponse {
    let Some(state) = params.state else {
        return Json(queue_map(&d)).into_response();
    };
    let limit = params.limit.unwrap_or(100).clamp(1, 1000) as i64;
    let deliveries = match d.store.lock().unwrap().list_deliveries(Some(&state), limit) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let out: Vec<_> = deliveries
        .iter()
        .map(|del| {
            let destination = if del.route == IDENTITY_ROUTE {
                format!(
                    "{}:{}",
                    del.destination.protocol,
                    identity_links::mask_ref(&del.destination.endpoint)
                )
            } else {
                del.destination.to_string()
            };
            json!({
                "message_id": del.message_id,
                "route": del.route,
                "destination": destination,
                "state": del.state,
                "reason": del.reason,
                "attempts": del.attempt_count,
                "created_at": del.created_at,
                "updated_at": del.updated_at,
            })
        })
        .collect();
    Json(json!({ "deliveries": out })).into_response()
}

/// `GET /v1/messages/{id}` response shape, DOCUMENTATION ONLY (Task 1: not
/// in the brief's named promote-list; kept doc-only alongside the other
/// small ad-hoc admin shapes rather than wired in, to keep this change's
/// runtime surface limited to the explicitly-called-out handlers).
/// `destination` is pre-masked per the same rule `queue`'s listing uses.
#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct TraceDeliveryItemDoc {
    attempts: u32,
    destination: String,
    expires_at: DateTime<Utc>,
    next_attempt: DateTime<Utc>,
    priority: u8,
    reason: Option<String>,
    route: String,
    state: String,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct TraceResponseDoc {
    body_bytes: usize,
    created_at: DateTime<Utc>,
    deliveries: Vec<TraceDeliveryItemDoc>,
    expires_at: DateTime<Utc>,
    id: Uuid,
    kind: String,
    received_at: DateTime<Utc>,
    source: String,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct TraceNotFound {
    error: String,
}

/// `GET /v1/messages/{id}` (design §90): delivery trace for one message --
/// per-delivery state/route/priority/attempts, body summarized as a byte
/// count only, never included.
#[utoipa::path(
    get,
    path = "/v1/messages/{id}",
    tag = "status",
    summary = "Delivery trace for one message",
    description = "Per-delivery state/route/priority/attempts for a message, plus envelope metadata. The message body is never included, only its byte length.",
    params(
        ("id" = Uuid, Path, description = "Message id"),
    ),
    responses(
        (status = 200, description = "Message trace", body = TraceResponseDoc),
        (status = 404, description = "Unknown message id", body = TraceNotFound),
    ),
)]
async fn trace(State(d): State<Arc<Daemon>>, AxPath(id): AxPath<Uuid>) -> impl IntoResponse {
    let store = d.store.lock().unwrap();
    let Ok(Some(env)) = store.get_message(id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown message"})),
        )
            .into_response();
    };
    // spec §Security invariants: refs masked in every API response, full
    // refs never in GET responses. Ordinary routes' `destination` is a route
    // endpoint (e.g. "mockb:chan"), not an identity ref, so it renders in
    // full as before; `@identity` deliveries carry the target's RAW native
    // ref verbatim in `dest_endpoint` (see `enqueue_identity_send`), so those
    // must use the same masked "protocol:masked_ref" compound form (RULING
    // 2) as `/v1/identities` and `/v1/identities/challenges`.
    let del_rows = match store.deliveries_for(id) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let deliveries: Vec<_> = del_rows
        .iter()
        .map(|del| {
            let destination = if del.route == IDENTITY_ROUTE {
                format!(
                    "{}:{}",
                    del.destination.protocol,
                    identity_links::mask_ref(&del.destination.endpoint)
                )
            } else {
                del.destination.to_string()
            };
            json!({
                "route": del.route,
                "destination": destination,
                "priority": del.priority,
                "state": del.state,
                "attempts": del.attempt_count,
                "reason": del.reason,
                "next_attempt": del.next_attempt,
                "expires_at": del.expires_at,
            })
        })
        .collect();
    // spec §90: trace without content — body is summarized, never included
    (
        StatusCode::OK,
        Json(json!({
            "id": env.id,
            "source": env.source.to_string(),
            "kind": env.kind,
            "created_at": env.created_at,
            "received_at": env.received_at,
            "expires_at": env.expires_at,
            "body_bytes": env.body.len(),
            "deliveries": deliveries,
        })),
    )
        .into_response()
}

/// `GET /metrics` (Prometheus text exposition format, not JSON): counters
/// `relayfabric_messages_ingress_total`, `relayfabric_messages_egress_total`,
/// `relayfabric_messages_dropped_total`, `relayfabric_duplicate_messages_total`,
/// `relayfabric_policy_denials_total`, `relayfabric_ratelimited_total`,
/// `relayfabric_queue_rejected_total`, `relayfabric_budget_deferred_total`,
/// `relayfabric_links_verified_total`, `relayfabric_federation_ingress_total`,
/// `relayfabric_federation_egress_total`, `relayfabric_federation_rejected_total`,
/// `relayfabric_advert_rx_total`, `relayfabric_advert_tx_total`,
/// `relayfabric_advert_rejected_total`; gauges `relayfabric_queue_depth{state}`,
/// `relayfabric_plugin_up{plugin}`, `relayfabric_federation_peer_up{peer}`,
/// `relayfabric_plugin_gauge{plugin,name}`; summary
/// `relayfabric_delivery_latency_seconds` (`_sum`/`_count`); and per-route
/// counter `relayfabric_route_messages_total{route}`.
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "status",
    summary = "Prometheus metrics",
    description = "Prometheus text exposition format (not JSON). Counters: relayfabric_messages_ingress_total, relayfabric_messages_egress_total, relayfabric_messages_dropped_total, relayfabric_duplicate_messages_total, relayfabric_policy_denials_total, relayfabric_ratelimited_total, relayfabric_queue_rejected_total, relayfabric_budget_deferred_total, relayfabric_links_verified_total, relayfabric_federation_ingress_total, relayfabric_federation_egress_total, relayfabric_federation_rejected_total, relayfabric_advert_rx_total, relayfabric_advert_tx_total, relayfabric_advert_rejected_total. Gauges: relayfabric_queue_depth{state}, relayfabric_plugin_up{plugin}, relayfabric_federation_peer_up{peer}, relayfabric_plugin_gauge{plugin,name}. Summary: relayfabric_delivery_latency_seconds (_sum/_count). Per-route counter: relayfabric_route_messages_total{route}.",
    responses(
        (status = 200, description = "Prometheus exposition text", content_type = "text/plain", body = String),
    ),
)]
async fn metrics_text(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let q = d.store.lock().unwrap().queue_counts().unwrap_or_default();
    metrics::render(&q, &plugin_state(&d), &d.gauges)
}

/// `GET /v1/identities` (design §Admin API / webui-notes): masked refs in
/// every response — protocol stays visible, only the ref is masked
/// (RULING 2's compound convention), full refs never leave this module.
/// `GET /v1/identities` response family (Task 1: promoted from ad-hoc
/// `json!`). Field order alphabetical -- see `StatusResponse`'s doc comment
/// for why. `a`/`b` are the masked "protocol:masked_ref" compound form
/// (RULING 2), never a raw native ref.
#[derive(Serialize, ToSchema)]
struct LinkItem {
    a: String,
    b: String,
    display_name: String,
    id: i64,
    verified_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
struct IdentitiesResponse {
    links: Vec<LinkItem>,
}

/// `GET /v1/identities` (design §Admin API / webui-notes): verified
/// identity links, refs masked.
#[utoipa::path(
    get,
    path = "/v1/identities",
    tag = "identities",
    summary = "Verified identity links",
    description = "Every verified identity link, with both sides' refs masked (protocol stays visible, only the ref is masked). Full refs never leave this endpoint.",
    responses(
        (status = 200, description = "Verified identity links", body = IdentitiesResponse),
    ),
)]
async fn identities(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let links = match d.store.lock().unwrap().list_links() {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let out: Vec<_> = links
        .iter()
        .map(|l| LinkItem {
            a: format!("{}:{}", l.a_protocol, identity_links::mask_ref(&l.a_ref)),
            b: format!("{}:{}", l.b_protocol, identity_links::mask_ref(&l.b_ref)),
            display_name: l.display_name.clone(),
            id: l.id,
            verified_at: l.verified_at,
        })
        .collect();
    Json(IdentitiesResponse { links: out }).into_response()
}

#[derive(Deserialize, ToSchema)]
struct LinkRequest {
    /// "protocol:ref" of the party requesting the link.
    requester: String,
    /// "protocol:ref" of the link target.
    target: String,
    display_name: String,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct CreateLinkAccepted {
    challenge_id: i64,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct CreateLinkError {
    error: String,
}

/// `POST /v1/identities/link` (design §Admin API): 202 with a challenge id
/// on success; 400 on a malformed body or an unparsable "proto:ref"; 409 on
/// `engine::initiate_link`'s rejection — either the target plugin isn't
/// direct-capable (naming which connected plugins are) or the global queue
/// is full (RULING 1). Parsing is done by hand against raw `Bytes` rather
/// than axum's `Json` extractor so every parse failure maps to exactly 400,
/// not axum's default 415 (bad content-type) / 422 (well-formed JSON, wrong
/// shape) split.
/// `POST /v1/identities/link` (design §Admin API): 202 with a challenge id
/// on success; 400 on a malformed body or an unparsable "proto:ref"; 409 if
/// the target plugin isn't direct-capable or the global queue is full.
#[utoipa::path(
    post,
    path = "/v1/identities/link",
    tag = "identities",
    summary = "Request an identity link",
    description = "Initiates an identity link between requester and target, sending a verification challenge to the target. 400 on a malformed body or an unparsable \"proto:ref\" endpoint string; 409 if the target plugin isn't direct-message-capable or the global queue is full.",
    request_body(content = LinkRequest, content_type = "application/json"),
    responses(
        (status = 202, description = "Challenge sent", body = CreateLinkAccepted),
        (status = 400, description = "Malformed body or unparsable endpoint", body = CreateLinkError),
        (status = 409, description = "Target not direct-capable, or global queue full", body = CreateLinkError),
    ),
)]
async fn create_link(State(d): State<Arc<Daemon>>, body: Bytes) -> impl IntoResponse {
    let req: LinkRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid request body: {e}")})),
            );
        }
    };
    let requester: Endpoint = match req.requester.parse() {
        Ok(e) => e,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))),
    };
    let target: Endpoint = match req.target.parse() {
        Ok(e) => e,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({"error": e}))),
    };
    match engine::initiate_link(&d, requester, target, &req.display_name) {
        Ok(challenge_id) => (
            StatusCode::ACCEPTED,
            Json(json!({"challenge_id": challenge_id})),
        ),
        Err(e) => (StatusCode::CONFLICT, Json(json!({"error": e}))),
    }
}

/// `DELETE /v1/identities/link/{id}` (design §Admin API / §22): 204 on
/// success, 404 if no such link. §95's "unlink reverts aliases to
/// pseudonyms immediately" regression is exercised at the rendering layer in
/// engine.rs (rendering reads links live) — this endpoint just removes the
/// row.
/// `DELETE /v1/identities/link/{id}` (design §Admin API / §22): 204 on
/// success, 404 if no such link.
#[utoipa::path(
    delete,
    path = "/v1/identities/link/{id}",
    tag = "identities",
    summary = "Remove an identity link",
    description = "Removes an identity link by id. Aliases on the affected route revert to pseudonyms immediately.",
    params(
        ("id" = i64, Path, description = "Link id"),
    ),
    responses(
        (status = 204, description = "Link removed"),
        (status = 404, description = "No such link"),
    ),
)]
async fn delete_link(State(d): State<Arc<Daemon>>, AxPath(id): AxPath<i64>) -> impl IntoResponse {
    // A storage error must be a 500, not a 404: 404 means "no such link",
    // which would tell the caller the delete succeeded/was unnecessary when it
    // actually failed (audit: fail-quiet control plane).
    match d.store.lock().unwrap().delete_link(id) {
        Ok(true) => StatusCode::NO_CONTENT,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(e) => {
            warn!(error = %e, id, "failed to delete identity link");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// `GET /v1/identities/challenges` (design §Admin API): pending count plus
/// masked targets and expiry — codes never leave `storage::Challenge`
/// (design §Security invariants); this handler never reads the `code`
/// field.
/// `GET /v1/identities/challenges` response family (Task 1: promoted from
/// ad-hoc `json!`). Field order alphabetical -- see `StatusResponse`'s doc
/// comment for why. `code` never appears -- see `storage::Challenge`.
#[derive(Serialize, ToSchema)]
struct ChallengeItem {
    expires_at: DateTime<Utc>,
    id: i64,
    target: String,
}

#[derive(Serialize, ToSchema)]
struct ChallengesResponse {
    challenges: Vec<ChallengeItem>,
    pending_count: usize,
}

/// `GET /v1/identities/challenges` (design §Admin API): pending identity
/// link challenges -- masked target and expiry only, codes never exposed.
#[utoipa::path(
    get,
    path = "/v1/identities/challenges",
    tag = "identities",
    summary = "Pending identity link challenges",
    description = "Pending (unexpired) identity link challenges: masked target ref and expiry. The verification code itself is never exposed by any API response.",
    responses(
        (status = 200, description = "Pending challenges", body = ChallengesResponse),
    ),
)]
async fn challenges(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let now = Utc::now();
    let list = match d.store.lock().unwrap().list_challenges(now) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let out: Vec<_> = list
        .iter()
        .map(|c| ChallengeItem {
            expires_at: c.expires_at,
            id: c.id,
            target: format!(
                "{}:{}",
                c.target_protocol,
                identity_links::mask_ref(&c.target_ref)
            ),
        })
        .collect();
    Json(ChallengesResponse {
        pending_count: out.len(),
        challenges: out,
    })
    .into_response()
}

/// `GET /v1/federation` (design §6, Task 5): every configured
/// `federation.peers[]` entry PLUS any trust-store node not covered by one
/// ("inbound-only seen": a node that has completed a Noise handshake with
/// this daemon but has no `peers[]` entry -- `name: null`), each with its
/// live `connected` state and a `last_seen` timestamp. Deliberately omits
/// `addr` (peer config's dial address) -- addresses are infrastructure, not
/// admin-surface data (§111.4 spirit; same posture as never surfacing
/// native refs). Federation entirely off (`d.fed` is `None`, i.e. no
/// `federation:` config block) reports an empty list rather than 404 --
/// consistent with `public()`'s "disabled reports zero services" precedent
/// below, not an error condition.
/// `GET /v1/federation` response family (Task 1: promoted from ad-hoc
/// `json!`). Field order alphabetical -- see `StatusResponse`'s doc comment
/// for why.
#[derive(Serialize, ToSchema)]
struct FederationPeerItem {
    connected: bool,
    last_seen: Option<DateTime<Utc>>,
    /// The configured peer name, or `null` for an "inbound-only seen" node
    /// (a completed Noise handshake with no `peers[]` entry).
    name: Option<String>,
    node_id: String,
    trust: String,
}

#[derive(Serialize, ToSchema)]
struct FederationResponse {
    peers: Vec<FederationPeerItem>,
}

/// `GET /v1/federation` (design §6, Task 5): every configured
/// `federation.peers[]` entry plus any trust-store node not covered by one,
/// each with its live connected state and last-seen timestamp. Federation
/// entirely off reports an empty list, not 404.
#[utoipa::path(
    get,
    path = "/v1/federation",
    tag = "federation",
    summary = "Federation peers",
    description = "Every configured federation peer, plus any trust-store node with no peers[] entry (\"inbound-only seen\"), with live connected state and last_seen. Deliberately omits dial addresses. Reports an empty list (not 404) when federation is off.",
    responses(
        (status = 200, description = "Federation peers", body = FederationResponse),
    ),
)]
async fn federation(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let Some(fed) = &d.fed else {
        return Json(FederationResponse { peers: Vec::new() }).into_response();
    };
    let configured: Vec<crate::config::PeerConfig> = d.cfg_snapshot(|c| {
        c.federation
            .as_ref()
            .map(|f| f.peers.clone())
            .unwrap_or_default()
    });
    let trust_rows = match d.store.lock().unwrap().list_trust() {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let conns = fed.conns.lock().unwrap();
    // Keyed by node_id, not `FedState.conns`'s own map key (a configured
    // peer's NAME, or an unconfigured connection's raw node_id -- see
    // `fed::conn::accept_loop_with_cap`'s `configured_peer_name` fallback):
    // reading `PeerConn.node_id` directly here makes the lookup below
    // uniform for both configured and inbound-only entries, with no need to
    // guess which key shape a given `conns` entry uses.
    let live: BTreeMap<&str, &PeerConn> = conns.values().map(|c| (c.node_id.as_str(), c)).collect();

    let mut named: BTreeSet<&str> = BTreeSet::new();
    let mut peers_out: Vec<FederationPeerItem> = Vec::new();
    for p in &configured {
        named.insert(p.node_id.as_str());
        peers_out.push(federation_peer_item(
            Some(p.name.as_str()),
            &p.node_id,
            &trust_rows,
            live.get(p.node_id.as_str()).copied(),
        ));
    }
    for row in &trust_rows {
        let node_id = row.0.as_str();
        if named.contains(node_id) {
            continue; // already listed above, under its configured name
        }
        peers_out.push(federation_peer_item(
            None,
            node_id,
            &trust_rows,
            live.get(node_id).copied(),
        ));
    }
    drop(conns);
    Json(FederationResponse { peers: peers_out }).into_response()
}

/// One `GET /v1/federation` peer entry. `last_seen` (Task 5 choice,
/// documented here since the design leaves it open): a currently-connected
/// peer reports its live connection's `connected_at` (more precise than the
/// trust store, which only advances `updated_at` on a fresh handshake, not
/// per-frame); otherwise it falls back to the trust store's `updated_at` --
/// the best record this daemon has of when it last actually saw the node.
/// `trust` similarly falls back to `"unknown"` for the (should-not-happen
/// in practice, since boot-time seeding covers every configured peer)
/// case of a configured peer absent from the trust store entirely.
fn federation_peer_item(
    name: Option<&str>,
    node_id: &str,
    trust_rows: &[crate::storage::TrustRow],
    conn: Option<&PeerConn>,
) -> FederationPeerItem {
    let row = trust_rows.iter().find(|row| row.0 == node_id);
    let trust = row.map(|r| r.1.as_str()).unwrap_or("unknown");
    let last_seen = conn.map(|c| c.connected_at).or_else(|| row.map(|r| r.3));
    FederationPeerItem {
        connected: conn.is_some(),
        last_seen,
        name: name.map(String::from),
        node_id: node_id.to_string(),
        trust: trust.to_string(),
    }
}

/// `GET /v1/discovery` (design §6, Task 3): this node's own advert -- built
/// fresh and signed from the live config snapshot via
/// `fed::conn::build_signed_advert`, the EXACT function the real fed wire
/// exchange calls on connection-up/refresh, so this surface can never show
/// an advert different from what peers actually receive -- `null` when
/// discovery is off (that function's own `mode == "disabled"` check).
/// `mode` echoes `cfg.discovery.mode` verbatim (`Config::discovery` always
/// has a value via its `#[serde(default)]`, so there's no separate
/// "block absent" state to report).
///
/// `peers` is every stored, unexpired advert (`Store::list_peer_adverts`),
/// each RE-VERIFIED against its own signature here (design §3's "verify on
/// serve" invariant) rather than trusted just because it's in the table --
/// defense against direct DB tampering, independent of the receive-path
/// verification `fed::conn::receive_advert` already performed once before
/// the row was ever written. `advert::verify` only proves an advert is
/// SELF-consistent (its `sig` matches its OWN embedded `node_id`); it says
/// nothing about whether that embedded `node_id` equals the `peer_adverts`
/// ROW KEY the record came back under, so this ALSO requires
/// `peer_advert.node_id == node_id` (the row key) -- fix round 1 (review
/// finding): without this, a DB-write-capable attacker with no victim
/// private key could insert a row keyed to a victim's `node_id` whose
/// `advert_cbor` is validly self-signed under the attacker's OWN keypair,
/// and `advert::verify` alone would pass it straight through as that
/// victim. This is the exact same binding the receive path enforces
/// (`fed::conn::receive_advert`'s `advert.node_id != peer_node_id` check)
/// re-checked here for the same "trust nothing not re-derived from the row
/// itself" reason. A row whose `advert_cbor` fails to decode, decodes but
/// fails `advert::verify`, or decodes+verifies but carries a DIFFERENT
/// embedded `node_id` than its row key, is DROPPED from the response
/// (never served half-trusted, and never served under either node_id) with
/// one warn -- and deliberately left in storage, not deleted: this is a
/// read path, and the hourly `purge_expired_adverts` sweep remains the
/// only thing that ever removes a `peer_adverts` row.
///
/// `name` is served from the FRESHLY-DECODED advert, re-sanitized via
/// `fed::conn::sanitize_advert_name` -- NEVER the raw decoded `.name`.
/// `advert_cbor` stores a fresh CBOR re-encode of the peer's verified
/// advert, not its literal wire bytes (`Store::upsert_peer_advert`'s
/// contract -- correction, final-review finding: it is a re-encode of the
/// verified struct, re-verifiable because the signature covers
/// `canonical_bytes`, not this CBOR encoding) -- but the re-encode
/// preserves every field's VALUE unchanged, so decoding it here still
/// recovers whatever raw name the peer originally sent, control
/// characters and all; re-sanitizing before it ever reaches this response
/// is the entire reason that function is `pub(crate)` rather than
/// private.
/// `GET /v1/discovery` response shape, DOCUMENTATION ONLY (Task 1: not
/// wired into `discovery()` below -- `our_advert` reuses the full
/// `fed::advert::Advert` shape while `peers[]` entries are a bespoke
/// reshaping of it (adds `received_at`, omits `sig`/`rf_version`), so no
/// single promoted type covers both without either duplicating fields or
/// misdescribing one of the two; doc-only mirrors instead, handler
/// unchanged). `protocols`/`security` mirror `fed::advert::{ProtoCaps,
/// SecurityCaps}` -- free-form here rather than `$ref`ing those types,
/// since doing so would require deriving `ToSchema` on `fed::advert` types
/// this task doesn't otherwise touch.
#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct DiscoveryAdvertDoc {
    expires: i64,
    name: String,
    node_id: String,
    protocols: serde_json::Value,
    rf_version: u32,
    security: serde_json::Value,
    services: BTreeMap<String, bool>,
    sig: Vec<u8>,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct DiscoveryPeerItemDoc {
    expires: i64,
    name: String,
    node_id: String,
    protocols: serde_json::Value,
    received_at: DateTime<Utc>,
    security: serde_json::Value,
    services: BTreeMap<String, bool>,
}

#[derive(Serialize, ToSchema)]
#[allow(dead_code)]
struct DiscoveryResponseDoc {
    mode: String,
    /// This node's own advert, freshly built and signed; `null` when
    /// discovery is off.
    our_advert: Option<DiscoveryAdvertDoc>,
    /// Every stored, unexpired peer advert, re-verified against its own
    /// signature (and against the row it's keyed under) on every request.
    peers: Vec<DiscoveryPeerItemDoc>,
}

/// `GET /v1/discovery` (design §6, Task 3): this node's own RFDP advert
/// (freshly built/signed from the live config, `null` when discovery is
/// off) plus every stored, unexpired peer advert, each re-verified on
/// serve.
#[utoipa::path(
    get,
    path = "/v1/discovery",
    tag = "federation",
    summary = "RFDP discovery: this node's advert and known peer adverts",
    description = "This node's own advert (built fresh from the live config on every request, null when discovery is off) plus every stored, unexpired peer advert. Each peer advert is re-verified against its own signature AND against the row key it's stored under before being served -- a row that fails either check is silently dropped, never served half-trusted.",
    responses(
        (status = 200, description = "This node's advert and known peer adverts", body = DiscoveryResponseDoc),
    ),
)]
async fn discovery(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let mode = d.cfg_snapshot(|c| c.discovery.mode.clone());
    let our_advert = crate::fed::conn::build_signed_advert(&d);

    let now = Utc::now();
    let rows = match d.store.lock().unwrap().list_peer_adverts(now) {
        Ok(v) => v,
        Err(e) => return storage_error(e),
    };
    let mut peers: Vec<serde_json::Value> = Vec::new();
    for (node_id, advert_cbor, received_at) in rows {
        let decoded: Option<Advert> = ciborium::from_reader(advert_cbor.as_slice()).ok();
        match decoded {
            // Fix round 1 (review Important finding): `advert::verify` only
            // proves the advert is SELF-consistent -- its `sig` matches its
            // OWN embedded `node_id`. It says nothing about whether that
            // embedded `node_id` matches the `peer_adverts` ROW KEY this
            // record was stored/looked-up under. Without this third check,
            // a DB-write-capable attacker (no victim private key needed)
            // could insert a row keyed `node_id: "rf:<victim>"` whose
            // `advert_cbor` is validly self-signed under the ATTACKER's own
            // keypair (embedded `node_id: "rf:<attacker>"`) -- `verify()`
            // passes, and without this check the response would serve
            // `node_id: "rf:<victim>"` with attacker-chosen name/services: a
            // full identity spoof of a trusted node. The receive path
            // already enforces this exact binding (`fed/conn.rs`'s
            // `advert.node_id != peer_node_id` check in `receive_advert`);
            // this is that same invariant, re-checked here because the
            // whole point of "verify on serve" is to trust nothing about a
            // stored row that isn't re-derived from the row itself.
            // Serving `peer_advert.node_id` instead (the attacker's REAL
            // id) would still surface an attacker-injected row, just under
            // a non-spoofed key -- dropping the row entirely is correct.
            Some(peer_advert)
                if advert::verify(&peer_advert).is_ok() && peer_advert.node_id == node_id =>
            {
                peers.push(json!({
                    "node_id": node_id,
                    "name": crate::fed::conn::sanitize_advert_name(&peer_advert.name),
                    "services": peer_advert.services,
                    "protocols": peer_advert.protocols,
                    "security": peer_advert.security,
                    "expires": peer_advert.expires,
                    "received_at": received_at,
                }));
            }
            _ => {
                warn!(node_id = %crate::fed::short_node_id(&node_id),
                    "stored peer advert failed re-verification on serve (tampered, corrupt, or \
                     row-key/embedded-node_id mismatch); dropped from GET /v1/discovery");
            }
        }
    }

    Json(json!({ "mode": mode, "our_advert": our_advert, "peers": peers })).into_response()
}

/// Builds the `GET /v1/events` (design §4) SSE stream from a live broadcast
/// receiver: `BroadcastStream` turns `Daemon.events.subscribe()` into a
/// `Stream`, and `filter_map` both (a) converts each successful item into an
/// SSE `Event` (`event:` = `event_name()`, `data:` = JSON) and (b) is what
/// implements "lagged receivers skip missed events and continue" -- a
/// `BroadcastStreamRecvError::Lagged` maps to `None`, which `filter_map`'s
/// own `poll_next` loop (tokio_stream's implementation, not something this
/// function has to drive itself) treats as "not an item, poll the inner
/// stream again," never as end-of-stream. Split out from the handler below
/// so it's unit-testable directly against a hand-built
/// `broadcast::channel`, without going through axum/tower at all (see the
/// `lagged_receiver_is_skipped_not_fatal` test).
fn events_stream_from(
    rx: broadcast::Receiver<Event>,
) -> impl Stream<Item = Result<SseEvent, Infallible>> {
    BroadcastStream::new(rx).filter_map(|item| {
        item.ok().map(|event| {
            Ok(SseEvent::default()
                .event(event.event_name())
                .data(serde_json::to_string(&event).unwrap_or_default()))
        })
    })
}

/// `GET /v1/events` (design §4): a live SSE feed of `Daemon.events`
/// (`tokio::sync::broadcast`, capacity 256; see `events_stream_from`).
/// `KeepAlive` (per-connection periodic `: comment` frames) keeps an
/// otherwise silent long-lived connection from looking dead to an
/// intermediary. SSE here is advisory -- the REST surface underneath
/// remains the source of truth (design §4) -- so a lagged/slow subscriber
/// simply misses events rather than the daemon buffering for it.
/// `GET /v1/events` (design §4): a live Server-Sent Events feed, NOT a
/// request/response JSON endpoint -- documented as `text/event-stream`
/// with the seven event types' payload shapes described here rather than a
/// fabricated JSON response body. Each SSE frame's `event:` field is one of
/// `ingress | delivery | plugin | link_verified | config_applied | \
/// federation | advert`; `data:` is that event's JSON payload (untagged,
/// flat -- no variant-name wrapper). Advisory only: the REST surface above
/// remains the source of truth, and a lagged/slow subscriber simply misses
/// events rather than the daemon buffering for it.
///
/// - `ingress {id, protocol, sender_masked, routes[], ts}` -- a message was
///   accepted and fanned out.
/// - `delivery {id, route, state, ts}` -- a delivery attempt reached a
///   terminal state or was scheduled for retry; `state` is one of
///   `delivered | failed | dead_letter | retry | expired`.
/// - `plugin {name, up, ts}` -- a plugin connected or disconnected.
/// - `link_verified {link_id, ts}` -- an identity-link challenge was
///   confirmed; carries only the opaque link id, nothing else.
/// - `config_applied {restart_required[], ts}` -- a config change was
///   applied (via `PUT /v1/config` or `POST /v1/config/rollback`).
/// - `federation {peer, up, ts}` -- a federation connection came up or
///   went down; `peer` is the configured name or a shortened node_id.
/// - `advert {node_id, name, ts}` -- a peer advertisement was verified and
///   upserted; `name` is sanitized for display.
///
/// PRIVACY: no message bodies, no full native refs, no identity-link
/// challenge codes, no resolved secrets in any payload, ever.
#[utoipa::path(
    get,
    path = "/v1/events",
    tag = "status",
    summary = "Live event feed (Server-Sent Events)",
    description = "A live SSE feed of daemon events. `event:` is one of ingress|delivery|plugin|link_verified|config_applied|federation|advert; `data:` is that event's flat JSON payload. Advisory only -- the REST surface remains the source of truth. See the handler doc comment in admin.rs for each event type's exact fields.",
    responses(
        (status = 200, description = "SSE stream of the seven event types (see description)", content_type = "text/event-stream", body = String),
    ),
)]
async fn events_stream(
    State(d): State<Arc<Daemon>>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    Sse::new(events_stream_from(d.events.subscribe())).keep_alive(KeepAlive::default())
}

/// `GET /v1/openapi.json` (Task 1, design §1): the generated OpenAPI 3.1
/// document for this admin API, produced fresh from `ApiDoc::openapi()` on
/// every request (so it can never drift from the annotated handlers below
/// it -- there is no separate hand-maintained copy to go stale).
#[utoipa::path(
    get,
    path = "/v1/openapi.json",
    tag = "status",
    summary = "OpenAPI document for this admin API",
    description = "This admin API's own OpenAPI 3.1 document, generated from the handler annotations in this module.",
    responses(
        (status = 200, description = "OpenAPI 3.1 document", content_type = "application/json"),
    ),
)]
async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

// ---- GET /docs -- Swagger UI (Task 2, design §2) ---------------------

/// `utoipa-swagger-ui`'s Swagger UI config (Task 2, design §2): points at
/// the SAME `/v1/openapi.json` this daemon already serves, as a relative
/// path -- so it works over whatever transport reaches the admin socket
/// (direct unix-socket HTTP, a `socat`/SSH TCP forward, ...), never a
/// baked-in absolute host. `validator_url("none")` disables Swagger UI's
/// DEFAULT behavior of calling out to swagger.io's hosted spec validator
/// on load: the vendored dist assets (`utoipa-swagger-ui-vendored`,
/// MIT/Apache-2.0, embedded at compile time, see Cargo.toml) are already
/// fully self-contained, but that default config setting would still make
/// the *browser* place an external request the project's no-CDN posture
/// doesn't want.
fn swagger_config() -> Arc<utoipa_swagger_ui::Config<'static>> {
    Arc::new(utoipa_swagger_ui::Config::from("/v1/openapi.json").validator_url("none"))
}

/// Serves one file out of the vendored Swagger UI dist -- `path` is `""`
/// for the index page (`utoipa_swagger_ui::serve` maps that to
/// `index.html`) or the tail segment for an asset (`swagger-ui-bundle.js`,
/// `swagger-ui.css`, `favicon-32x32.png`, ...). Deliberately bypasses
/// `utoipa_swagger_ui`'s own axum `Router::from(SwaggerUi)` glue, which
/// 303-redirects a bare `/docs` (no trailing slash) to `/docs/` -- the
/// brief requires `GET /docs` itself to be a direct 200, not a redirect a
/// plain (non-following) HTTP client would have to chase.
fn serve_swagger_asset(path: &str) -> axum::response::Response {
    match utoipa_swagger_ui::serve(path, swagger_config()) {
        Ok(Some(file)) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, file.content_type)],
            file.bytes.into_owned(),
        )
            .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `GET /docs` and `GET /docs/` (Task 2, design §2): both serve the
/// Swagger UI index page directly (200), not one redirecting to the
/// other -- see `serve_swagger_asset`'s doc comment for why this doesn't
/// go through the crate's own router glue.
async fn docs_index() -> axum::response::Response {
    serve_swagger_asset("")
}

/// `GET /docs/{*rest}` (Task 2, design §2): the Swagger UI's own JS/CSS/
/// image assets, all same-origin under `/docs/`.
async fn docs_asset(AxPath(rest): AxPath<String>) -> axum::response::Response {
    serve_swagger_asset(&rest)
}

/// The generated OpenAPI document for the switchyardd admin API (Task 1,
/// design §1). `info.description` states the actual trust boundary: this
/// API is served over a Unix domain socket, gated by filesystem
/// permissions/same-UID access, not an HTTP auth scheme -- deliberately no
/// `securityScheme` is declared, since inventing one the daemon doesn't
/// implement would mislead client generators (design's "No auth scheme is
/// invented" ruling).
#[derive(OpenApi)]
#[openapi(
    info(
        title = "RelayFabric switchyardd Admin API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Admin/control API for a RelayFabric switchyardd node. \
            Trust boundary: served exclusively over a Unix domain socket \
            (default `admin.sock`), access controlled by filesystem \
            permissions -- any process running as the same UID (or in an \
            authorized group) as the daemon can reach it. There is no HTTP \
            authentication/authorization scheme at this layer (no bearer \
            token, no OAuth, no API key): callers are expected to reach \
            this socket only via a trusted local path (switchyardctl, a \
            reverse proxy fronting the socket, or an operator's own \
            tunnel). Do not expose this API over a network listener \
            without adding an auth layer in front of it.",
    ),
    paths(
        status, plugins, routes, config_yaml, config_prev, config_put, config_validate, config_rollback,
        queue, trace, public, limits, identities, create_link, delete_link, challenges,
        federation, discovery, events_stream, healthz, readyz, metrics_text, openapi_json,
    ),
    components(schemas(
        StatusResponse,
        HealthResponse,
        PublicResponse, PublicServiceItem,
        LimitsResponse, GlobalLimitsItem, PerRouteLimitsItem, PerSenderLimitsItem, TransportBudgetItem,
        PluginsResponseDoc, PluginEntryDoc, PluginGaugeItemDoc,
        RoutesResponse, RouteItem, RouteRenderItem,
        ConfigValidateOk, ConfigValidateError, ConfigApplyOk, ConfigWriteError,
        ConfigRollbackNotFound, ConfigRollbackConflict,
        QueueListingDoc, QueueDeliveryItemDoc,
        TraceResponseDoc, TraceDeliveryItemDoc, TraceNotFound,
        IdentitiesResponse, LinkItem,
        LinkRequest, CreateLinkAccepted, CreateLinkError,
        ChallengesResponse, ChallengeItem,
        FederationResponse, FederationPeerItem,
        DiscoveryResponseDoc, DiscoveryAdvertDoc, DiscoveryPeerItemDoc,
    )),
)]
struct ApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{handle_inbound, Daemon};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn cfg_with_plugins(yaml_plugins: &str) -> crate::config::Config {
        let raw =
            format!("node:\n  name: t\n  data_dir: /tmp/rf-admin-test\nplugins:\n{yaml_plugins}");
        crate::config::load_from_str(&raw).expect("test config must parse")
    }

    #[test]
    fn admin_config_write_rejects_introducing_or_changing_a_plugin_command() {
        // currently running: plugin "a" with a command, "b" with none
        let mut current = BTreeMap::new();
        current.insert("a".to_string(), Some("/bin/a".to_string()));
        current.insert("b".to_string(), None);

        // identical command for "a" is fine; a NEW command on "b" and a NEW
        // plugin "c" with a command are both rejected.
        let new = cfg_with_plugins(
            "  a:\n    enabled: true\n    command: /bin/a\n\
             \x20 b:\n    enabled: true\n    command: /bin/evil\n\
             \x20 c:\n    enabled: true\n    command: /bin/rce\n",
        );
        let rejected = rejected_command_changes(&current, &new);
        assert_eq!(rejected, vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn admin_config_write_allows_non_command_changes() {
        let mut current = BTreeMap::new();
        current.insert("a".to_string(), Some("/bin/a".to_string()));

        // same command, changed config only -> allowed; and a new plugin with
        // NO command (operator runs it themselves) -> allowed.
        let new = cfg_with_plugins(
            "  a:\n    enabled: false\n    command: /bin/a\n\
             \x20 d:\n    enabled: true\n",
        );
        assert!(rejected_command_changes(&current, &new).is_empty());
    }

    /// Shadows `super::router` (now `fn(Arc<Daemon>, PathBuf) -> Router`)
    /// for the pre-Task-3 call sites in this module, none of which exercise
    /// a config_path-reading endpoint — a path that's guaranteed not to
    /// exist is fine for them. Tests that DO exercise `PUT /v1/config` /
    /// `POST /v1/config/{validate,rollback}` call `super::router` directly
    /// with a real path from `daemon_with_config_file`.
    fn router(d: Arc<Daemon>) -> axum::Router {
        super::router(d, PathBuf::from("/nonexistent/relayfabric-admin-test.yaml"))
    }

    async fn get(router: axum::Router, path: &str) -> (u16, String) {
        let resp = router
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    /// Like `get`, but for the POST/DELETE identity-link endpoints: sets the
    /// method and (when a body is given) a `content-type: application/json`
    /// header, matching what the real ctl client sends.
    async fn req(
        router: axum::Router,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> (u16, String) {
        let mut builder = Request::builder().method(method).uri(path);
        let request_body = match body {
            Some(b) => {
                builder = builder.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let resp = router
            .oneshot(builder.body(request_body).unwrap())
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn daemon() -> Arc<Daemon> {
        // reuse the engine test constructor shape: two mock plugins + one route
        let dir = tempfile::tempdir().unwrap();
        let d = crate::engine::tests_support::test_daemon(dir.path());
        std::mem::forget(dir); // keep the tempdir alive for the test process
        Arc::new(d)
    }

    #[tokio::test]
    async fn status_reports_node_and_queue() {
        let d = daemon();
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            None,
            vec![],
            None,
        );
        let (code, body) = get(router(d), "/v1/status").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"node\":\"t\""));
        assert!(body.contains("\"node_id\":\"rf:"));
        assert!(body.contains("\"pending\":1"));
        assert!(body.contains("\"public\":false"), "status was: {body}");
    }

    fn daemon_with_public(
        public: bool,
        services: Vec<crate::config::PublicService>,
    ) -> Arc<Daemon> {
        let dir = tempfile::tempdir().unwrap();
        let d = crate::engine::tests_support::test_daemon_with_public(dir.path(), public, services);
        std::mem::forget(dir);
        Arc::new(d)
    }

    #[tokio::test]
    async fn status_reports_public_true_when_configured() {
        let d = daemon_with_public(true, vec![]);
        let (code, body) = get(router(d), "/v1/status").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"public\":true"), "status was: {body}");
    }

    #[tokio::test]
    async fn healthz_is_ok_and_readyz_is_ready_on_a_healthy_daemon() {
        let d = daemon_with_public(false, vec![]);
        let (hc, hb) = get(router(d.clone()), "/healthz").await;
        assert_eq!(hc, 200);
        assert!(hb.contains("\"status\":\"ok\""), "healthz body: {hb}");
        let (rc, rb) = get(router(d), "/readyz").await;
        assert_eq!(rc, 200);
        assert!(rb.contains("\"status\":\"ready\""), "readyz body: {rb}");
    }

    #[tokio::test]
    async fn public_endpoint_reports_disabled_and_no_services_by_default() {
        let d = daemon_with_public(false, vec![]);
        let (code, body) = get(router(d), "/v1/public").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"public\":false"), "body was: {body}");
        assert!(body.contains("\"services\":[]"), "body was: {body}");
    }

    #[tokio::test]
    async fn public_endpoint_reports_configured_services() {
        let d = daemon_with_public(
            true,
            vec![crate::config::PublicService {
                name: "regional-chat".into(),
                r#type: "chat".into(),
                ingress: vec!["mocka".into()],
                egress: vec!["mockb".into()],
            }],
        );
        let (code, body) = get(router(d), "/v1/public").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"public\":true"), "body was: {body}");
        assert!(
            body.contains("\"name\":\"regional-chat\""),
            "body was: {body}"
        );
        assert!(body.contains("\"type\":\"chat\""), "body was: {body}");
        assert!(body.contains("\"ingress\":[\"mocka\"]"), "body was: {body}");
        assert!(body.contains("\"egress\":[\"mockb\"]"), "body was: {body}");
    }

    #[tokio::test]
    async fn limits_endpoint_echoes_configured_limits() {
        let d = daemon();
        let (code, body) = get(router(d), "/v1/limits").await;
        assert_eq!(code, 200);
        // test_daemon's Config uses Limits::default() -- every field 0
        // (unlimited), which is the v0.1-compat default (see config.rs's
        // v0_1_style_config_parses_with_all_defaults).
        assert!(
            body.contains("\"messages_per_minute\":0"),
            "body was: {body}"
        );
        assert!(body.contains("\"bytes_per_hour\":0"), "body was: {body}");
        assert!(body.contains("\"queue_max\":0"), "body was: {body}");
        assert!(body.contains("\"cas_max_bytes\":0"), "body was: {body}");
        assert!(
            body.contains("\"transport_budgets\":{}"),
            "body was: {body}"
        );
    }

    #[tokio::test]
    async fn limits_endpoint_echoes_nonzero_limits_and_transport_budgets() {
        let dir = tempfile::tempdir().unwrap();
        let d = crate::engine::tests_support::test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                per_sender: crate::config::PerSender {
                    messages_per_minute: 10,
                    bytes_per_hour: 50_000,
                },
                per_route: crate::config::PerRoute { queue_max: 5_000 },
                global: crate::config::GlobalLimits {
                    queue_max: 50_000,
                    cas_max_bytes: 1_000_000_000,
                },
            },
        );
        std::mem::forget(dir);
        let (code, body) = get(router(Arc::new(d)), "/v1/limits").await;
        assert_eq!(code, 200);
        assert!(
            body.contains("\"messages_per_minute\":10"),
            "body was: {body}"
        );
        assert!(
            body.contains("\"bytes_per_hour\":50000"),
            "body was: {body}"
        );
        assert!(body.contains("\"queue_max\":5000"), "body was: {body}");
        assert!(body.contains("\"queue_max\":50000"), "body was: {body}");
        assert!(
            body.contains("\"cas_max_bytes\":1000000000"),
            "body was: {body}"
        );

        let dir2 = tempfile::tempdir().unwrap();
        let mut budgets = std::collections::BTreeMap::new();
        budgets.insert(
            "mockb".to_string(),
            crate::config::Budget {
                messages_per_minute: 30,
            },
        );
        let d2 = crate::engine::tests_support::test_daemon_with_budgets(dir2.path(), budgets);
        std::mem::forget(dir2);
        let (code, body) = get(router(Arc::new(d2)), "/v1/limits").await;
        assert_eq!(code, 200);
        assert!(
            body.contains("\"transport_budgets\":{\"mockb\":{\"messages_per_minute\":30}}"),
            "body was: {body}"
        );
    }

    #[tokio::test]
    async fn trace_omits_body_and_404s_unknown() {
        let d = daemon();
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "secret-content".into(),
            None,
            vec![],
            None,
        );
        let id = d
            .store
            .lock()
            .unwrap()
            .due_deliveries(chrono::Utc::now(), 1)
            .unwrap()[0]
            .message_id;
        let (code, body) = get(router(d.clone()), &format!("/v1/messages/{id}")).await;
        assert_eq!(code, 200);
        assert!(
            !body.contains("secret-content"),
            "trace leaked message body"
        );
        assert!(body.contains("\"deliveries\""));
        let (code, _) = get(router(d), &format!("/v1/messages/{}", uuid::Uuid::now_v7())).await;
        assert_eq!(code, 404);
    }

    /// Each delivery in a trace must carry its numeric priority rank (spec
    /// §46 scheduling), not just the state/route fields — a "high" priority
    /// message must show rank 1 (`relay_core::priority_rank`'s ordering),
    /// distinct from the default "normal" rank 2.
    #[tokio::test]
    async fn trace_deliveries_include_priority_rank() {
        let d = daemon();
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "urgent-ish".into(),
            None,
            vec![],
            Some("high".into()),
        );
        let id = d
            .store
            .lock()
            .unwrap()
            .due_deliveries(chrono::Utc::now(), 1)
            .unwrap()[0]
            .message_id;
        let (code, body) = get(router(d), &format!("/v1/messages/{id}")).await;
        assert_eq!(code, 200);
        assert!(body.contains("\"priority\":1"), "body was: {body}");
    }

    /// Finding 1 (whole-branch review, blocker): deliveries on the reserved
    /// `@identity` route carry the target's RAW native ref in
    /// `del.destination.endpoint` (`enqueue_identity_send` stores it verbatim
    /// so `process_due_identity`'s `SendDirect` has something to deliver to)
    /// — the trace handler must mask that ref with the same compound
    /// "protocol:masked_ref" convention used everywhere else (RULING 2)
    /// rather than rendering `del.destination.to_string()` unmasked. Ordinary
    /// routes are unaffected: their destination is a route endpoint, not an
    /// identity ref, and must keep rendering in full.
    #[tokio::test]
    async fn trace_masks_identity_route_destination_but_renders_ordinary_route_destination_in_full()
    {
        let d = daemon();
        let _rx = crate::engine::tests_support::register_direct_plugin(&d, "mockb");
        let requester: Endpoint = "mocka:!alice-secret".parse().unwrap();
        let target: Endpoint = "mockb:+14155551234".parse().unwrap();
        engine::initiate_link(&d, requester, target, "Jascha").unwrap();

        let identity_message_id = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(Utc::now(), 10)
                .unwrap()
                .into_iter()
                .find(|de| de.route == crate::config::IDENTITY_ROUTE)
                .expect("challenge delivery must be queued on the @identity route")
                .message_id
        };
        let (code, body) = get(
            router(d.clone()),
            &format!("/v1/messages/{identity_message_id}"),
        )
        .await;
        assert_eq!(code, 200);
        assert!(
            !body.contains("+14155551234"),
            "full target ref leaked in trace: {body}"
        );
        assert!(
            body.contains("\"destination\":\"mockb:+1****1234\""),
            "masked destination missing: {body}"
        );

        // an ordinary route's destination is a route endpoint, not an
        // identity ref, and must still render in full (existing behavior).
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            None,
            vec![],
            None,
        );
        let ordinary_message_id = d
            .store
            .lock()
            .unwrap()
            .due_deliveries(Utc::now(), 10)
            .unwrap()
            .into_iter()
            .find(|de| de.route != crate::config::IDENTITY_ROUTE)
            .expect("ordinary delivery must exist")
            .message_id;
        let (code2, body2) = get(router(d), &format!("/v1/messages/{ordinary_message_id}")).await;
        assert_eq!(code2, 200);
        assert!(
            body2.contains("\"destination\":\"mockb:chan\""),
            "ordinary route destination must still render in full: {body2}"
        );
    }

    /// Finding 2 (whole-branch review, goal gate): omitting `?state=` must
    /// keep returning the pre-existing `{route: count}` aggregate shape
    /// verbatim -- the listing behavior below is opt-in only, not a breaking
    /// change to the endpoint every caller already uses.
    #[tokio::test]
    async fn queue_without_state_param_returns_aggregate_counts_shape_unchanged() {
        let d = daemon();
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            None,
            vec![],
            None,
        );
        let (code, body) = get(router(d), "/v1/queue").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"pending\":1"), "body was: {body}");
        assert!(
            !body.contains("\"deliveries\""),
            "omitting ?state= must keep the pre-existing aggregate-counts shape: {body}"
        );
    }

    /// Finding 2 (whole-branch review, goal gate): `?state=dead_letter`
    /// lists individual rows -- masked per the SAME rule `trace` uses for an
    /// `@identity`-route destination, newest (highest id) first, no message
    /// body anywhere, and `limit` respected.
    #[tokio::test]
    async fn queue_by_state_lists_deliveries_masked_newest_first_with_limit_clamp() {
        let d = daemon();
        let _rx = crate::engine::tests_support::register_direct_plugin(&d, "mockb");

        const SENTINEL_BODY: &str = "queue-listing-secret-body";
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            SENTINEL_BODY.into(),
            None,
            vec![],
            None,
        );
        let id_a = {
            let store = d.store.lock().unwrap();
            let id = store.due_deliveries(Utc::now(), 10).unwrap()[0].id;
            store
                .mark_terminal(id, "dead_letter", "POLICY_DENIED")
                .unwrap();
            id
        };

        // an @identity-route row with a KNOWN target ref, inserted after
        // `id_a` above -- the higher id, so it's the "newest" row.
        let requester: Endpoint = "mocka:!req".parse().unwrap();
        let target: Endpoint = "mockb:+14155551234".parse().unwrap();
        engine::initiate_link(&d, requester, target, "Jascha").unwrap();
        let id_identity = {
            let store = d.store.lock().unwrap();
            let del = store
                .due_deliveries(Utc::now(), 10)
                .unwrap()
                .into_iter()
                .find(|de| de.route == IDENTITY_ROUTE)
                .expect("identity challenge delivery must be queued");
            store
                .mark_terminal(del.id, "dead_letter", "QUEUE_FULL")
                .unwrap();
            del.id
        };
        assert!(
            id_identity > id_a,
            "identity delivery must be the newer row"
        );

        // limit=1 must clamp to exactly the newest row.
        let (code, body) = get(router(d.clone()), "/v1/queue?state=dead_letter&limit=1").await;
        assert_eq!(code, 200);
        assert!(
            !body.contains(SENTINEL_BODY),
            "queue listing must never include message content: {body}"
        );
        assert!(
            !body.contains("+14155551234"),
            "full target ref leaked: {body}"
        );
        assert!(
            body.contains("\"destination\":\"mockb:+1****1234\""),
            "masked identity-route destination missing: {body}"
        );
        assert!(
            body.contains("\"reason\":\"QUEUE_FULL\""),
            "body was: {body}"
        );
        assert_eq!(
            body.matches("\"message_id\"").count(),
            1,
            "limit=1 must clamp to exactly one row: {body}"
        );

        // default limit returns both, newest (identity row) first.
        let (code2, body2) = get(router(d.clone()), "/v1/queue?state=dead_letter").await;
        assert_eq!(code2, 200);
        assert_eq!(
            body2.matches("\"message_id\"").count(),
            2,
            "default limit must return both dead_letter rows: {body2}"
        );
        let idx_identity = body2.find("QUEUE_FULL").expect("QUEUE_FULL reason missing");
        let idx_a = body2
            .find("POLICY_DENIED")
            .expect("POLICY_DENIED reason missing");
        assert!(
            idx_identity < idx_a,
            "newest (highest id) dead_letter row must come first: {body2}"
        );

        // out-of-range limits clamp rather than error: 0 -> 1, 5000 -> 1000.
        let (code3, body3) = get(router(d.clone()), "/v1/queue?state=dead_letter&limit=0").await;
        assert_eq!(code3, 200);
        assert_eq!(
            body3.matches("\"message_id\"").count(),
            1,
            "limit=0 must clamp up to one row: {body3}"
        );
        let (code4, body4) = get(router(d), "/v1/queue?state=dead_letter&limit=5000").await;
        assert_eq!(code4, 200);
        assert_eq!(
            body4.matches("\"message_id\"").count(),
            2,
            "limit=5000 must clamp to 1000 and return all rows: {body4}"
        );
    }

    // ---- read surface completion (design §2) --------------------------

    /// A route with no `identity_mode`/`render`/policies configured must
    /// still surface the same defaults `RouteConfig`'s own deserializer
    /// applies (`pseudonymous` / `{tag: "alias", max_chars: 0}`), and an
    /// empty `policies` list when `cfg.policies` is empty -- `daemon()`'s
    /// fixture route is exactly this default case.
    #[tokio::test]
    async fn routes_endpoint_reports_identity_mode_render_defaults_and_empty_policies() {
        let (code, body) = get(router(daemon()), "/v1/routes").await;
        assert_eq!(code, 200);
        assert!(
            body.starts_with("{\"routes\":["),
            "response must be wrapped in a routes object: {body}"
        );
        assert!(body.contains("\"name\":\"general\""), "body was: {body}");
        assert!(
            body.contains("\"identity_mode\":\"pseudonymous\""),
            "body was: {body}"
        );
        assert!(body.contains("\"tag\":\"alias\""), "body was: {body}");
        assert!(body.contains("\"max_chars\":0"), "body was: {body}");
        assert!(body.contains("\"policies\":[]"), "body was: {body}");
    }

    /// The route -> policy mapping mirrors `policy::evaluate`'s own
    /// matching rule (each delivery is evaluated against its single
    /// destination endpoint's protocol): a policy "applies to" a route if
    /// its `match.destination_protocol` is empty (matches every protocol)
    /// or intersects the set of protocols among the route's destinations.
    /// `meshtastic-only` matches neither of `general`'s destinations
    /// (`mocka`, `mockb`) and must be excluded.
    #[tokio::test]
    async fn routes_endpoint_lists_only_policies_whose_match_intersects_route_destination_protocols(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
    identity_mode: linked
    render:
      tag: none
      max_chars: 40
policies:
  - name: mockb-policy
    match:
      destination_protocol: ["mockb"]
    rules:
      max_payload: 500
  - name: catch-all-policy
    match: {{}}
    rules:
      max_payload: 1000
  - name: meshtastic-only
    match:
      destination_protocol: ["meshtastic"]
    rules:
      deny: true
"#,
            data_dir.display()
        );
        let cfg_path = dir.path().join("relayfabric.yaml");
        std::fs::write(&cfg_path, &yaml).unwrap();
        let cfg = crate::config::load(&cfg_path).unwrap();
        let d = Arc::new(crate::engine::Daemon::new(cfg, &data_dir).unwrap());
        std::mem::forget(dir);

        let (code, body) = get(router(d), "/v1/routes").await;
        assert_eq!(code, 200);
        assert!(
            body.contains("\"identity_mode\":\"linked\""),
            "body was: {body}"
        );
        assert!(body.contains("\"tag\":\"none\""), "body was: {body}");
        assert!(body.contains("\"max_chars\":40"), "body was: {body}");
        assert!(
            body.contains("\"policies\":[\"mockb-policy\",\"catch-all-policy\"]"),
            "matching policies (in declared order) missing or wrong: {body}"
        );
        assert!(!body.contains("meshtastic-only"),
            "a policy whose match doesn't intersect the route's destination protocols must be excluded: {body}");
    }

    /// `GET /v1/plugins` (design §2): each entry grows a `gauges` object
    /// keyed by gauge name -> `{value, age_secs}`; a plugin that never
    /// reported gauges gets `{}`, matching `PluginGauges::for_plugin`'s
    /// staleness/absence rule.
    #[tokio::test]
    async fn plugins_endpoint_includes_gauges_and_empty_object_when_none_reported() {
        let d = daemon();
        let _rx = crate::engine::tests_support::register_plugin(&d, "mocka", false);
        let mut vals = std::collections::BTreeMap::new();
        vals.insert("rssi".to_string(), -71.5);
        d.gauges.record("mocka", vals);

        let (code, body) = get(router(d), "/v1/plugins").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"rssi\""), "mocka's gauge missing: {body}");
        assert!(
            body.contains("\"value\":-71.5"),
            "gauge value missing: {body}"
        );
        assert!(body.contains("\"age_secs\":0"), "gauge age missing: {body}");
        // mockb is enabled (test_daemon's fixture) but never reported gauges.
        assert!(
            body.contains("\"mockb\":{\"capabilities\":null,\"connected\":false,\"gauges\":{}}"),
            "mockb must report an empty gauges object: {body}"
        );
    }

    /// `GET /v1/config` (design §2): serves `Config.raw_yaml` byte-verbatim
    /// with `Content-Type: text/yaml` -- secrets stay in their unresolved
    /// `${...}` form since resolution never touches `raw_yaml` at all.
    #[tokio::test]
    async fn config_endpoint_serves_raw_yaml_verbatim_with_text_yaml_content_type() {
        let sentinel = "sentinel-config-yaml-leak-1a2b";
        let d = daemon_with_plugin_secret("RF_ADMIN_TEST_SECRET_CONFIG_YAML", sentinel);
        let expected_yaml = d.cfg_snapshot(|c| c.raw_yaml.clone());
        assert!(
            !expected_yaml.is_empty(),
            "test fixture sanity: raw_yaml must be populated"
        );

        let resp = router(d)
            .oneshot(
                Request::builder()
                    .uri("/v1/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "text/yaml",
            "wrong content-type"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body);
        assert_eq!(body_str, expected_yaml, "raw yaml not served byte-verbatim");
        assert!(
            body_str.contains("${env:RF_ADMIN_TEST_SECRET_CONFIG_YAML}"),
            "unresolved reference form must be present: {body_str}"
        );
        assert!(
            !body_str.contains(sentinel),
            "resolved secret leaked in /v1/config: {body_str}"
        );
    }

    #[tokio::test]
    async fn metrics_render() {
        let (code, body) = get(router(daemon()), "/metrics").await;
        assert_eq!(code, 200);
        assert!(body.contains("relayfabric_messages_ingress_total"));
    }

    // ---- identity admin endpoints ------------------------------------------

    /// Masking regression (design §Security invariants / webui-notes): a
    /// full ref must never appear anywhere in the response body, and the
    /// masked "protocol:masked_ref" compound form (RULING 2) must.
    #[tokio::test]
    async fn identities_lists_masked_links_and_never_leaks_full_refs() {
        let d = daemon();
        let now = Utc::now();
        let id = d
            .store
            .lock()
            .unwrap()
            .insert_link(
                "signal",
                "+14155551234",
                "lxmf",
                "aabbccddeeff",
                "Jascha",
                now,
            )
            .unwrap();

        let (code, body) = get(router(d), "/v1/identities").await;
        assert_eq!(code, 200);
        assert!(
            !body.contains("+14155551234"),
            "full requester ref leaked: {body}"
        );
        assert!(
            !body.contains("aabbccddeeff"),
            "full target ref leaked: {body}"
        );
        assert!(
            body.contains("\"a\":\"signal:+1****1234\""),
            "masked a-side missing: {body}"
        );
        assert!(
            body.contains("\"b\":\"lxmf:aa****eeff\""),
            "masked b-side missing: {body}"
        );
        assert!(body.contains(&format!("\"id\":{id}")), "body was: {body}");
        assert!(
            body.contains("\"display_name\":\"Jascha\""),
            "body was: {body}"
        );
    }

    #[tokio::test]
    async fn identities_empty_by_default() {
        let (code, body) = get(router(daemon()), "/v1/identities").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"links\":[]"), "body was: {body}");
    }

    #[tokio::test]
    async fn post_identities_link_returns_202_and_challenge_id_when_target_direct_capable() {
        let d = daemon();
        let _rx = crate::engine::tests_support::register_direct_plugin(&d, "mockb");
        let body = serde_json::json!({
            "requester": "mocka:!alice-secret",
            "target": "mockb:!bob-secret",
            "display_name": "Jascha",
        })
        .to_string();

        let (code, resp_body) = req(router(d), "POST", "/v1/identities/link", Some(&body)).await;
        assert_eq!(code, 202, "body was: {resp_body}");
        assert!(
            resp_body.contains("\"challenge_id\""),
            "body was: {resp_body}"
        );
        assert!(
            !resp_body.contains("!alice-secret"),
            "the requester's full ref must never leak in the response: {resp_body}"
        );
    }

    /// 409 case must name the direct-capable connected plugin(s) — mirrors
    /// engine.rs's own `initiate_link_rejects_target_without_direct_messages_
    /// and_names_direct_capable_plugins` at the HTTP layer.
    #[tokio::test]
    async fn post_identities_link_returns_409_naming_direct_capable_plugins() {
        let d = daemon();
        let _rx_a = crate::engine::tests_support::register_direct_plugin(&d, "mocka");
        let _rx_b = crate::engine::tests_support::register_plugin(&d, "mockb", false);
        let body = serde_json::json!({
            "requester": "mockb:!req",
            "target": "mockb:!target-secret",
            "display_name": "X",
        })
        .to_string();

        let (code, resp_body) = req(router(d), "POST", "/v1/identities/link", Some(&body)).await;
        assert_eq!(code, 409, "body was: {resp_body}");
        assert!(
            resp_body.contains("mocka"),
            "409 body must name the direct-capable plugin: {resp_body}"
        );
        assert!(
            !resp_body.contains("target-secret"),
            "target ref must never leak in the 409 body: {resp_body}"
        );
    }

    /// RULING 1 (Task 3/4), surfaced through the HTTP layer: a global-queue-
    /// cap rejection from `engine::initiate_link` folds into the same 409 the
    /// capability-rejection case uses (see `create_link`'s doc comment), but
    /// with "queue full" in the body so the WebUI can branch on the two
    /// distinct 409 causes by text — mirrors engine.rs's own
    /// `initiate_link_over_global_queue_cap_dead_letters_and_returns_queue_full`
    /// at the admin-router level.
    #[tokio::test]
    async fn post_identities_link_returns_409_with_queue_full_when_global_queue_is_saturated() {
        let dir = tempfile::tempdir().unwrap();
        let d = crate::engine::tests_support::test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                global: crate::config::GlobalLimits {
                    queue_max: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        std::mem::forget(dir);
        let d = Arc::new(d);
        let _rx = crate::engine::tests_support::register_direct_plugin(&d, "mockb");

        // saturate the global queue with an ordinary routed message first.
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            None,
            vec![],
            None,
        );

        let body = serde_json::json!({
            "requester": "mocka:!req",
            "target": "mockb:!target-secret",
            "display_name": "X",
        })
        .to_string();
        let (code, resp_body) = req(router(d), "POST", "/v1/identities/link", Some(&body)).await;
        assert_eq!(code, 409, "body was: {resp_body}");
        assert!(
            resp_body.contains("queue full"),
            "409 body must be distinguishable as queue-full: {resp_body}"
        );
        assert!(
            !resp_body.contains("target-secret"),
            "target ref must never leak in the 409 body: {resp_body}"
        );
    }

    #[tokio::test]
    async fn post_identities_link_returns_400_on_malformed_json() {
        let (code, _) = req(
            router(daemon()),
            "POST",
            "/v1/identities/link",
            Some("not json"),
        )
        .await;
        assert_eq!(code, 400);
    }

    #[tokio::test]
    async fn post_identities_link_returns_400_on_unparsable_endpoint() {
        let body = serde_json::json!({
            "requester": "not-a-valid-endpoint",
            "target": "mocka:!b",
            "display_name": "X",
        })
        .to_string();
        let (code, _) = req(router(daemon()), "POST", "/v1/identities/link", Some(&body)).await;
        assert_eq!(code, 400);
    }

    #[tokio::test]
    async fn delete_identities_link_returns_204_then_404() {
        let d = daemon();
        let now = Utc::now();
        let id = d
            .store
            .lock()
            .unwrap()
            .insert_link("signal", "+1234567890", "lxmf", "abc123", "X", now)
            .unwrap();

        let (code, _) = req(
            router(d.clone()),
            "DELETE",
            &format!("/v1/identities/link/{id}"),
            None,
        )
        .await;
        assert_eq!(code, 204);

        let (code2, _) = req(
            router(d),
            "DELETE",
            &format!("/v1/identities/link/{id}"),
            None,
        )
        .await;
        assert_eq!(code2, 404);
    }

    /// Masking regression (challenges variant): the code must never appear
    /// in the response, and the masked target must.
    #[tokio::test]
    async fn challenges_lists_masked_targets_and_never_leaks_code_or_full_ref() {
        let d = daemon();
        let now = Utc::now();
        let expires = now + chrono::Duration::minutes(15);
        d.store
            .lock()
            .unwrap()
            .create_challenge(
                "424242",
                "signal",
                "+14155551234",
                "lxmf",
                "abc123def456",
                "Jascha",
                now,
                expires,
            )
            .unwrap();

        let (code, body) = get(router(d), "/v1/identities/challenges").await;
        assert_eq!(code, 200);
        assert!(!body.contains("424242"), "code leaked: {body}");
        assert!(
            !body.contains("+14155551234"),
            "full target ref leaked: {body}"
        );
        assert!(
            body.contains("\"target\":\"signal:+1****1234\""),
            "masked target missing: {body}"
        );
        assert!(body.contains("\"pending_count\":1"), "body was: {body}");
    }

    #[tokio::test]
    async fn challenges_empty_by_default() {
        let (code, body) = get(router(daemon()), "/v1/identities/challenges").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"pending_count\":0"), "body was: {body}");
        assert!(body.contains("\"challenges\":[]"), "body was: {body}");
    }

    // ---- GET /v1/federation (design §6, Task 5) ----------------------------

    fn fed_peer(name: &str, node_id: &str) -> crate::config::PeerConfig {
        crate::config::PeerConfig {
            name: name.into(),
            node_id: node_id.into(),
            addr: "10.0.0.2:47000".into(),
            trust: "verified".into(),
            messages_per_minute: 0,
            sealed_key: None,
        }
    }

    fn fed_cfg(peers: Vec<crate::config::PeerConfig>) -> crate::config::FederationConfig {
        crate::config::FederationConfig {
            listen: None,
            accept_from: "verified".into(),
            max_hops: 4,
            max_ttl_secs: 86_400,
            identity_exposure: "pseudonymous".into(),
            ingress_routes: vec![],
            peers,
            trusted: vec![],
            blocked: vec![],
        }
    }

    fn daemon_with_federation(fed: crate::config::FederationConfig) -> Arc<Daemon> {
        let dir = tempfile::tempdir().unwrap();
        let d = crate::engine::tests_support::test_daemon_with_federation(dir.path(), fed);
        std::mem::forget(dir);
        Arc::new(d)
    }

    /// Registers a live federation connection directly on `d.fed.conns`
    /// under `key` -- the same map a real handshake (`fed::conn::
    /// register_up`) would populate, without needing an actual Noise
    /// connection. `key` is a configured peer's NAME for the "configured,
    /// connected" tests, or the raw node_id for the "inbound-only,
    /// unconfigured" test (mirroring `fed::conn::accept_loop_with_cap`'s own
    /// `configured_peer_name`-or-`node_id` keying).
    fn register_fed_conn(
        d: &Daemon,
        key: &str,
        node_id: &str,
        connected_at: chrono::DateTime<Utc>,
    ) {
        let (tx, _rx) = tokio::sync::mpsc::channel::<crate::fed::wire::Fed>(1);
        d.fed.as_ref().unwrap().conns.lock().unwrap().insert(
            key.to_string(),
            PeerConn::new(tx, node_id.to_string(), connected_at),
        );
    }

    #[tokio::test]
    async fn federation_endpoint_reports_empty_peers_when_federation_is_not_configured() {
        let (code, body) = get(router(daemon()), "/v1/federation").await;
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["peers"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn federation_endpoint_lists_a_connected_configured_peer() {
        let node_id = format!("rf:{}", "aa".repeat(32));
        let d = daemon_with_federation(fed_cfg(vec![fed_peer("phoenix", &node_id)]));
        register_fed_conn(&d, "phoenix", &node_id, Utc::now());

        let (code, body) = get(router(d), "/v1/federation").await;
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let peers = v["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0]["name"], "phoenix");
        assert_eq!(peers[0]["node_id"], node_id);
        assert_eq!(
            peers[0]["trust"], "verified",
            "seeded from peers[].trust at boot"
        );
        assert_eq!(peers[0]["connected"], true);
        assert!(!peers[0]["last_seen"].is_null());
    }

    #[tokio::test]
    async fn federation_endpoint_reports_a_configured_but_disconnected_peer() {
        let node_id = format!("rf:{}", "bb".repeat(32));
        let d = daemon_with_federation(fed_cfg(vec![fed_peer("phoenix", &node_id)]));
        // No register_fed_conn call: configured, but never connected.

        let (code, body) = get(router(d), "/v1/federation").await;
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let peers = v["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0]["name"], "phoenix");
        assert_eq!(peers[0]["connected"], false);
        // Seeded at boot (test_daemon_with_federation calls
        // seed_federation_trust) -- last_seen falls back to the trust
        // store's updated_at, never null for a configured peer.
        assert!(!peers[0]["last_seen"].is_null());
    }

    #[tokio::test]
    async fn federation_endpoint_includes_an_inbound_only_seen_node_with_null_name() {
        let d = daemon_with_federation(fed_cfg(vec![])); // no configured peers at all
        let node_id = format!("rf:{}", "cc".repeat(32));
        d.store
            .lock()
            .unwrap()
            .record_seen(&node_id, Utc::now())
            .unwrap();
        register_fed_conn(&d, &node_id, &node_id, Utc::now()); // unconfigured: keyed by its own node_id

        let (code, body) = get(router(d), "/v1/federation").await;
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let peers = v["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 1);
        assert!(
            peers[0]["name"].is_null(),
            "an inbound-only node has no configured name: {body}"
        );
        assert_eq!(peers[0]["node_id"], node_id);
        assert_eq!(peers[0]["trust"], "seen");
        assert_eq!(peers[0]["connected"], true);
    }

    #[tokio::test]
    async fn federation_endpoint_never_includes_an_addr_field() {
        let node_id = format!("rf:{}", "dd".repeat(32));
        let mut peer = fed_peer("phoenix", &node_id);
        peer.addr = "203.0.113.7:47000".into(); // distinctive marker, must never leak
        let d = daemon_with_federation(fed_cfg(vec![peer]));
        register_fed_conn(&d, "phoenix", &node_id, Utc::now());

        let (_, body) = get(router(d), "/v1/federation").await;
        assert!(
            !body.contains("addr"),
            "response must never surface a peer's dial address: {body}"
        );
        assert!(
            !body.contains("203.0.113.7"),
            "response must never surface a peer's dial address: {body}"
        );
    }

    // ---- discovery (design §6, Task 3) -------------------------------------

    fn daemon_with_discovery_mode(mode: &str) -> Arc<Daemon> {
        let dir = tempfile::tempdir().unwrap();
        let d = crate::engine::tests_support::test_daemon(dir.path());
        d.cfg.write().unwrap().discovery.mode = mode.to_string();
        std::mem::forget(dir);
        Arc::new(d)
    }

    #[tokio::test]
    async fn discovery_endpoint_reports_disabled_mode_and_null_our_advert_by_default() {
        let d = daemon(); // discovery: DiscoveryConfig::default() => mode "disabled"
        let (code, body) = get(router(d), "/v1/discovery").await;
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["mode"], "disabled");
        assert!(
            v["our_advert"].is_null(),
            "discovery disabled must report our_advert: null, got {body}"
        );
        assert_eq!(v["peers"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn discovery_endpoint_reports_our_advert_when_enabled() {
        let d = daemon_with_discovery_mode("federation");
        let (code, body) = get(router(d.clone()), "/v1/discovery").await;
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["mode"], "federation");
        let our = &v["our_advert"];
        assert!(
            !our.is_null(),
            "discovery enabled must produce a non-null our_advert: {body}"
        );
        assert_eq!(our["node_id"], d.node_id);
        assert_eq!(our["name"], "t", "test_daemon's node.name fixture");
        assert_eq!(our["services"]["federation"], true);
    }

    /// Builds and signs a standalone peer advert (own throwaway identity,
    /// never the daemon-under-test's own) for the storage-tampering tests
    /// below -- mirrors `fed::advert`'s own `fixed_advert`/`sign` test
    /// fixtures rather than going through `fed::conn`'s wire path, since
    /// these tests are exercising `GET /v1/discovery`'s serve-side
    /// re-verification directly against hand-inserted `peer_adverts` rows.
    fn signed_peer_advert(
        dir: &std::path::Path,
        key_name: &str,
        advert_name: &str,
        expires: chrono::DateTime<Utc>,
    ) -> Advert {
        let identity =
            crate::node_identity::NodeIdentity::load_or_create(&dir.join(key_name)).unwrap();
        let mut services = BTreeMap::new();
        services.insert("federation".to_string(), true);
        let unsigned = Advert {
            rf_version: 1,
            node_id: identity.node_id(),
            name: advert_name.to_string(),
            services,
            protocols: BTreeMap::new(),
            security: crate::fed::advert::SecurityCaps {
                translate: true,
                signed: true,
                sealed: true,
                sealed_key: Some("11".repeat(32)),
            },
            expires: expires.timestamp(),
            sig: Vec::new(),
        };
        advert::sign(unsigned, &identity)
    }

    #[tokio::test]
    async fn discovery_endpoint_lists_a_stored_peer_advert_with_the_documented_shape() {
        let d = daemon();
        let dir = tempfile::tempdir().unwrap();
        let expires = Utc::now() + chrono::Duration::hours(1);
        let signed = signed_peer_advert(dir.path(), "peer1", "Phoenix", expires);
        let mut raw = Vec::new();
        ciborium::into_writer(&signed, &mut raw).unwrap();
        d.store
            .lock()
            .unwrap()
            .upsert_peer_advert(&signed.node_id, &raw, "Phoenix", expires, Utc::now())
            .unwrap();

        let (code, body) = get(router(d), "/v1/discovery").await;
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let peers = v["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0]["node_id"], signed.node_id);
        assert_eq!(peers[0]["name"], "Phoenix");
        assert_eq!(peers[0]["services"]["federation"], true);
        assert_eq!(peers[0]["expires"], signed.expires);
        assert!(!peers[0]["received_at"].is_null());
        assert!(
            peers[0].get("security").is_some(),
            "shape must include security: {body}"
        );
        assert!(
            peers[0].get("protocols").is_some(),
            "shape must include protocols: {body}"
        );
    }

    /// The brief's exact tamper scenario: garbage bytes written straight
    /// into `advert_cbor`, simulating direct DB tampering rather than
    /// anything that ever passed the receive path's own verification.
    #[tokio::test]
    async fn discovery_endpoint_drops_a_row_whose_stored_cbor_is_garbage() {
        let d = daemon();
        let node_id = format!("rf:{}", "ee".repeat(32));
        d.store
            .lock()
            .unwrap()
            .upsert_peer_advert(
                &node_id,
                b"not-valid-cbor-at-all",
                "Tampered",
                Utc::now() + chrono::Duration::hours(1),
                Utc::now(),
            )
            .unwrap();

        let (code, body) = get(router(d), "/v1/discovery").await;
        assert_eq!(
            code, 200,
            "a tampered row must not crash the endpoint: {body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["peers"],
            serde_json::json!([]),
            "a row that fails re-verification on serve must be dropped, not served: {body}"
        );
    }

    /// The sibling tamper case: valid CBOR shape (decodes fine) but a
    /// field was mutated after signing, so the signature no longer matches
    /// -- design §3/§6's "verify on serve" must catch this too, not just
    /// outright-unparseable bytes.
    #[tokio::test]
    async fn discovery_endpoint_drops_a_row_whose_cbor_decodes_but_fails_signature_reverification()
    {
        let d = daemon();
        let dir = tempfile::tempdir().unwrap();
        let mut signed = signed_peer_advert(
            dir.path(),
            "peer2",
            "Seattle",
            Utc::now() + chrono::Duration::hours(1),
        );
        signed.name.push('!'); // mutate AFTER signing: valid CBOR, bad signature
        let mut raw = Vec::new();
        ciborium::into_writer(&signed, &mut raw).unwrap();
        d.store
            .lock()
            .unwrap()
            .upsert_peer_advert(
                &signed.node_id,
                &raw,
                "Seattle!",
                Utc::now() + chrono::Duration::hours(1),
                Utc::now(),
            )
            .unwrap();

        let (code, body) = get(router(d), "/v1/discovery").await;
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["peers"],
            serde_json::json!([]),
            "a row whose stored CBOR fails signature re-verification must be dropped: {body}"
        );
    }

    /// Fix round 1 (review Important finding): `advert::verify` only
    /// proves an advert is SELF-consistent -- its `sig` matches its OWN
    /// embedded `node_id` -- it says nothing about whether that embedded
    /// `node_id` matches the `peer_adverts` ROW KEY it's stored under. A
    /// DB-write-capable attacker needs no victim private key at all: sign a
    /// perfectly valid advert under their OWN keypair (embedded
    /// `node_id: "rf:<attacker>"`), then insert it keyed to the VICTIM's
    /// `node_id`. `advert::verify` alone passes this straight through,
    /// which -- before this fix -- the handler would then serve as
    /// `node_id: "rf:<victim>"` with attacker-chosen name/services: a full
    /// identity spoof of a trusted node, no signing key compromise needed.
    /// This asserts that row is dropped entirely (not served under EITHER
    /// node_id), while a sibling row whose key matches its embedded
    /// node_id still serves normally -- proving the fix doesn't just drop
    /// everything.
    #[tokio::test]
    async fn discovery_endpoint_drops_a_row_whose_embedded_node_id_does_not_match_its_storage_key()
    {
        let d = daemon();
        let dir = tempfile::tempdir().unwrap();

        // The spoofed row: validly self-signed under the ATTACKER's own
        // keypair, but inserted keyed to a DIFFERENT (victim) node_id --
        // exactly the "no victim private key needed" attack the review
        // finding describes.
        let victim_node_id = format!("rf:{}", "ff".repeat(32));
        let attacker_signed = signed_peer_advert(
            dir.path(),
            "attacker",
            "Attacker-Controlled Name",
            Utc::now() + chrono::Duration::hours(1),
        );
        assert_ne!(
            attacker_signed.node_id, victim_node_id,
            "sanity: distinct identities"
        );
        let mut attacker_raw = Vec::new();
        ciborium::into_writer(&attacker_signed, &mut attacker_raw).unwrap();
        d.store
            .lock()
            .unwrap()
            .upsert_peer_advert(
                &victim_node_id,
                &attacker_raw,
                "Attacker-Controlled Name",
                Utc::now() + chrono::Duration::hours(1),
                Utc::now(),
            )
            .unwrap();

        // A legitimate sibling row (key == embedded node_id) must still be
        // served -- this fix must not turn into "drop every row".
        let legit_signed = signed_peer_advert(
            dir.path(),
            "legit",
            "Legit",
            Utc::now() + chrono::Duration::hours(1),
        );
        let mut legit_raw = Vec::new();
        ciborium::into_writer(&legit_signed, &mut legit_raw).unwrap();
        d.store
            .lock()
            .unwrap()
            .upsert_peer_advert(
                &legit_signed.node_id,
                &legit_raw,
                "Legit",
                Utc::now() + chrono::Duration::hours(1),
                Utc::now(),
            )
            .unwrap();

        let (code, body) = get(router(d), "/v1/discovery").await;
        assert_eq!(code, 200);
        assert!(!body.contains(&victim_node_id),
            "the victim's node_id must never appear in the response -- spoofed row must be fully dropped: {body}");
        assert!(!body.contains(&attacker_signed.node_id),
            "the row must not be served under the attacker's real node_id either -- dropping means \
             dropping, not re-keying: {body}");
        assert!(
            !body.contains("Attacker-Controlled Name"),
            "spoofed content must not leak: {body}"
        );

        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let peers = v["peers"].as_array().unwrap();
        assert_eq!(
            peers.len(),
            1,
            "only the legitimate row must survive: {body}"
        );
        assert_eq!(peers[0]["node_id"], legit_signed.node_id);
        assert_eq!(peers[0]["name"], "Legit");
    }

    /// Task 3 binding note: `advert_cbor` carries the peer's ORIGINAL,
    /// unsanitized `name` inside the signed bytes -- decoding it fresh on
    /// every serve (as re-verification requires) recovers whatever raw
    /// name the peer actually sent, control characters and all. This
    /// writes a properly-signed advert whose `.name` has raw control
    /// characters DIRECTLY into `advert_cbor` (bypassing `fed::conn::
    /// receive_advert`'s sanitize-before-store step entirely, and giving
    /// the `name` COLUMN a deliberately different, equally-unsanitized
    /// value) and asserts the served name is clean regardless -- proving
    /// the handler re-sanitizes the DECODED name itself rather than
    /// leaning on the (in this test, useless) stored column.
    #[tokio::test]
    async fn discovery_endpoint_always_serves_a_sanitized_name_even_when_the_raw_stored_advert_carries_control_chars(
    ) {
        let d = daemon();
        let dir = tempfile::tempdir().unwrap();
        let malicious_name = "\x1b[31mRED\x1b[0m\nline2\x00null";
        let signed = signed_peer_advert(
            dir.path(),
            "peer3",
            malicious_name,
            Utc::now() + chrono::Duration::hours(1),
        );
        let mut raw = Vec::new();
        ciborium::into_writer(&signed, &mut raw).unwrap();
        d.store
            .lock()
            .unwrap()
            .upsert_peer_advert(
                &signed.node_id,
                &raw,
                "unused-column-value-also-messy\x00",
                Utc::now() + chrono::Duration::hours(1),
                Utc::now(),
            )
            .unwrap();

        let (code, body) = get(router(d), "/v1/discovery").await;
        assert_eq!(code, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let peers = v["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 1);
        let served_name = peers[0]["name"].as_str().unwrap();
        assert_eq!(
            served_name,
            crate::fed::conn::sanitize_advert_name(malicious_name)
        );
        assert!(
            !served_name.contains('\x1b')
                && !served_name.contains('\n')
                && !served_name.contains('\0'),
            "served name must never carry control characters: {served_name:?}"
        );
    }

    // ---- secret reference redaction (design §2 / SPEC §51, §59) -----------

    /// Builds a daemon through the real `config::load` path (not
    /// `engine::tests_support`'s hand-built `Config` literals) so the
    /// plugin config's `${env:...}` reference actually goes through
    /// `config::resolve_secrets` -- the exact pipeline production runs.
    /// `mocka`'s config carries a secret reference resolving to `sentinel`;
    /// callers assert `sentinel` never appears in an admin response.
    ///
    /// `var_name` must be unique per call site: `std::env::set_var`/
    /// `remove_var` mutate real process-global state, and Rust runs
    /// `#[tokio::test]`s concurrently within one process, so two callers
    /// sharing a var name can race (one's `remove_var` firing between the
    /// other's `set_var` and `config::load`) and spuriously fail with
    /// "unset or empty".
    fn daemon_with_plugin_secret(var_name: &str, sentinel: &str) -> Arc<Daemon> {
        std::env::set_var(var_name, sentinel);
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
    config:
      token: "${{env:{var_name}}}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            data_dir.display()
        );
        let cfg_path = dir.path().join("relayfabric.yaml");
        std::fs::write(&cfg_path, &yaml).unwrap();
        let cfg = crate::config::load(&cfg_path).unwrap();
        // sanity: resolution actually happened, so a subsequent "never
        // leaked" assertion isn't vacuously true because nothing resolved.
        assert_eq!(
            cfg.plugins["mocka"]
                .config
                .get("token")
                .unwrap()
                .as_str()
                .unwrap(),
            sentinel,
        );
        std::env::remove_var(var_name);
        let d = crate::engine::Daemon::new(cfg, &data_dir).unwrap();
        std::mem::forget(dir);
        Arc::new(d)
    }

    /// Design §2's redaction invariant, binding the three read-surface
    /// endpoints this task completes: `/v1/routes` and `/v1/plugins` don't
    /// render plugin `config:` at all (they only echo route endpoints/
    /// identity_mode/render/policy names, or connection state/capabilities/
    /// gauges) -- a regression guard, not proof of active redaction, for
    /// those two. `/v1/config` is the one live case: it serves
    /// `Config.raw_yaml` verbatim, which is captured BEFORE
    /// `resolve_secrets` ever runs, so the resolved sentinel can never
    /// appear there by construction (only the `${...}` reference form).
    /// If any handler ever starts surfacing plugin config directly, it
    /// must read `Config::raw_plugin_configs` (the unresolved snapshot),
    /// never `cfg.plugins[_].config` (resolved, IPC-bound). See
    /// `config.rs`'s `raw_plugin_configs_retains_unresolved_form_for_
    /// display` for the unit-level half of this invariant.
    #[tokio::test]
    async fn admin_responses_never_contain_a_resolved_secret_value() {
        let sentinel = "sentinel-admin-leak-9f21";
        let d = daemon_with_plugin_secret("RF_ADMIN_TEST_SECRET", sentinel);
        for path in ["/v1/routes", "/v1/plugins", "/v1/config"] {
            let (code, body) = get(router(d.clone()), path).await;
            assert_eq!(code, 200, "path {path} status");
            assert!(
                !body.contains(sentinel),
                "resolved secret leaked from {path}: {body}"
            );
        }
    }

    // ---- config validate / apply / rollback (design §3) -------------------

    /// Builds a REAL on-disk config file (unlike `daemon()`'s hand-built
    /// `Config` literal, which has no backing file at all) plus a daemon
    /// loaded from it via the real `config::load` pipeline — the fixture
    /// every `config_{validate,put,rollback}` test needs, since those
    /// endpoints read/write `state.config_path` on disk. Deliberately
    /// force-set to 644 (rather than trusting whatever `std::fs::write` +
    /// the test runner's umask happens to produce) so every test built on
    /// this fixture starts from a mode `write_config_replacing_current`/
    /// `swap_with_prev` must actively CORRECT, not one that coincidentally
    /// already looks like 0600.
    fn daemon_with_config_file() -> (Arc<Daemon>, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let cfg_path = dir.path().join("relayfabric.yaml");
        let yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            data_dir.display()
        );
        std::fs::write(&cfg_path, &yaml).unwrap();
        std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let cfg = crate::config::load(&cfg_path).unwrap();
        let d = Daemon::new(cfg, &data_dir).unwrap();
        std::mem::forget(dir);
        (Arc::new(d), cfg_path)
    }

    #[tokio::test]
    async fn config_validate_returns_200_valid_true_for_good_yaml() {
        let (d, cfg_path) = daemon_with_config_file();
        let good_yaml = std::fs::read_to_string(&cfg_path).unwrap();
        let (code, body) = req(
            super::router(d, cfg_path),
            "POST",
            "/v1/config/validate",
            Some(&good_yaml),
        )
        .await;
        assert_eq!(code, 200, "body was: {body}");
        assert_eq!(body, "{\"valid\":true}", "body was: {body}");
    }

    #[tokio::test]
    async fn config_validate_returns_422_with_errors_for_unparsable_yaml() {
        let (d, cfg_path) = daemon_with_config_file();
        let bad_yaml = "node: [unterminated";
        let (code, body) = req(
            super::router(d, cfg_path),
            "POST",
            "/v1/config/validate",
            Some(bad_yaml),
        )
        .await;
        assert_eq!(code, 422, "body was: {body}");
        assert!(body.contains("\"valid\":false"), "body was: {body}");
        assert!(body.contains("\"errors\""), "body was: {body}");
    }

    /// Exercises `config::validate`'s own business-rule layer specifically
    /// (not just the parse layer above) — a route destination naming a
    /// plugin that was never declared under `plugins:` at all.
    #[tokio::test]
    async fn config_validate_returns_422_for_a_config_validate_rule_violation() {
        let (d, cfg_path) = daemon_with_config_file();
        let data_dir = d.cfg_snapshot(|c| c.node.data_dir.clone());
        let yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#,
            data_dir.display()
        );
        let (code, body) = req(
            super::router(d, cfg_path),
            "POST",
            "/v1/config/validate",
            Some(&yaml),
        )
        .await;
        assert_eq!(code, 422, "body was: {body}");
        assert!(body.contains("unknown plugin"), "body was: {body}");
        assert!(body.contains("mockb"), "body was: {body}");
    }

    /// Exercises the secret-reference-resolution layer specifically: a
    /// syntactically valid, `config::validate`-clean config whose
    /// `${env:...}` reference can't resolve (the var is unset) must still
    /// 422 — this is the "resolution CHECK" half of validate's pipeline
    /// (design §3), and the error must name only the reference FORM.
    #[tokio::test]
    async fn config_validate_returns_422_when_a_secret_reference_is_unresolvable() {
        std::env::remove_var("RF_ADMIN_TEST_VALIDATE_UNSET_VAR"); // ensure genuinely unset
        let (d, cfg_path) = daemon_with_config_file();
        let data_dir = d.cfg_snapshot(|c| c.node.data_dir.clone());
        let yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
    config:
      token: "${{env:RF_ADMIN_TEST_VALIDATE_UNSET_VAR}}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            data_dir.display()
        );
        let (code, body) = req(
            super::router(d, cfg_path),
            "POST",
            "/v1/config/validate",
            Some(&yaml),
        )
        .await;
        assert_eq!(code, 422, "body was: {body}");
        assert!(
            body.contains("env:RF_ADMIN_TEST_VALIDATE_UNSET_VAR"),
            "error must name the reference form: {body}"
        );
    }

    /// Fix round 1 (Important) — regression sentinel pinning
    /// `config::load_from_str`'s validate-before-resolve ordering: a config
    /// whose secret reference WOULD resolve (the env var is set to a
    /// sentinel) but that fails `config::validate` for an unrelated reason
    /// (the reserved `@identity` route name) must 422 with neither the
    /// sentinel NOR the reference form itself anywhere in the body. This
    /// holds today because `load_from_str` calls `validate` BEFORE
    /// `resolve_secrets`, so a config this broken never gets far enough to
    /// resolve anything at all -- this test exists to catch a future
    /// reordering that would change that.
    #[tokio::test]
    async fn config_validate_returns_422_with_neither_sentinel_nor_resolved_value_when_validation_fails_for_an_unrelated_reason(
    ) {
        let var = "RF_ADMIN_TEST_VALIDATE_BEFORE_RESOLVE";
        let sentinel = "sentinel-validate-before-resolve-6e2a";
        std::env::set_var(var, sentinel);
        let (d, cfg_path) = daemon_with_config_file();
        let data_dir = d.cfg_snapshot(|c| c.node.data_dir.clone());
        let yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
    config:
      token: "${{env:{var}}}"
  mockb:
    enabled: true
routes:
  - name: "@identity"
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#,
            data_dir.display()
        );

        let (code, body) = req(
            super::router(d, cfg_path),
            "POST",
            "/v1/config/validate",
            Some(&yaml),
        )
        .await;
        std::env::remove_var(var);

        assert_eq!(code, 422, "body was: {body}");
        assert!(body.contains("\"valid\":false"), "body was: {body}");
        assert!(
            body.contains("reserved"),
            "error must name the actual validate()-level cause: {body}"
        );
        assert!(
            !body.contains(sentinel),
            "resolved secret leaked despite an unrelated validate() failure: {body}"
        );
        assert!(!body.contains(&format!("env:{var}")),
            "the secret reference form must not even appear -- resolve_secrets must never have run: {body}");
    }

    #[tokio::test]
    async fn config_put_happy_path_writes_file_renames_prev_and_applies() {
        use std::os::unix::fs::PermissionsExt;

        let (d, cfg_path) = daemon_with_config_file();
        let original_text = std::fs::read_to_string(&cfg_path).unwrap();
        let data_dir = d.cfg_snapshot(|c| c.node.data_dir.clone());
        // adds an unused "mockc" plugin so restart_required is nonempty --
        // exercises the response shape beyond the bare {"applied":true}.
        let new_yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
  mockc:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            data_dir.display()
        );

        let (code, body) = req(
            super::router(d.clone(), cfg_path.clone()),
            "PUT",
            "/v1/config",
            Some(&new_yaml),
        )
        .await;
        assert_eq!(code, 200, "body was: {body}");
        assert!(body.contains("\"applied\":true"), "body was: {body}");
        assert!(
            body.contains("\"mockc\""),
            "restart_required must name the added plugin: {body}"
        );

        // file-state matrix: current holds the new content verbatim, .prev
        // holds the pre-PUT content verbatim, no leftover tmp artifact.
        let current = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(
            current, new_yaml,
            "current config file must hold the new content verbatim"
        );
        let prev = std::fs::read_to_string(super::prev_path_for(&cfg_path)).unwrap();
        assert_eq!(
            prev, original_text,
            ".prev must hold the pre-PUT content verbatim"
        );
        assert!(
            !super::tmp_path_for(&cfg_path).exists(),
            "no tmp artifact must remain after a successful PUT"
        );

        // 0600 on the newly-written current file (design §3 / alias.rs precedent).
        let mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "current config file must be 0600");

        // Fix round 1 (Critical): `.prev` must ALSO be forced to 0600, not
        // left at whatever mode the pre-PUT file had (`daemon_with_config_file`
        // deliberately starts it at 644 so this assertion actually exercises
        // the fix rather than passing by coincidence).
        let prev_mode = std::fs::metadata(super::prev_path_for(&cfg_path))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            prev_mode & 0o777,
            0o600,
            ".prev must be 0600, not inherited from the 644 original"
        );

        // daemon state actually applied: GET /v1/config would now serve the new text.
        assert_eq!(d.cfg_snapshot(|c| c.raw_yaml.clone()), new_yaml);
    }

    #[tokio::test]
    async fn config_put_keeps_five_previous_revisions_and_drops_the_oldest() {
        let (d, cfg_path) = daemon_with_config_file();
        let data_dir = d.cfg_snapshot(|c| c.node.data_dir.clone());
        let cfg = |tag: &str| {
            format!(
                "node:\n  name: rev-{tag}\n  data_dir: {}\nplugins:\n  mocka:\n    enabled: true\n  mockb:\n    enabled: true\nroutes:\n  - name: general\n    sources: [\"mocka:chan\"]\n    destinations: [\"mockb:chan\"]\n",
                data_dir.display()
            )
        };

        // Apply six distinct configs (v1..v6). With CONFIG_HISTORY = 5, the
        // five most recent PRIOR revisions (v5..v1) must survive, v6 is live,
        // and the original + v-nothing beyond five are dropped.
        let versions: Vec<String> = (1..=6).map(|i| cfg(&i.to_string())).collect();
        for v in &versions {
            let (code, body) = req(
                super::router(d.clone(), cfg_path.clone()),
                "PUT",
                "/v1/config",
                Some(v),
            )
            .await;
            assert_eq!(code, 200, "apply must succeed: {body}");
        }

        assert_eq!(
            std::fs::read_to_string(&cfg_path).unwrap(),
            versions[5],
            "live config = v6"
        );
        // slot 1 (newest prior) = v5, slot 2 = v4, … slot 5 (oldest kept) = v1.
        for (slot, vi) in (1..=5).zip([4usize, 3, 2, 1, 0]) {
            let text = std::fs::read_to_string(super::prev_slot_path(&cfg_path, slot))
                .unwrap_or_else(|_| panic!("slot {slot} must exist"));
            assert_eq!(text, versions[vi], "slot {slot} must hold v{}", vi + 1);
        }
        // Nothing kept beyond the five-deep history.
        assert!(
            !super::prev_slot_path(&cfg_path, 6).exists(),
            "no revision may be retained beyond CONFIG_HISTORY"
        );

        // The API surfaces each slot: ?n=1 = newest prior (v5), ?n=5 = v1.
        let (code, newest) = req(
            super::router(d.clone(), cfg_path.clone()),
            "GET",
            "/v1/config/prev",
            None,
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(
            newest, versions[4],
            "GET /v1/config/prev (default n=1) = v5"
        );
        let (code, oldest) = req(
            super::router(d.clone(), cfg_path.clone()),
            "GET",
            "/v1/config/prev?n=5",
            None,
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(oldest, versions[0], "GET /v1/config/prev?n=5 = v1");
        let (code, _) = req(
            super::router(d, cfg_path),
            "GET",
            "/v1/config/prev?n=6",
            None,
        )
        .await;
        assert_eq!(code, 404, "n beyond the kept history is 404");
    }

    #[tokio::test]
    async fn config_put_returns_422_and_makes_no_changes_for_invalid_yaml() {
        let (d, cfg_path) = daemon_with_config_file();
        let original_text = std::fs::read_to_string(&cfg_path).unwrap();
        let bad_yaml = "node: [unterminated";

        let (code, body) = req(
            super::router(d.clone(), cfg_path.clone()),
            "PUT",
            "/v1/config",
            Some(bad_yaml),
        )
        .await;
        assert_eq!(code, 422, "body was: {body}");
        assert!(body.contains("\"valid\":false"), "body was: {body}");

        let current = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(
            current, original_text,
            "an invalid PUT must not touch the config file"
        );
        assert!(
            !super::prev_path_for(&cfg_path).exists(),
            "an invalid PUT must not create .prev"
        );
    }

    /// Fix round 1 (Important): before the fix, `write_config_replacing_
    /// current` renamed `path` -> `.prev` FIRST and only wrote the tmp file
    /// second, so a failure during the (I/O-heavy) write left `path`
    /// missing with no automatic way back (`swap_with_prev` can't recover
    /// either -- it renames `path` first too). The fix writes the tmp file
    /// BEFORE touching `path`/`.prev` at all, so a write failure must leave
    /// both byte-identical to their pre-call state.
    ///
    /// Forces the failure by pre-creating `<path>.tmp` as a file this
    /// process cannot write to (mode 0o400) -- `OpenOptions::open` then
    /// fails at the open-for-write step specifically, WITHOUT touching
    /// directory permissions (a directory-permission-based fault would fail
    /// the rename() calls too, which would make this pass regardless of
    /// which order the rename/write steps run in -- it wouldn't actually
    /// distinguish the fixed ordering from the bug it replaces). Verified
    /// against the pre-fix ordering (rename-before-write): with that order
    /// restored, this same fault leaves `path` renamed away with nothing to
    /// replace it, and the assertions below fail exactly as the finding
    /// described.
    #[tokio::test]
    async fn config_put_returns_500_and_makes_no_changes_when_the_tmp_write_fails() {
        use std::os::unix::fs::PermissionsExt;

        let (d, cfg_path) = daemon_with_config_file();
        let original_text = std::fs::read_to_string(&cfg_path).unwrap();
        let data_dir = d.cfg_snapshot(|c| c.node.data_dir.clone());
        let new_yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            data_dir.display()
        );

        let tmp_path = super::tmp_path_for(&cfg_path);
        std::fs::write(&tmp_path, "pre-existing, unwritable").unwrap();
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o400)).unwrap();

        let (code, body) = req(
            super::router(d.clone(), cfg_path.clone()),
            "PUT",
            "/v1/config",
            Some(&new_yaml),
        )
        .await;

        assert_eq!(code, 500, "body was: {body}");
        let current = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(
            current, original_text,
            "a write failure must leave the config file untouched"
        );
        assert!(
            !super::prev_path_for(&cfg_path).exists(),
            "a write failure must never create .prev"
        );
    }

    /// Fix round 1 (Minor) — admin-layer restart_required matrix: proves
    /// `apply_config`'s diff behaves correctly THROUGH the real `PUT
    /// /v1/config` handler, not just via engine.rs's own unit tests that
    /// call `apply_config` directly. (a) a plugin config-block-only change
    /// must name that plugin, and only that plugin. (b) from that new
    /// baseline, a route-only change (render knobs) must report an EMPTY
    /// restart_required.
    #[tokio::test]
    async fn config_put_restart_required_names_a_plugin_config_change_and_is_empty_for_a_route_only_change(
    ) {
        let (d, cfg_path) = daemon_with_config_file();
        let data_dir = d.cfg_snapshot(|c| c.node.data_dir.clone());

        // (a) plugin config-block-only change.
        let plugin_config_changed = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
    config:
      token: "hello"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            data_dir.display()
        );
        let (code1, body1) = req(
            super::router(d.clone(), cfg_path.clone()),
            "PUT",
            "/v1/config",
            Some(&plugin_config_changed),
        )
        .await;
        assert_eq!(code1, 200, "body was: {body1}");
        assert_eq!(
            body1, "{\"applied\":true,\"restart_required\":[\"mocka\"]}",
            "only the plugin whose config block changed must be named: {body1}"
        );

        // (b) route-only change from THIS new baseline -- everything else
        // (node, plugins) held identical to `plugin_config_changed`.
        let route_only_changed = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
    config:
      token: "hello"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
    render:
      tag: none
      max_chars: 0
"#,
            data_dir.display()
        );
        let (code2, body2) = req(
            super::router(d.clone(), cfg_path.clone()),
            "PUT",
            "/v1/config",
            Some(&route_only_changed),
        )
        .await;
        assert_eq!(code2, 200, "body was: {body2}");
        assert_eq!(
            body2, "{\"applied\":true,\"restart_required\":[]}",
            "a route-only change must never require a restart: {body2}"
        );
    }

    #[tokio::test]
    async fn config_rollback_returns_404_when_no_prev_exists() {
        let (d, cfg_path) = daemon_with_config_file();
        let (code, body) = req(
            super::router(d, cfg_path),
            "POST",
            "/v1/config/rollback",
            None,
        )
        .await;
        assert_eq!(code, 404, "body was: {body}");
    }

    #[tokio::test]
    async fn config_rollback_happy_path_swaps_files_and_applies_the_previous_config() {
        use std::os::unix::fs::PermissionsExt;

        let (d, cfg_path) = daemon_with_config_file();
        let original_text = std::fs::read_to_string(&cfg_path).unwrap();
        let data_dir = d.cfg_snapshot(|c| c.node.data_dir.clone());
        let new_yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
    render:
      tag: none
      max_chars: 0
"#,
            data_dir.display()
        );

        let (put_code, put_body) = req(
            super::router(d.clone(), cfg_path.clone()),
            "PUT",
            "/v1/config",
            Some(&new_yaml),
        )
        .await;
        assert_eq!(put_code, 200, "seeding PUT failed: {put_body}");

        // Fix round 1 (Critical): force `.prev` back to 644 right before the
        // rollback -- simulating a `.prev` that landed at a non-0600 mode by
        // some other path (an older daemon, a manual copy, ...) -- so the
        // post-rollback 0600 assertion below actually exercises
        // `swap_with_prev`'s chmod rather than passing because the file
        // happened to already be 0600 from the seeding PUT.
        std::fs::set_permissions(
            super::prev_path_for(&cfg_path),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();

        let (code, body) = req(
            super::router(d.clone(), cfg_path.clone()),
            "POST",
            "/v1/config/rollback",
            None,
        )
        .await;
        assert_eq!(code, 200, "body was: {body}");
        assert!(body.contains("\"applied\":true"), "body was: {body}");

        let current = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(
            current, original_text,
            "current file must hold the rolled-back content"
        );
        let prev = std::fs::read_to_string(super::prev_path_for(&cfg_path)).unwrap();
        assert_eq!(
            prev, new_yaml,
            ".prev must now hold what was current before the rollback"
        );

        // Fix round 1 (Critical): the live config path after a rollback must
        // be 0600, even though the `.prev` it was just swapped in from was
        // deliberately left at 644 above.
        let live_mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode();
        assert_eq!(
            live_mode & 0o777,
            0o600,
            "live config path must be 0600 after rollback, not inherited from .prev's 644"
        );

        assert_eq!(d.cfg_snapshot(|c| c.raw_yaml.clone()), original_text);
    }

    /// Design §3's rollback safety net: `.prev` was valid when it was
    /// written, but the environment can drift afterward (an env-backed
    /// secret vanishes) -- re-validation must catch this and 409, leaving
    /// BOTH files exactly as they were before the call (validated before
    /// any swap happens, so there's nothing to undo).
    #[tokio::test]
    async fn config_rollback_returns_409_on_env_drift_with_files_untouched() {
        let var = "RF_ADMIN_TEST_ROLLBACK_DRIFT";
        std::env::set_var(var, "sentinel-rollback-drift-value");
        let (d, cfg_path) = daemon_with_config_file();
        let data_dir = d.cfg_snapshot(|c| c.node.data_dir.clone());

        // First PUT (var set): puts a config referencing the env var into
        // CURRENT, pushing the fixture's plain original into `.prev`.
        let secret_yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
    config:
      token: "${{env:{var}}}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            data_dir.display()
        );
        let (seed1_code, seed1_body) = req(
            super::router(d.clone(), cfg_path.clone()),
            "PUT",
            "/v1/config",
            Some(&secret_yaml),
        )
        .await;
        assert_eq!(seed1_code, 200, "seeding PUT 1 failed: {seed1_body}");

        // Second PUT (still var set, so `secret_yaml` re-validates fine):
        // pushes `secret_yaml` (now current) into `.prev`, and this new
        // plain config becomes current -- `.prev` is now what rollback will
        // try to restore, and it's the one that references the env var.
        let plain_yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            data_dir.display()
        );
        let (seed2_code, seed2_body) = req(
            super::router(d.clone(), cfg_path.clone()),
            "PUT",
            "/v1/config",
            Some(&plain_yaml),
        )
        .await;
        assert_eq!(seed2_code, 200, "seeding PUT 2 failed: {seed2_body}");

        let current_before = std::fs::read_to_string(&cfg_path).unwrap();
        let prev_before = std::fs::read_to_string(super::prev_path_for(&cfg_path)).unwrap();
        assert_eq!(
            current_before, plain_yaml,
            "test fixture sanity: current must be plain_yaml"
        );
        assert_eq!(
            prev_before, secret_yaml,
            "test fixture sanity: .prev must be secret_yaml"
        );

        std::env::remove_var(var);

        let (code, body) = req(
            super::router(d.clone(), cfg_path.clone()),
            "POST",
            "/v1/config/rollback",
            None,
        )
        .await;
        assert_eq!(code, 409, "body was: {body}");
        assert!(body.contains("\"errors\""), "body was: {body}");
        assert!(
            body.contains(&format!("env:{var}")),
            "error must name the reference form: {body}"
        );
        assert!(
            !body.contains("sentinel-rollback-drift-value"),
            "resolved secret leaked: {body}"
        );

        let current_after = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(
            current_after, current_before,
            "current file must be untouched after a 409"
        );
        let prev_after = std::fs::read_to_string(super::prev_path_for(&cfg_path)).unwrap();
        assert_eq!(
            prev_after, prev_before,
            ".prev must be untouched after a 409"
        );
    }

    /// Design §3's redaction invariant, extended to the three mutation
    /// endpoints (the read-surface half is `admin_responses_never_contain_
    /// a_resolved_secret_value` above): a resolved secret value must never
    /// appear in a validate/PUT/rollback response body.
    #[tokio::test]
    async fn config_mutation_responses_never_contain_a_resolved_secret_value() {
        let var = "RF_ADMIN_TEST_MUTATION_SECRET";
        let sentinel = "sentinel-mutation-secret-4c1d";
        std::env::set_var(var, sentinel);
        let (d, cfg_path) = daemon_with_config_file();
        let data_dir = d.cfg_snapshot(|c| c.node.data_dir.clone());
        let secret_yaml = format!(
            r#"
node:
  name: t
  data_dir: {}
plugins:
  mocka:
    enabled: true
    config:
      token: "${{env:{var}}}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            data_dir.display()
        );

        let (vcode, vbody) = req(
            super::router(d.clone(), cfg_path.clone()),
            "POST",
            "/v1/config/validate",
            Some(&secret_yaml),
        )
        .await;
        assert_eq!(vcode, 200, "body was: {vbody}");
        assert!(!vbody.contains(sentinel), "validate leaked secret: {vbody}");

        let (pcode, pbody) = req(
            super::router(d.clone(), cfg_path.clone()),
            "PUT",
            "/v1/config",
            Some(&secret_yaml),
        )
        .await;
        assert_eq!(pcode, 200, "body was: {pbody}");
        assert!(!pbody.contains(sentinel), "PUT leaked secret: {pbody}");

        let (rcode, rbody) = req(
            super::router(d.clone(), cfg_path.clone()),
            "POST",
            "/v1/config/rollback",
            None,
        )
        .await;
        assert_eq!(rcode, 200, "body was: {rbody}");
        assert!(!rbody.contains(sentinel), "rollback leaked secret: {rbody}");

        std::env::remove_var(var);
    }

    // ---- GET /v1/events (design §4) -----------------------------------

    /// Tower-oneshot CAN drive this deterministically, despite the response
    /// body being an unbounded stream: `events_stream`'s handler body has no
    /// `.await` point of its own (`subscribe()`, `BroadcastStream::new`,
    /// `filter_map`, `Sse::new`, `.keep_alive()` are all synchronous
    /// constructors), so by the time `.oneshot(request).await` resolves to a
    /// `Response`, the subscription is already registered on `d.events` --
    /// sending an event from this same task right afterward, before the
    /// body is ever polled, is race-free by construction, not a sleep-and-
    /// hope. Reading the body then uses `BodyExt::frame` under a bounded
    /// `tokio::time::timeout` (never `.collect()`, which would wait for
    /// EOF -- this stream never reaches one while the router is alive).
    #[tokio::test]
    async fn get_v1_events_streams_a_driven_ingress_event_over_tower_oneshot() {
        let d = daemon();
        let resp = router(d.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/events")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "text/event-stream",
            "wrong content-type"
        );

        let id = uuid::Uuid::now_v7();
        d.events
            .send(crate::events::Event::Ingress {
                id,
                protocol: "mocka".into(),
                sender_masked: "mocka:si****1234".into(),
                routes: vec!["general".into()],
                ts: chrono::Utc::now(),
            })
            .expect("send must succeed: the handler above has already subscribed");

        let mut body = resp.into_body();
        let mut collected = String::new();
        for _ in 0..20 {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(2), body.frame())
                .await
                .expect("timed out waiting for an SSE frame")
                .expect("body ended before yielding the driven event")
                .unwrap();
            if let Ok(data) = frame.into_data() {
                collected.push_str(&String::from_utf8_lossy(&data));
            }
            if collected.contains("event: ingress") {
                break;
            }
        }
        assert!(
            collected.contains("event: ingress"),
            "stream was: {collected}"
        );
        assert!(
            collected.contains(&format!("\"id\":\"{id}\"")),
            "stream was: {collected}"
        );
        assert!(
            collected.contains("\"sender_masked\":\"mocka:si****1234\""),
            "stream was: {collected}"
        );
        assert!(
            collected.contains("\"routes\":[\"general\"]"),
            "stream was: {collected}"
        );
    }

    /// Design §4: "lagged receivers skip missed events and continue" --
    /// tested directly against `events_stream_from`, bypassing axum/tower
    /// entirely (no HTTP machinery needed to prove the adapter's own
    /// behavior). Overrunning the 256-capacity channel without reading
    /// guarantees this receiver is lagged by the time it's finally polled;
    /// the assertion is simply that the stream yields a real `Ok(_)` event
    /// next, rather than erroring out or hanging.
    #[tokio::test]
    async fn lagged_receiver_is_skipped_not_fatal() {
        let (tx, rx) = tokio::sync::broadcast::channel(256);
        for i in 0..300u32 {
            tx.send(crate::events::Event::Plugin {
                name: format!("p{i}"),
                up: true,
                ts: chrono::Utc::now(),
            })
            .unwrap();
        }

        let mut stream = super::events_stream_from(rx);
        let item = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("must not hang skipping a lagged gap")
            .expect("stream must not end just because the receiver lagged");
        let _event: SseEvent =
            item.expect("must yield a real event once the lagged gap is skipped, not an error");
    }

    // ---- Task 1 (design §1): OpenAPI generation ---------------------------

    /// The load-bearing completeness test (design §1): every route the live
    /// `Router` serves must appear in `ApiDoc::openapi().paths`, and vice
    /// versa. Both sides of the comparison are structural, not hand-typed:
    /// `admin_routes()` is the SAME list `router()` is built from (not a
    /// separately hand-maintained mirror of it), and `doc.paths.paths` is
    /// whatever the `#[utoipa::path]` annotations actually produced. A
    /// route added to the router without a matching `#[utoipa::path]`
    /// entry in `ApiDoc`'s `paths(...)` list -- or vice versa -- fails
    /// this test.
    ///
    /// The path-set/length checks alone can't see a narrower mistake:
    /// a path documented under the wrong HTTP verb (e.g. `ApiDoc` claims
    /// `PUT /v1/config` but the router only wired `GET`) -- `MethodRouter`
    /// doesn't expose which methods it was built with, so a live probe
    /// closes that gap: for every (method, path) `ApiDoc` documents, send
    /// exactly that method through the real router and assert the
    /// response is never `405 Method Not Allowed`. Business-logic status
    /// codes (several handlers legitimately return their OWN 404s, e.g.
    /// `config_rollback`/`delete_link`) are irrelevant to this check --
    /// only 405 uniquely means "the path matched but this method isn't
    /// wired," so nothing else needs to be interpreted.
    #[tokio::test]
    async fn every_admin_route_is_documented_in_the_openapi_spec() {
        let router_paths: BTreeSet<&str> = admin_routes().iter().map(|(path, _)| *path).collect();
        let doc = ApiDoc::openapi();
        let doc_paths: BTreeSet<&str> = doc.paths.paths.keys().map(|s| s.as_str()).collect();

        assert_eq!(
            router_paths, doc_paths,
            "router paths and ApiDoc paths must match exactly -- a route was added to one without the other"
        );
        assert_eq!(
            admin_routes().len(), doc.paths.paths.len(),
            "admin_routes().len() (what router() is literally built from) must equal ApiDoc's documented path count"
        );

        let live = router(daemon());
        for (path, item) in &doc.paths.paths {
            let methods: [(&str, bool); 8] = [
                ("GET", item.get.is_some()),
                ("PUT", item.put.is_some()),
                ("POST", item.post.is_some()),
                ("DELETE", item.delete.is_some()),
                ("OPTIONS", item.options.is_some()),
                ("HEAD", item.head.is_some()),
                ("PATCH", item.patch.is_some()),
                ("TRACE", item.trace.is_some()),
            ];
            // The router matches on path SHAPE, not a path param's own
            // validity (Uuid vs i64 vs anything else) -- any non-empty
            // segment proves the pattern is registered.
            let concrete_path = path.replace("{id}", "1");
            for (method, documented) in methods {
                if !documented {
                    continue;
                }
                let resp = live
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(&concrete_path)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_ne!(
                    resp.status(), StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {path} is documented in ApiDoc but the router has no handler for that method"
                );
            }
        }
    }

    /// Sentinel test (design §1 / Security invariants): the served OpenAPI
    /// document is produced only from static handler annotations + Rust
    /// types -- `ApiDoc::openapi()` takes no config/daemon argument at all,
    /// so it structurally cannot echo a loaded secret. Asserted directly
    /// anyway per the brief: load a config whose ONLY appearance of a
    /// sentinel value is a resolved `${env:...}` secret reference, then
    /// confirm the generated OpenAPI document's serialized JSON never
    /// contains it.
    #[test]
    fn openapi_document_never_contains_a_loaded_secret_value() {
        const VAR: &str = "RF_ADMIN_TEST_OPENAPI_SENTINEL";
        const SENTINEL: &str = "sentinel-runtime-value-must-not-appear-in-openapi-doc";
        std::env::set_var(VAR, SENTINEL);
        let yaml = format!(
            r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-admin-openapi-sentinel-test
plugins:
  mocka:
    enabled: true
    config:
      token: "${{env:{VAR}}}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#
        );
        let cfg = crate::config::load_from_str(&yaml).unwrap();
        // Prove the secret genuinely resolved (not just an unused env var
        // sitting in the process environment) before checking the doc.
        assert_eq!(
            cfg.plugins["mocka"]
                .config
                .get("token")
                .unwrap()
                .as_str()
                .unwrap(),
            SENTINEL
        );

        let doc_json = serde_json::to_string(&ApiDoc::openapi()).unwrap();
        assert!(
            !doc_json.contains(SENTINEL),
            "OpenAPI doc leaked a loaded secret value: {doc_json}"
        );
        std::env::remove_var(VAR);
    }

    /// A promoted struct must serialize to the identical bytes the
    /// pre-promotion ad-hoc `json!` construction produced (design §1: "do
    /// not change the actual JSON shape on the wire"). `serde_json`'s
    /// default (non-`preserve_order`) `Value::Object` is `BTreeMap`-backed,
    /// so `json!{...}` always serializes object keys in ALPHABETICAL
    /// order regardless of the literal's field order -- each promoted
    /// struct's fields are declared in that same alphabetical order (see
    /// each struct's own doc comment) specifically so a plain
    /// `#[derive(Serialize)]` (which serializes in DECLARATION order)
    /// reproduces it byte-for-byte. Covers the two most structurally
    /// nested promotions (`LimitsResponse`, `FederationResponse`); the
    /// existing handler tests above (unchanged, still passing with
    /// `body.contains(...)` assertions) cover the rest at the HTTP-response
    /// level.
    #[test]
    fn limits_response_serializes_byte_identical_to_the_pre_promotion_json_shape() {
        let mut transport_budgets = BTreeMap::new();
        transport_budgets.insert(
            "mockb".to_string(),
            TransportBudgetItem {
                messages_per_minute: 30,
            },
        );
        let resp = LimitsResponse {
            global: GlobalLimitsItem {
                cas_max_bytes: 1_000_000_000,
                queue_max: 50_000,
            },
            per_route: PerRouteLimitsItem { queue_max: 5_000 },
            per_sender: PerSenderLimitsItem {
                bytes_per_hour: 50_000,
                messages_per_minute: 10,
            },
            transport_budgets,
        };
        let old = json!({
            "per_sender": { "messages_per_minute": 10u32, "bytes_per_hour": 50_000u64 },
            "per_route": { "queue_max": 5_000u32 },
            "global": { "queue_max": 50_000u32, "cas_max_bytes": 1_000_000_000u64 },
            "transport_budgets": { "mockb": { "messages_per_minute": 30u32 } },
        });
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            serde_json::to_string(&old).unwrap()
        );
    }

    #[test]
    fn federation_response_serializes_byte_identical_to_the_pre_promotion_json_shape() {
        let ts = chrono::Utc::now();
        let resp = FederationResponse {
            peers: vec![
                FederationPeerItem {
                    connected: true,
                    last_seen: Some(ts),
                    name: Some("phoenix".to_string()),
                    node_id: "rf:abc".to_string(),
                    trust: "trusted".to_string(),
                },
                FederationPeerItem {
                    connected: false,
                    last_seen: None,
                    name: None,
                    node_id: "rf:def".to_string(),
                    trust: "unknown".to_string(),
                },
            ],
        };
        let old = json!({
            "peers": [
                json!({
                    "name": "phoenix", "node_id": "rf:abc", "trust": "trusted",
                    "connected": true, "last_seen": ts,
                }),
                json!({
                    "name": serde_json::Value::Null, "node_id": "rf:def", "trust": "unknown",
                    "connected": false, "last_seen": serde_json::Value::Null,
                }),
            ]
        });
        assert_eq!(
            serde_json::to_string(&resp).unwrap(),
            serde_json::to_string(&old).unwrap()
        );
    }

    // ---- Task 2 (design §2): Swagger UI at GET /docs -----------------

    /// `/docs` (no trailing slash) must be a direct 200, NOT a redirect to
    /// `/docs/` -- that's the whole reason `serve_swagger_asset` bypasses
    /// `utoipa_swagger_ui`'s own axum glue (see its doc comment). A plain
    /// (non-redirect-following) client hitting `/docs` must get the page.
    #[tokio::test]
    async fn docs_serves_the_swagger_ui_index_directly_at_200() {
        let (status, body) = get(router(daemon()), "/docs").await;
        assert_eq!(status, 200);
        assert!(
            body.contains("swagger-ui"),
            "expected a Swagger UI marker in the body: {body}"
        );
    }

    /// `/docs/` (trailing slash) is the same page, also a direct 200.
    #[tokio::test]
    async fn docs_with_trailing_slash_also_serves_200_html() {
        let (status, body) = get(router(daemon()), "/docs/").await;
        assert_eq!(status, 200);
        assert!(
            body.contains("swagger-ui"),
            "expected a Swagger UI marker in the body: {body}"
        );
    }

    /// `/docs` response is actually served as `text/html`, matching what a
    /// browser needs to render it (not e.g. `application/octet-stream`).
    #[tokio::test]
    async fn docs_is_served_as_text_html() {
        let resp = router(daemon())
            .oneshot(Request::builder().uri("/docs").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            content_type.starts_with("text/html"),
            "unexpected content-type: {content_type}"
        );
    }

    /// Self-contained assertion (design §2 Security invariants / brief):
    /// the served `/docs` bytes reference no external host in an `href=`/
    /// `src=` attribute -- every asset is same-origin/relative, matching
    /// the project's no-CDN posture. Checked against the literal served
    /// index.html bytes, not the (huge, vendored, third-party) JS bundles
    /// it loads -- those aren't rewritten by this project and can contain
    /// incidental `https://` substrings (license headers, XML namespaces)
    /// that aren't resource-loading `src=`/`href=` attributes at all.
    #[tokio::test]
    async fn docs_html_has_no_external_href_or_src() {
        let (status, body) = get(router(daemon()), "/docs").await;
        assert_eq!(status, 200);
        for needle in [
            "href=\"http://",
            "href=\"https://",
            "src=\"http://",
            "src=\"https://",
        ] {
            assert!(
                !body.contains(needle),
                "self-contained /docs must not reference {needle}: {body}"
            );
        }
    }

    /// `/docs` actually points the Swagger UI at THIS daemon's own
    /// `/v1/openapi.json` (relative, same-origin), not some other spec --
    /// the reference lives in `swagger-initializer.js` (the `{{config}}`
    /// substitution `swagger_config()` drives), which is what a browser
    /// loading `/docs` fetches next.
    #[tokio::test]
    async fn docs_initializer_references_the_relative_openapi_json_url() {
        let (status, body) = get(router(daemon()), "/docs/swagger-initializer.js").await;
        assert_eq!(status, 200);
        assert!(
            body.contains("/v1/openapi.json"),
            "swagger-initializer.js must reference the relative /v1/openapi.json: {body}"
        );
        assert!(
            !body.contains("http://") && !body.contains("https://"),
            "swagger-initializer.js must not reference an external host: {body}"
        );
    }

    /// An unknown asset tail under `/docs/` (not part of the vendored
    /// dist) is a plain 404, not a panic or a fallback to the index page.
    #[tokio::test]
    async fn docs_unknown_asset_is_404() {
        let (status, _) = get(router(daemon()), "/docs/no-such-asset.js").await;
        assert_eq!(status, 404);
    }

    /// `/docs` is a UI route, deliberately outside `admin_routes()` (see
    /// `router`'s doc comment) -- it must never show up in the generated
    /// OpenAPI document's paths, since it isn't part of the API contract.
    #[test]
    fn docs_is_not_documented_in_the_openapi_spec() {
        let doc = ApiDoc::openapi();
        assert!(
            !doc.paths.paths.keys().any(|p| p.starts_with("/docs")),
            "/docs is UI, not API contract, and must not appear in ApiDoc's paths: {:?}",
            doc.paths.paths.keys().collect::<Vec<_>>()
        );
    }
}
