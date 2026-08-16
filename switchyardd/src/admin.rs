use crate::config::IDENTITY_ROUTE;
use crate::engine::{self, Daemon};
use crate::events::Event;
use crate::identity_links;
use crate::metrics;
use axum::body::Bytes;
use axum::extract::{FromRef, Path as AxPath, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use relay_core::Endpoint;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tracing::warn;
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

pub fn router(d: Arc<Daemon>, config_path: PathBuf) -> Router {
    let state = AdminState { daemon: d, config_path, write_lock: Arc::new(Mutex::new(())) };
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/plugins", get(plugins))
        .route("/v1/routes", get(routes))
        .route("/v1/config", get(config_yaml).put(config_put))
        .route("/v1/config/validate", post(config_validate))
        .route("/v1/config/rollback", post(config_rollback))
        .route("/v1/queue", get(queue))
        .route("/v1/messages/{id}", get(trace))
        .route("/v1/public", get(public))
        .route("/v1/limits", get(limits))
        .route("/v1/identities", get(identities))
        .route("/v1/identities/link", post(create_link))
        .route("/v1/identities/link/{id}", delete(delete_link))
        .route("/v1/identities/challenges", get(challenges))
        .route("/v1/events", get(events_stream))
        .route("/metrics", get(metrics_text))
        .with_state(state)
}

/// Takes an already-bound listener (bind failures must fail startup loudly in
/// `main`, not silently kill only this background task — see `plugins.sock`).
pub async fn serve(d: Arc<Daemon>, config_path: PathBuf, listener: tokio::net::UnixListener) {
    axum::serve(listener, router(d, config_path)).await.expect("admin serve");
}

fn queue_map(d: &Daemon) -> BTreeMap<String, i64> {
    d.store.lock().unwrap().queue_counts().unwrap_or_default().into_iter().collect()
}

/// Cfg is read (and dropped) BEFORE `plugins` is locked -- consistent lock
/// order (cfg never held across another Daemon lock acquisition) matters
/// more than which order is chosen, but "cfg first" is what every other
/// call site in this module follows too.
fn plugin_state(d: &Daemon) -> Vec<(String, bool)> {
    let enabled_names: Vec<String> = d.cfg_snapshot(|c| {
        c.plugins.iter().filter(|(_, p)| p.enabled).map(|(name, _)| name.clone()).collect()
    });
    let connected = d.plugins.lock().unwrap();
    enabled_names.into_iter()
        .map(|name| {
            let up = connected.get(&name).map(|h| h.connected).unwrap_or(false);
            (name, up)
        })
        .collect()
}

async fn status(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let plugins: BTreeMap<_, _> = plugin_state(&d).into_iter().collect();
    let (node_name, public) = d.cfg_snapshot(|c| (c.node.name.clone(), c.node.public));
    Json(json!({
        "node": node_name,
        "node_id": d.node_id,
        "public": public,
        "plugins": plugins,
        "queue": queue_map(&d),
    }))
}

/// spec §112.3: which services this node exposes publicly, and their
/// ingress/egress protocol coverage — the WebUI (and, later, RFDP
/// discovery) read this rather than parsing the raw config.
async fn public(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let (public, services) = d.cfg_snapshot(|c| {
        let services: Vec<_> = c.public_services.iter().map(|s| json!({
            "name": s.name,
            "type": s.r#type,
            "ingress": s.ingress,
            "egress": s.egress,
        })).collect();
        (c.node.public, services)
    });
    Json(json!({ "public": public, "services": services }))
}

/// Configured quotas and transport budgets (spec §112.8/§45/§79) — a config
/// echo, not live counter state: an operator diagnosing "why is this
/// getting rate-limited" starts from what's configured, and the in-memory
/// limiter windows aren't worth exposing (they reset on restart and aren't
/// meaningful without matching request context anyway).
async fn limits(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    Json(d.cfg_snapshot(|c| {
        let transport_budgets: BTreeMap<_, _> = c.transport_budgets.iter()
            .map(|(proto, b)| (proto.clone(), json!({ "messages_per_minute": b.messages_per_minute })))
            .collect();
        json!({
            "per_sender": {
                "messages_per_minute": c.limits.per_sender.messages_per_minute,
                "bytes_per_hour": c.limits.per_sender.bytes_per_hour,
            },
            "per_route": {
                "queue_max": c.limits.per_route.queue_max,
            },
            "global": {
                "queue_max": c.limits.global.queue_max,
                "cas_max_bytes": c.limits.global.cas_max_bytes,
            },
            "transport_budgets": transport_budgets,
        })
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
async fn plugins(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let enabled_names: Vec<String> = d.cfg_snapshot(|c| {
        c.plugins.iter().filter(|(_, p)| p.enabled).map(|(name, _)| name.clone()).collect()
    });
    let states: Vec<(String, bool, Option<serde_json::Value>)> = {
        let handles = d.plugins.lock().unwrap();
        enabled_names.into_iter()
            .map(|name| {
                let h = handles.get(&name);
                let connected = h.map(|h| h.connected).unwrap_or(false);
                let capabilities = h.map(|h| serde_json::to_value(&h.capabilities).unwrap());
                (name, connected, capabilities)
            })
            .collect()
    };
    let now = std::time::Instant::now();
    let out: BTreeMap<String, serde_json::Value> = states.into_iter()
        .map(|(name, connected, capabilities)| {
            let gauges: BTreeMap<String, serde_json::Value> = d.gauges.for_plugin(&name, now)
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
    let dest_protocols: std::collections::BTreeSet<&str> =
        route.destinations.iter().map(|e| e.protocol.as_str()).collect();
    policies.iter()
        .filter(|p| {
            p.r#match.destination_protocol.is_empty()
                || p.r#match.destination_protocol.iter()
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
async fn routes(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    Json(json!({
        "routes": d.cfg_snapshot(|c| {
            c.routes.iter().map(|r| json!({
                "name": r.name,
                "sources": r.sources.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
                "destinations": r.destinations.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
                "identity_mode": r.identity_mode,
                "render": { "tag": r.render.tag, "max_chars": r.render.max_chars },
                "policies": policies_for_route(r, &c.policies),
            })).collect::<Vec<_>>()
        })
    }))
}

/// `GET /v1/config` (design §2): the loaded config as YAML text, secrets
/// UNRESOLVED. Serves `Config.raw_yaml` byte-verbatim -- that field is
/// captured straight from the loaded file's text, before parsing/
/// resolution touch anything, and is never mutated except by
/// `apply_config` storing a newly-applied config's own raw text -- so
/// byte-fidelity to whatever's actually loaded and zero secret exposure
/// both fall out of "just don't re-serialize anything".
async fn config_yaml(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let yaml = d.cfg_snapshot(|c| c.raw_yaml.clone());
    (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "text/yaml")], yaml)
}

/// `<path>.prev` — the single-revision history slot `PUT`/`rollback` swap
/// into and out of (design §3: "one-revision history", not a stack).
fn prev_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".prev");
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
/// succeeded does it touch `path`/`.prev` at all: renames whatever is
/// currently at `path` to `<path>.prev` (overwriting any older `.prev` —
/// one revision, not a stack), then renames the tmp file into place at
/// `path`. A failure during the write leaves `path` and `.prev`
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
    // Both renames run back-to-back with nothing fallible between them, so
    // the only crash window where `path` is transiently absent is the gap
    // between two same-directory rename() calls. The chmods run after both
    // renames: a chmod failure then leaves complete files at final names.
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
    std::str::from_utf8(body).map_err(|_| (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"valid": false, "errors": ["request body is not valid UTF-8"]})),
    ))
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
async fn config_validate(body: Bytes) -> impl IntoResponse {
    let text = match decode_body_or_422(&body) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    match crate::config::load_from_str(text) {
        Ok(_) => (StatusCode::OK, Json(json!({"valid": true}))),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"valid": false, "errors": [e]}))),
    }
}

/// `PUT /v1/config` (design §3): validates the POSTed YAML text first (422,
/// zero filesystem changes, on failure — same pipeline as
/// `config_validate`), then, holding `write_lock` for the rest of the
/// handler (serialized against a racing `config_rollback`), replaces the
/// on-disk config file (`write_config_replacing_current`) and calls
/// `apply_config` (which itself serializes against ANY other `apply_config`
/// caller via its own `apply_lock` — see that method's doc comment).
async fn config_put(State(state): State<AdminState>, body: Bytes) -> impl IntoResponse {
    let text = match decode_body_or_422(&body) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let new_cfg = match crate::config::load_from_str(text) {
        Ok(cfg) => cfg,
        Err(e) => {
            return (StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"valid": false, "errors": [e]})));
        }
    };
    let _write_guard = state.write_lock.lock().unwrap();
    if let Err(e) = write_config_replacing_current(&state.config_path, text) {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to write config file: {e}")})));
    }
    let outcome = state.daemon.apply_config(new_cfg);
    (StatusCode::OK, Json(json!({"applied": true, "restart_required": outcome.restart_required})))
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
async fn config_rollback(State(state): State<AdminState>) -> impl IntoResponse {
    let prev_path = prev_path_for(&state.config_path);
    let _write_guard = state.write_lock.lock().unwrap();
    if !prev_path.exists() {
        return (StatusCode::NOT_FOUND,
            Json(json!({"error": "no previous config to roll back to"})));
    }
    let prev_text = match std::fs::read_to_string(&prev_path) {
        Ok(t) => t,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("failed to read previous config: {e}")})));
        }
    };
    let new_cfg = match crate::config::load_from_str(&prev_text) {
        Ok(cfg) => cfg,
        Err(e) => return (StatusCode::CONFLICT, Json(json!({"errors": [e]}))),
    };
    if let Err(e) = swap_with_prev(&state.config_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("failed to swap config files: {e}")})));
    }
    let outcome = state.daemon.apply_config(new_cfg);
    (StatusCode::OK, Json(json!({"applied": true, "restart_required": outcome.restart_required})))
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
async fn queue(State(d): State<Arc<Daemon>>, Query(params): Query<QueueParams>) -> impl IntoResponse {
    let Some(state) = params.state else {
        return Json(queue_map(&d)).into_response();
    };
    let limit = params.limit.unwrap_or(100).clamp(1, 1000) as i64;
    let deliveries = d.store.lock().unwrap().list_deliveries(Some(&state), limit).unwrap_or_default();
    let out: Vec<_> = deliveries.iter().map(|del| {
        let destination = if del.route == IDENTITY_ROUTE {
            format!("{}:{}", del.destination.protocol,
                identity_links::mask_ref(&del.destination.endpoint))
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
    }).collect();
    Json(json!({ "deliveries": out })).into_response()
}

async fn trace(
    State(d): State<Arc<Daemon>>,
    AxPath(id): AxPath<Uuid>,
) -> impl IntoResponse {
    let store = d.store.lock().unwrap();
    let Ok(Some(env)) = store.get_message(id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown message"})));
    };
    // spec §Security invariants: refs masked in every API response, full
    // refs never in GET responses. Ordinary routes' `destination` is a route
    // endpoint (e.g. "mockb:chan"), not an identity ref, so it renders in
    // full as before; `@identity` deliveries carry the target's RAW native
    // ref verbatim in `dest_endpoint` (see `enqueue_identity_send`), so those
    // must use the same masked "protocol:masked_ref" compound form (RULING
    // 2) as `/v1/identities` and `/v1/identities/challenges`.
    let deliveries: Vec<_> = store.deliveries_for(id).unwrap_or_default().iter()
        .map(|del| {
            let destination = if del.route == IDENTITY_ROUTE {
                format!("{}:{}", del.destination.protocol,
                    identity_links::mask_ref(&del.destination.endpoint))
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
    (StatusCode::OK, Json(json!({
        "id": env.id,
        "source": env.source.to_string(),
        "kind": env.kind,
        "created_at": env.created_at,
        "received_at": env.received_at,
        "expires_at": env.expires_at,
        "body_bytes": env.body.len(),
        "deliveries": deliveries,
    })))
}

async fn metrics_text(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let q = d.store.lock().unwrap().queue_counts().unwrap_or_default();
    metrics::render(&q, &plugin_state(&d), &d.gauges)
}

/// `GET /v1/identities` (design §Admin API / webui-notes): masked refs in
/// every response — protocol stays visible, only the ref is masked
/// (RULING 2's compound convention), full refs never leave this module.
async fn identities(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let links = d.store.lock().unwrap().list_links().unwrap_or_default();
    let out: Vec<_> = links.iter().map(|l| json!({
        "id": l.id,
        "a": format!("{}:{}", l.a_protocol, identity_links::mask_ref(&l.a_ref)),
        "b": format!("{}:{}", l.b_protocol, identity_links::mask_ref(&l.b_ref)),
        "display_name": l.display_name,
        "verified_at": l.verified_at,
    })).collect();
    Json(json!({ "links": out }))
}

#[derive(Deserialize)]
struct LinkRequest {
    requester: String,
    target: String,
    display_name: String,
}

/// `POST /v1/identities/link` (design §Admin API): 202 with a challenge id
/// on success; 400 on a malformed body or an unparsable "proto:ref"; 409 on
/// `engine::initiate_link`'s rejection — either the target plugin isn't
/// direct-capable (naming which connected plugins are) or the global queue
/// is full (RULING 1). Parsing is done by hand against raw `Bytes` rather
/// than axum's `Json` extractor so every parse failure maps to exactly 400,
/// not axum's default 415 (bad content-type) / 422 (well-formed JSON, wrong
/// shape) split.
async fn create_link(State(d): State<Arc<Daemon>>, body: Bytes) -> impl IntoResponse {
    let req: LinkRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid request body: {e}")})));
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
        Ok(challenge_id) => (StatusCode::ACCEPTED, Json(json!({"challenge_id": challenge_id}))),
        Err(e) => (StatusCode::CONFLICT, Json(json!({"error": e}))),
    }
}

/// `DELETE /v1/identities/link/{id}` (design §Admin API / §22): 204 on
/// success, 404 if no such link. §95's "unlink reverts aliases to
/// pseudonyms immediately" regression is exercised at the rendering layer in
/// engine.rs (rendering reads links live) — this endpoint just removes the
/// row.
async fn delete_link(State(d): State<Arc<Daemon>>, AxPath(id): AxPath<i64>) -> impl IntoResponse {
    let deleted = match d.store.lock().unwrap().delete_link(id) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, id, "failed to delete identity link");
            false
        }
    };
    if deleted { StatusCode::NO_CONTENT } else { StatusCode::NOT_FOUND }
}

/// `GET /v1/identities/challenges` (design §Admin API): pending count plus
/// masked targets and expiry — codes never leave `storage::Challenge`
/// (design §Security invariants); this handler never reads the `code`
/// field.
async fn challenges(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let now = Utc::now();
    let list = d.store.lock().unwrap().list_challenges(now).unwrap_or_default();
    let out: Vec<_> = list.iter().map(|c| json!({
        "id": c.id,
        "target": format!("{}:{}", c.target_protocol, identity_links::mask_ref(&c.target_ref)),
        "expires_at": c.expires_at,
    })).collect();
    Json(json!({ "pending_count": out.len(), "challenges": out }))
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
fn events_stream_from(rx: broadcast::Receiver<Event>) -> impl Stream<Item = Result<SseEvent, Infallible>> {
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
async fn events_stream(
    State(d): State<Arc<Daemon>>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    Sse::new(events_stream_from(d.events.subscribe())).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{handle_inbound, Daemon};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

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
    async fn req(router: axum::Router, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
        let mut builder = Request::builder().method(method).uri(path);
        let request_body = match body {
            Some(b) => {
                builder = builder.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let resp = router.oneshot(builder.body(request_body).unwrap()).await.unwrap();
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
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        let (code, body) = get(router(d), "/v1/status").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"node\":\"t\""));
        assert!(body.contains("\"node_id\":\"rf:"));
        assert!(body.contains("\"pending\":1"));
        assert!(body.contains("\"public\":false"), "status was: {body}");
    }

    fn daemon_with_public(public: bool, services: Vec<crate::config::PublicService>) -> Arc<Daemon> {
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
    async fn public_endpoint_reports_disabled_and_no_services_by_default() {
        let d = daemon_with_public(false, vec![]);
        let (code, body) = get(router(d), "/v1/public").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"public\":false"), "body was: {body}");
        assert!(body.contains("\"services\":[]"), "body was: {body}");
    }

    #[tokio::test]
    async fn public_endpoint_reports_configured_services() {
        let d = daemon_with_public(true, vec![crate::config::PublicService {
            name: "regional-chat".into(),
            r#type: "chat".into(),
            ingress: vec!["mocka".into()],
            egress: vec!["mockb".into()],
        }]);
        let (code, body) = get(router(d), "/v1/public").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"public\":true"), "body was: {body}");
        assert!(body.contains("\"name\":\"regional-chat\""), "body was: {body}");
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
        assert!(body.contains("\"messages_per_minute\":0"), "body was: {body}");
        assert!(body.contains("\"bytes_per_hour\":0"), "body was: {body}");
        assert!(body.contains("\"queue_max\":0"), "body was: {body}");
        assert!(body.contains("\"cas_max_bytes\":0"), "body was: {body}");
        assert!(body.contains("\"transport_budgets\":{}"), "body was: {body}");
    }

    #[tokio::test]
    async fn limits_endpoint_echoes_nonzero_limits_and_transport_budgets() {
        let dir = tempfile::tempdir().unwrap();
        let d = crate::engine::tests_support::test_daemon_with_limits(dir.path(), crate::config::Limits {
            per_sender: crate::config::PerSender { messages_per_minute: 10, bytes_per_hour: 50_000 },
            per_route: crate::config::PerRoute { queue_max: 5_000 },
            global: crate::config::GlobalLimits { queue_max: 50_000, cas_max_bytes: 1_000_000_000 },
        });
        std::mem::forget(dir);
        let (code, body) = get(router(Arc::new(d)), "/v1/limits").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"messages_per_minute\":10"), "body was: {body}");
        assert!(body.contains("\"bytes_per_hour\":50000"), "body was: {body}");
        assert!(body.contains("\"queue_max\":5000"), "body was: {body}");
        assert!(body.contains("\"queue_max\":50000"), "body was: {body}");
        assert!(body.contains("\"cas_max_bytes\":1000000000"), "body was: {body}");

        let dir2 = tempfile::tempdir().unwrap();
        let mut budgets = std::collections::BTreeMap::new();
        budgets.insert("mockb".to_string(), crate::config::Budget { messages_per_minute: 30 });
        let d2 = crate::engine::tests_support::test_daemon_with_budgets(dir2.path(), budgets);
        std::mem::forget(dir2);
        let (code, body) = get(router(Arc::new(d2)), "/v1/limits").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"transport_budgets\":{\"mockb\":{\"messages_per_minute\":30}}"),
            "body was: {body}");
    }

    #[tokio::test]
    async fn trace_omits_body_and_404s_unknown() {
        let d = daemon();
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "secret-content".into(), None, vec![], None);
        let id = d.store.lock().unwrap()
            .due_deliveries(chrono::Utc::now(), 1).unwrap()[0].message_id;
        let (code, body) = get(router(d.clone()), &format!("/v1/messages/{id}")).await;
        assert_eq!(code, 200);
        assert!(!body.contains("secret-content"), "trace leaked message body");
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
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "urgent-ish".into(), None, vec![], Some("high".into()));
        let id = d.store.lock().unwrap()
            .due_deliveries(chrono::Utc::now(), 1).unwrap()[0].message_id;
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
    async fn trace_masks_identity_route_destination_but_renders_ordinary_route_destination_in_full() {
        let d = daemon();
        let _rx = crate::engine::tests_support::register_direct_plugin(&d, "mockb");
        let requester: Endpoint = "mocka:!alice-secret".parse().unwrap();
        let target: Endpoint = "mockb:+14155551234".parse().unwrap();
        engine::initiate_link(&d, requester, target, "Jascha").unwrap();

        let identity_message_id = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(Utc::now(), 10).unwrap().into_iter()
                .find(|de| de.route == crate::config::IDENTITY_ROUTE)
                .expect("challenge delivery must be queued on the @identity route")
                .message_id
        };
        let (code, body) = get(router(d.clone()), &format!("/v1/messages/{identity_message_id}")).await;
        assert_eq!(code, 200);
        assert!(!body.contains("+14155551234"), "full target ref leaked in trace: {body}");
        assert!(body.contains("\"destination\":\"mockb:+1****1234\""),
            "masked destination missing: {body}");

        // an ordinary route's destination is a route endpoint, not an
        // identity ref, and must still render in full (existing behavior).
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        let ordinary_message_id = d.store.lock().unwrap()
            .due_deliveries(Utc::now(), 10).unwrap().into_iter()
            .find(|de| de.route != crate::config::IDENTITY_ROUTE)
            .expect("ordinary delivery must exist")
            .message_id;
        let (code2, body2) = get(router(d), &format!("/v1/messages/{ordinary_message_id}")).await;
        assert_eq!(code2, 200);
        assert!(body2.contains("\"destination\":\"mockb:chan\""),
            "ordinary route destination must still render in full: {body2}");
    }

    /// Finding 2 (whole-branch review, goal gate): omitting `?state=` must
    /// keep returning the pre-existing `{route: count}` aggregate shape
    /// verbatim -- the listing behavior below is opt-in only, not a breaking
    /// change to the endpoint every caller already uses.
    #[tokio::test]
    async fn queue_without_state_param_returns_aggregate_counts_shape_unchanged() {
        let d = daemon();
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        let (code, body) = get(router(d), "/v1/queue").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"pending\":1"), "body was: {body}");
        assert!(!body.contains("\"deliveries\""),
            "omitting ?state= must keep the pre-existing aggregate-counts shape: {body}");
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
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       SENTINEL_BODY.into(), None, vec![], None);
        let id_a = {
            let store = d.store.lock().unwrap();
            let id = store.due_deliveries(Utc::now(), 10).unwrap()[0].id;
            store.mark_terminal(id, "dead_letter", "POLICY_DENIED").unwrap();
            id
        };

        // an @identity-route row with a KNOWN target ref, inserted after
        // `id_a` above -- the higher id, so it's the "newest" row.
        let requester: Endpoint = "mocka:!req".parse().unwrap();
        let target: Endpoint = "mockb:+14155551234".parse().unwrap();
        engine::initiate_link(&d, requester, target, "Jascha").unwrap();
        let id_identity = {
            let store = d.store.lock().unwrap();
            let del = store.due_deliveries(Utc::now(), 10).unwrap().into_iter()
                .find(|de| de.route == IDENTITY_ROUTE)
                .expect("identity challenge delivery must be queued");
            store.mark_terminal(del.id, "dead_letter", "QUEUE_FULL").unwrap();
            del.id
        };
        assert!(id_identity > id_a, "identity delivery must be the newer row");

        // limit=1 must clamp to exactly the newest row.
        let (code, body) = get(router(d.clone()), "/v1/queue?state=dead_letter&limit=1").await;
        assert_eq!(code, 200);
        assert!(!body.contains(SENTINEL_BODY), "queue listing must never include message content: {body}");
        assert!(!body.contains("+14155551234"), "full target ref leaked: {body}");
        assert!(body.contains("\"destination\":\"mockb:+1****1234\""),
            "masked identity-route destination missing: {body}");
        assert!(body.contains("\"reason\":\"QUEUE_FULL\""), "body was: {body}");
        assert_eq!(body.matches("\"message_id\"").count(), 1,
            "limit=1 must clamp to exactly one row: {body}");

        // default limit returns both, newest (identity row) first.
        let (code2, body2) = get(router(d.clone()), "/v1/queue?state=dead_letter").await;
        assert_eq!(code2, 200);
        assert_eq!(body2.matches("\"message_id\"").count(), 2,
            "default limit must return both dead_letter rows: {body2}");
        let idx_identity = body2.find("QUEUE_FULL").expect("QUEUE_FULL reason missing");
        let idx_a = body2.find("POLICY_DENIED").expect("POLICY_DENIED reason missing");
        assert!(idx_identity < idx_a,
            "newest (highest id) dead_letter row must come first: {body2}");

        // out-of-range limits clamp rather than error: 0 -> 1, 5000 -> 1000.
        let (code3, body3) =
            get(router(d.clone()), "/v1/queue?state=dead_letter&limit=0").await;
        assert_eq!(code3, 200);
        assert_eq!(body3.matches("\"message_id\"").count(), 1,
            "limit=0 must clamp up to one row: {body3}");
        let (code4, body4) =
            get(router(d), "/v1/queue?state=dead_letter&limit=5000").await;
        assert_eq!(code4, 200);
        assert_eq!(body4.matches("\"message_id\"").count(), 2,
            "limit=5000 must clamp to 1000 and return all rows: {body4}");
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
        assert!(body.starts_with("{\"routes\":["), "response must be wrapped in a routes object: {body}");
        assert!(body.contains("\"name\":\"general\""), "body was: {body}");
        assert!(body.contains("\"identity_mode\":\"pseudonymous\""), "body was: {body}");
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
    async fn routes_endpoint_lists_only_policies_whose_match_intersects_route_destination_protocols() {
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
        assert!(body.contains("\"identity_mode\":\"linked\""), "body was: {body}");
        assert!(body.contains("\"tag\":\"none\""), "body was: {body}");
        assert!(body.contains("\"max_chars\":40"), "body was: {body}");
        assert!(body.contains("\"policies\":[\"mockb-policy\",\"catch-all-policy\"]"),
            "matching policies (in declared order) missing or wrong: {body}");
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
        assert!(body.contains("\"value\":-71.5"), "gauge value missing: {body}");
        assert!(body.contains("\"age_secs\":0"), "gauge age missing: {body}");
        // mockb is enabled (test_daemon's fixture) but never reported gauges.
        assert!(body.contains("\"mockb\":{\"capabilities\":null,\"connected\":false,\"gauges\":{}}"),
            "mockb must report an empty gauges object: {body}");
    }

    /// `GET /v1/config` (design §2): serves `Config.raw_yaml` byte-verbatim
    /// with `Content-Type: text/yaml` -- secrets stay in their unresolved
    /// `${...}` form since resolution never touches `raw_yaml` at all.
    #[tokio::test]
    async fn config_endpoint_serves_raw_yaml_verbatim_with_text_yaml_content_type() {
        let sentinel = "sentinel-config-yaml-leak-1a2b";
        let d = daemon_with_plugin_secret("RF_ADMIN_TEST_SECRET_CONFIG_YAML", sentinel);
        let expected_yaml = d.cfg_snapshot(|c| c.raw_yaml.clone());
        assert!(!expected_yaml.is_empty(), "test fixture sanity: raw_yaml must be populated");

        let resp = router(d)
            .oneshot(Request::builder().uri("/v1/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
            "text/yaml",
            "wrong content-type"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8_lossy(&body);
        assert_eq!(body_str, expected_yaml, "raw yaml not served byte-verbatim");
        assert!(body_str.contains("${env:RF_ADMIN_TEST_SECRET_CONFIG_YAML}"),
            "unresolved reference form must be present: {body_str}");
        assert!(!body_str.contains(sentinel), "resolved secret leaked in /v1/config: {body_str}");
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
        let id = d.store.lock().unwrap().insert_link(
            "signal", "+14155551234", "lxmf", "aabbccddeeff", "Jascha", now,
        ).unwrap();

        let (code, body) = get(router(d), "/v1/identities").await;
        assert_eq!(code, 200);
        assert!(!body.contains("+14155551234"), "full requester ref leaked: {body}");
        assert!(!body.contains("aabbccddeeff"), "full target ref leaked: {body}");
        assert!(body.contains("\"a\":\"signal:+1****1234\""), "masked a-side missing: {body}");
        assert!(body.contains("\"b\":\"lxmf:aa****eeff\""), "masked b-side missing: {body}");
        assert!(body.contains(&format!("\"id\":{id}")), "body was: {body}");
        assert!(body.contains("\"display_name\":\"Jascha\""), "body was: {body}");
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
        }).to_string();

        let (code, resp_body) = req(router(d), "POST", "/v1/identities/link", Some(&body)).await;
        assert_eq!(code, 202, "body was: {resp_body}");
        assert!(resp_body.contains("\"challenge_id\""), "body was: {resp_body}");
        assert!(!resp_body.contains("!alice-secret"),
            "the requester's full ref must never leak in the response: {resp_body}");
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
        }).to_string();

        let (code, resp_body) = req(router(d), "POST", "/v1/identities/link", Some(&body)).await;
        assert_eq!(code, 409, "body was: {resp_body}");
        assert!(resp_body.contains("mocka"),
            "409 body must name the direct-capable plugin: {resp_body}");
        assert!(!resp_body.contains("target-secret"),
            "target ref must never leak in the 409 body: {resp_body}");
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
        let d = crate::engine::tests_support::test_daemon_with_limits(dir.path(), crate::config::Limits {
            global: crate::config::GlobalLimits { queue_max: 1, ..Default::default() },
            ..Default::default()
        });
        std::mem::forget(dir);
        let d = Arc::new(d);
        let _rx = crate::engine::tests_support::register_direct_plugin(&d, "mockb");

        // saturate the global queue with an ordinary routed message first.
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);

        let body = serde_json::json!({
            "requester": "mocka:!req",
            "target": "mockb:!target-secret",
            "display_name": "X",
        }).to_string();
        let (code, resp_body) = req(router(d), "POST", "/v1/identities/link", Some(&body)).await;
        assert_eq!(code, 409, "body was: {resp_body}");
        assert!(resp_body.contains("queue full"), "409 body must be distinguishable as queue-full: {resp_body}");
        assert!(!resp_body.contains("target-secret"), "target ref must never leak in the 409 body: {resp_body}");
    }

    #[tokio::test]
    async fn post_identities_link_returns_400_on_malformed_json() {
        let (code, _) = req(router(daemon()), "POST", "/v1/identities/link", Some("not json")).await;
        assert_eq!(code, 400);
    }

    #[tokio::test]
    async fn post_identities_link_returns_400_on_unparsable_endpoint() {
        let body = serde_json::json!({
            "requester": "not-a-valid-endpoint",
            "target": "mocka:!b",
            "display_name": "X",
        }).to_string();
        let (code, _) = req(router(daemon()), "POST", "/v1/identities/link", Some(&body)).await;
        assert_eq!(code, 400);
    }

    #[tokio::test]
    async fn delete_identities_link_returns_204_then_404() {
        let d = daemon();
        let now = Utc::now();
        let id = d.store.lock().unwrap()
            .insert_link("signal", "+1234567890", "lxmf", "abc123", "X", now).unwrap();

        let (code, _) = req(router(d.clone()), "DELETE", &format!("/v1/identities/link/{id}"), None).await;
        assert_eq!(code, 204);

        let (code2, _) = req(router(d), "DELETE", &format!("/v1/identities/link/{id}"), None).await;
        assert_eq!(code2, 404);
    }

    /// Masking regression (challenges variant): the code must never appear
    /// in the response, and the masked target must.
    #[tokio::test]
    async fn challenges_lists_masked_targets_and_never_leaks_code_or_full_ref() {
        let d = daemon();
        let now = Utc::now();
        let expires = now + chrono::Duration::minutes(15);
        d.store.lock().unwrap().create_challenge(
            "424242", "signal", "+14155551234", "lxmf", "abc123def456", "Jascha", now, expires,
        ).unwrap();

        let (code, body) = get(router(d), "/v1/identities/challenges").await;
        assert_eq!(code, 200);
        assert!(!body.contains("424242"), "code leaked: {body}");
        assert!(!body.contains("+14155551234"), "full target ref leaked: {body}");
        assert!(body.contains("\"target\":\"signal:+1****1234\""), "masked target missing: {body}");
        assert!(body.contains("\"pending_count\":1"), "body was: {body}");
    }

    #[tokio::test]
    async fn challenges_empty_by_default() {
        let (code, body) = get(router(daemon()), "/v1/identities/challenges").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"pending_count\":0"), "body was: {body}");
        assert!(body.contains("\"challenges\":[]"), "body was: {body}");
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
            cfg.plugins["mocka"].config.get("token").unwrap().as_str().unwrap(),
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
            assert!(!body.contains(sentinel), "resolved secret leaked from {path}: {body}");
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
        let (code, body) =
            req(super::router(d, cfg_path), "POST", "/v1/config/validate", Some(&good_yaml)).await;
        assert_eq!(code, 200, "body was: {body}");
        assert_eq!(body, "{\"valid\":true}", "body was: {body}");
    }

    #[tokio::test]
    async fn config_validate_returns_422_with_errors_for_unparsable_yaml() {
        let (d, cfg_path) = daemon_with_config_file();
        let bad_yaml = "node: [unterminated";
        let (code, body) =
            req(super::router(d, cfg_path), "POST", "/v1/config/validate", Some(bad_yaml)).await;
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
        let (code, body) =
            req(super::router(d, cfg_path), "POST", "/v1/config/validate", Some(&yaml)).await;
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
        let (code, body) =
            req(super::router(d, cfg_path), "POST", "/v1/config/validate", Some(&yaml)).await;
        assert_eq!(code, 422, "body was: {body}");
        assert!(body.contains("env:RF_ADMIN_TEST_VALIDATE_UNSET_VAR"),
            "error must name the reference form: {body}");
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
    async fn config_validate_returns_422_with_neither_sentinel_nor_resolved_value_when_validation_fails_for_an_unrelated_reason() {
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

        let (code, body) =
            req(super::router(d, cfg_path), "POST", "/v1/config/validate", Some(&yaml)).await;
        std::env::remove_var(var);

        assert_eq!(code, 422, "body was: {body}");
        assert!(body.contains("\"valid\":false"), "body was: {body}");
        assert!(body.contains("reserved"), "error must name the actual validate()-level cause: {body}");
        assert!(!body.contains(sentinel),
            "resolved secret leaked despite an unrelated validate() failure: {body}");
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

        let (code, body) =
            req(super::router(d.clone(), cfg_path.clone()), "PUT", "/v1/config", Some(&new_yaml)).await;
        assert_eq!(code, 200, "body was: {body}");
        assert!(body.contains("\"applied\":true"), "body was: {body}");
        assert!(body.contains("\"mockc\""), "restart_required must name the added plugin: {body}");

        // file-state matrix: current holds the new content verbatim, .prev
        // holds the pre-PUT content verbatim, no leftover tmp artifact.
        let current = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(current, new_yaml, "current config file must hold the new content verbatim");
        let prev = std::fs::read_to_string(super::prev_path_for(&cfg_path)).unwrap();
        assert_eq!(prev, original_text, ".prev must hold the pre-PUT content verbatim");
        assert!(!super::tmp_path_for(&cfg_path).exists(),
            "no tmp artifact must remain after a successful PUT");

        // 0600 on the newly-written current file (design §3 / alias.rs precedent).
        let mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "current config file must be 0600");

        // Fix round 1 (Critical): `.prev` must ALSO be forced to 0600, not
        // left at whatever mode the pre-PUT file had (`daemon_with_config_file`
        // deliberately starts it at 644 so this assertion actually exercises
        // the fix rather than passing by coincidence).
        let prev_mode = std::fs::metadata(super::prev_path_for(&cfg_path)).unwrap().permissions().mode();
        assert_eq!(prev_mode & 0o777, 0o600, ".prev must be 0600, not inherited from the 644 original");

        // daemon state actually applied: GET /v1/config would now serve the new text.
        assert_eq!(d.cfg_snapshot(|c| c.raw_yaml.clone()), new_yaml);
    }

    #[tokio::test]
    async fn config_put_returns_422_and_makes_no_changes_for_invalid_yaml() {
        let (d, cfg_path) = daemon_with_config_file();
        let original_text = std::fs::read_to_string(&cfg_path).unwrap();
        let bad_yaml = "node: [unterminated";

        let (code, body) =
            req(super::router(d.clone(), cfg_path.clone()), "PUT", "/v1/config", Some(bad_yaml)).await;
        assert_eq!(code, 422, "body was: {body}");
        assert!(body.contains("\"valid\":false"), "body was: {body}");

        let current = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(current, original_text, "an invalid PUT must not touch the config file");
        assert!(!super::prev_path_for(&cfg_path).exists(),
            "an invalid PUT must not create .prev");
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

        let (code, body) =
            req(super::router(d.clone(), cfg_path.clone()), "PUT", "/v1/config", Some(&new_yaml)).await;

        assert_eq!(code, 500, "body was: {body}");
        let current = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(current, original_text, "a write failure must leave the config file untouched");
        assert!(!super::prev_path_for(&cfg_path).exists(), "a write failure must never create .prev");
    }

    /// Fix round 1 (Minor) — admin-layer restart_required matrix: proves
    /// `apply_config`'s diff behaves correctly THROUGH the real `PUT
    /// /v1/config` handler, not just via engine.rs's own unit tests that
    /// call `apply_config` directly. (a) a plugin config-block-only change
    /// must name that plugin, and only that plugin. (b) from that new
    /// baseline, a route-only change (render knobs) must report an EMPTY
    /// restart_required.
    #[tokio::test]
    async fn config_put_restart_required_names_a_plugin_config_change_and_is_empty_for_a_route_only_change() {
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
            super::router(d.clone(), cfg_path.clone()), "PUT", "/v1/config", Some(&plugin_config_changed),
        ).await;
        assert_eq!(code1, 200, "body was: {body1}");
        assert_eq!(body1, "{\"applied\":true,\"restart_required\":[\"mocka\"]}",
            "only the plugin whose config block changed must be named: {body1}");

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
            super::router(d.clone(), cfg_path.clone()), "PUT", "/v1/config", Some(&route_only_changed),
        ).await;
        assert_eq!(code2, 200, "body was: {body2}");
        assert_eq!(body2, "{\"applied\":true,\"restart_required\":[]}",
            "a route-only change must never require a restart: {body2}");
    }

    #[tokio::test]
    async fn config_rollback_returns_404_when_no_prev_exists() {
        let (d, cfg_path) = daemon_with_config_file();
        let (code, body) =
            req(super::router(d, cfg_path), "POST", "/v1/config/rollback", None).await;
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

        let (put_code, put_body) =
            req(super::router(d.clone(), cfg_path.clone()), "PUT", "/v1/config", Some(&new_yaml)).await;
        assert_eq!(put_code, 200, "seeding PUT failed: {put_body}");

        // Fix round 1 (Critical): force `.prev` back to 644 right before the
        // rollback -- simulating a `.prev` that landed at a non-0600 mode by
        // some other path (an older daemon, a manual copy, ...) -- so the
        // post-rollback 0600 assertion below actually exercises
        // `swap_with_prev`'s chmod rather than passing because the file
        // happened to already be 0600 from the seeding PUT.
        std::fs::set_permissions(super::prev_path_for(&cfg_path), std::fs::Permissions::from_mode(0o644))
            .unwrap();

        let (code, body) =
            req(super::router(d.clone(), cfg_path.clone()), "POST", "/v1/config/rollback", None).await;
        assert_eq!(code, 200, "body was: {body}");
        assert!(body.contains("\"applied\":true"), "body was: {body}");

        let current = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(current, original_text, "current file must hold the rolled-back content");
        let prev = std::fs::read_to_string(super::prev_path_for(&cfg_path)).unwrap();
        assert_eq!(prev, new_yaml, ".prev must now hold what was current before the rollback");

        // Fix round 1 (Critical): the live config path after a rollback must
        // be 0600, even though the `.prev` it was just swapped in from was
        // deliberately left at 644 above.
        let live_mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode();
        assert_eq!(live_mode & 0o777, 0o600,
            "live config path must be 0600 after rollback, not inherited from .prev's 644");

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
        let (seed1_code, seed1_body) =
            req(super::router(d.clone(), cfg_path.clone()), "PUT", "/v1/config", Some(&secret_yaml)).await;
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
        let (seed2_code, seed2_body) =
            req(super::router(d.clone(), cfg_path.clone()), "PUT", "/v1/config", Some(&plain_yaml)).await;
        assert_eq!(seed2_code, 200, "seeding PUT 2 failed: {seed2_body}");

        let current_before = std::fs::read_to_string(&cfg_path).unwrap();
        let prev_before = std::fs::read_to_string(super::prev_path_for(&cfg_path)).unwrap();
        assert_eq!(current_before, plain_yaml, "test fixture sanity: current must be plain_yaml");
        assert_eq!(prev_before, secret_yaml, "test fixture sanity: .prev must be secret_yaml");

        std::env::remove_var(var);

        let (code, body) =
            req(super::router(d.clone(), cfg_path.clone()), "POST", "/v1/config/rollback", None).await;
        assert_eq!(code, 409, "body was: {body}");
        assert!(body.contains("\"errors\""), "body was: {body}");
        assert!(body.contains(&format!("env:{var}")), "error must name the reference form: {body}");
        assert!(!body.contains("sentinel-rollback-drift-value"), "resolved secret leaked: {body}");

        let current_after = std::fs::read_to_string(&cfg_path).unwrap();
        assert_eq!(current_after, current_before, "current file must be untouched after a 409");
        let prev_after = std::fs::read_to_string(super::prev_path_for(&cfg_path)).unwrap();
        assert_eq!(prev_after, prev_before, ".prev must be untouched after a 409");
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
            super::router(d.clone(), cfg_path.clone()), "POST", "/v1/config/validate", Some(&secret_yaml),
        ).await;
        assert_eq!(vcode, 200, "body was: {vbody}");
        assert!(!vbody.contains(sentinel), "validate leaked secret: {vbody}");

        let (pcode, pbody) = req(
            super::router(d.clone(), cfg_path.clone()), "PUT", "/v1/config", Some(&secret_yaml),
        ).await;
        assert_eq!(pcode, 200, "body was: {pbody}");
        assert!(!pbody.contains(sentinel), "PUT leaked secret: {pbody}");

        let (rcode, rbody) =
            req(super::router(d.clone(), cfg_path.clone()), "POST", "/v1/config/rollback", None).await;
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
            .oneshot(Request::builder().uri("/v1/events").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(axum::http::header::CONTENT_TYPE).unwrap(),
            "text/event-stream",
            "wrong content-type"
        );

        let id = uuid::Uuid::now_v7();
        d.events.send(crate::events::Event::Ingress {
            id,
            protocol: "mocka".into(),
            sender_masked: "mocka:si****1234".into(),
            routes: vec!["general".into()],
            ts: chrono::Utc::now(),
        }).expect("send must succeed: the handler above has already subscribed");

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
        assert!(collected.contains("event: ingress"), "stream was: {collected}");
        assert!(collected.contains(&format!("\"id\":\"{id}\"")), "stream was: {collected}");
        assert!(collected.contains("\"sender_masked\":\"mocka:si****1234\""), "stream was: {collected}");
        assert!(collected.contains("\"routes\":[\"general\"]"), "stream was: {collected}");
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
                name: format!("p{i}"), up: true, ts: chrono::Utc::now(),
            }).unwrap();
        }

        let mut stream = super::events_stream_from(rx);
        let item = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("must not hang skipping a lagged gap")
            .expect("stream must not end just because the receiver lagged");
        let _event: SseEvent =
            item.expect("must yield a real event once the lagged gap is skipped, not an error");
    }
}
