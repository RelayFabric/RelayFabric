use crate::config::IDENTITY_ROUTE;
use crate::engine::{self, Daemon};
use crate::identity_links;
use crate::metrics;
use axum::body::Bytes;
use axum::extract::{Path as AxPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use relay_core::Endpoint;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

pub fn router(d: Arc<Daemon>) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/plugins", get(plugins))
        .route("/v1/routes", get(routes))
        .route("/v1/queue", get(queue))
        .route("/v1/messages/{id}", get(trace))
        .route("/v1/public", get(public))
        .route("/v1/limits", get(limits))
        .route("/v1/identities", get(identities))
        .route("/v1/identities/link", post(create_link))
        .route("/v1/identities/link/{id}", delete(delete_link))
        .route("/v1/identities/challenges", get(challenges))
        .route("/metrics", get(metrics_text))
        .with_state(d)
}

/// Takes an already-bound listener (bind failures must fail startup loudly in
/// `main`, not silently kill only this background task — see `plugins.sock`).
pub async fn serve(d: Arc<Daemon>, listener: tokio::net::UnixListener) {
    axum::serve(listener, router(d)).await.expect("admin serve");
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

async fn plugins(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let enabled_names: Vec<String> = d.cfg_snapshot(|c| {
        c.plugins.iter().filter(|(_, p)| p.enabled).map(|(name, _)| name.clone()).collect()
    });
    let handles = d.plugins.lock().unwrap();
    let out: BTreeMap<String, serde_json::Value> = enabled_names.into_iter()
        .map(|name| {
            let h = handles.get(&name);
            let entry = json!({
                "connected": h.map(|h| h.connected).unwrap_or(false),
                "capabilities": h.map(|h| serde_json::to_value(&h.capabilities).unwrap()),
            });
            (name, entry)
        })
        .collect();
    Json(out)
}

async fn routes(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    Json(d.cfg_snapshot(|c| {
        c.routes.iter().map(|r| json!({
            "name": r.name,
            "sources": r.sources.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
            "destinations": r.destinations.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        })).collect::<Vec<_>>()
    }))
}

async fn queue(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    Json(queue_map(&d))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{handle_inbound, Daemon};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

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
    fn daemon_with_plugin_secret(sentinel: &str) -> Arc<Daemon> {
        std::env::set_var("RF_ADMIN_TEST_SECRET", sentinel);
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
      token: "${{env:RF_ADMIN_TEST_SECRET}}"
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
        std::env::remove_var("RF_ADMIN_TEST_SECRET");
        let d = crate::engine::Daemon::new(cfg, &data_dir).unwrap();
        std::mem::forget(dir);
        Arc::new(d)
    }

    /// Design §2's redaction invariant, defensively: `/v1/routes`,
    /// `/v1/plugins`, and `/v1/status` don't render plugin `config:` at all
    /// today (they only echo route endpoints / connection state /
    /// capabilities), so this test is a regression guard rather than proof
    /// of active redaction logic -- if any of these handlers ever start
    /// surfacing plugin config, they must read `Config::raw_plugin_configs`
    /// (the unresolved snapshot), never `cfg.plugins[_].config` (resolved,
    /// IPC-bound). See `config.rs`'s `raw_plugin_configs_retains_unresolved_
    /// form_for_display` for the unit-level half of this invariant.
    #[tokio::test]
    async fn admin_responses_never_contain_a_resolved_secret_value() {
        let sentinel = "sentinel-admin-leak-9f21";
        let d = daemon_with_plugin_secret(sentinel);
        for path in ["/v1/routes", "/v1/plugins", "/v1/status"] {
            let (code, body) = get(router(d.clone()), path).await;
            assert_eq!(code, 200, "path {path} status");
            assert!(!body.contains(sentinel), "resolved secret leaked from {path}: {body}");
        }
    }
}
