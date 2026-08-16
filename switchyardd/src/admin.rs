use crate::engine::Daemon;
use crate::metrics;
use axum::extract::{Path as AxPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
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

fn plugin_state(d: &Daemon) -> Vec<(String, bool)> {
    let connected = d.plugins.lock().unwrap();
    d.cfg.plugins.iter()
        .filter(|(_, p)| p.enabled)
        .map(|(name, _)| {
            (name.clone(), connected.get(name).map(|h| h.connected).unwrap_or(false))
        })
        .collect()
}

async fn status(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let plugins: BTreeMap<_, _> = plugin_state(&d).into_iter().collect();
    Json(json!({
        "node": d.cfg.node.name,
        "node_id": d.node_id,
        "public": d.cfg.node.public,
        "plugins": plugins,
        "queue": queue_map(&d),
    }))
}

/// spec §112.3: which services this node exposes publicly, and their
/// ingress/egress protocol coverage — the WebUI (and, later, RFDP
/// discovery) read this rather than parsing the raw config.
async fn public(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let services: Vec<_> = d.cfg.public_services.iter().map(|s| json!({
        "name": s.name,
        "type": s.r#type,
        "ingress": s.ingress,
        "egress": s.egress,
    })).collect();
    Json(json!({ "public": d.cfg.node.public, "services": services }))
}

/// Configured quotas and transport budgets (spec §112.8/§45/§79) — a config
/// echo, not live counter state: an operator diagnosing "why is this
/// getting rate-limited" starts from what's configured, and the in-memory
/// limiter windows aren't worth exposing (they reset on restart and aren't
/// meaningful without matching request context anyway).
async fn limits(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let transport_budgets: BTreeMap<_, _> = d.cfg.transport_budgets.iter()
        .map(|(proto, b)| (proto.clone(), json!({ "messages_per_minute": b.messages_per_minute })))
        .collect();
    Json(json!({
        "per_sender": {
            "messages_per_minute": d.cfg.limits.per_sender.messages_per_minute,
            "bytes_per_hour": d.cfg.limits.per_sender.bytes_per_hour,
        },
        "per_route": {
            "queue_max": d.cfg.limits.per_route.queue_max,
        },
        "global": {
            "queue_max": d.cfg.limits.global.queue_max,
            "cas_max_bytes": d.cfg.limits.global.cas_max_bytes,
        },
        "transport_budgets": transport_budgets,
    }))
}

async fn plugins(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let handles = d.plugins.lock().unwrap();
    let out: BTreeMap<String, serde_json::Value> = d.cfg.plugins.iter()
        .filter(|(_, p)| p.enabled)
        .map(|(name, _)| {
            let h = handles.get(name);
            (name.clone(), json!({
                "connected": h.map(|h| h.connected).unwrap_or(false),
                "capabilities": h.map(|h| serde_json::to_value(&h.capabilities).unwrap()),
            }))
        })
        .collect();
    Json(out)
}

async fn routes(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let out: Vec<_> = d.cfg.routes.iter().map(|r| json!({
        "name": r.name,
        "sources": r.sources.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        "destinations": r.destinations.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
    })).collect();
    Json(out)
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
    let deliveries: Vec<_> = store.deliveries_for(id).unwrap_or_default().iter()
        .map(|del| json!({
            "route": del.route,
            "destination": del.destination.to_string(),
            "priority": del.priority,
            "state": del.state,
            "attempts": del.attempt_count,
            "reason": del.reason,
            "next_attempt": del.next_attempt,
            "expires_at": del.expires_at,
        }))
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
    metrics::render(&q, &plugin_state(&d))
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

    #[tokio::test]
    async fn metrics_render() {
        let (code, body) = get(router(daemon()), "/metrics").await;
        assert_eq!(code, 200);
        assert!(body.contains("relayfabric_messages_ingress_total"));
    }
}
