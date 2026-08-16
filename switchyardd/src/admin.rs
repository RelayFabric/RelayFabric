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
    Json(json!({ "node": d.cfg.node.name, "node_id": d.node_id, "plugins": plugins, "queue": queue_map(&d) }))
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
                       "hello".into(), None, vec![]);
        let (code, body) = get(router(d), "/v1/status").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"node\":\"t\""));
        assert!(body.contains("\"node_id\":\"rf:"));
        assert!(body.contains("\"pending\":1"));
    }

    #[tokio::test]
    async fn trace_omits_body_and_404s_unknown() {
        let d = daemon();
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "secret-content".into(), None, vec![]);
        let id = d.store.lock().unwrap()
            .due_deliveries(chrono::Utc::now(), 1).unwrap()[0].message_id;
        let (code, body) = get(router(d.clone()), &format!("/v1/messages/{id}")).await;
        assert_eq!(code, 200);
        assert!(!body.contains("secret-content"), "trace leaked message body");
        assert!(body.contains("\"deliveries\""));
        let (code, _) = get(router(d), &format!("/v1/messages/{}", uuid::Uuid::now_v7())).await;
        assert_eq!(code, 404);
    }

    #[tokio::test]
    async fn metrics_render() {
        let (code, body) = get(router(daemon()), "/metrics").await;
        assert_eq!(code, 200);
        assert!(body.contains("relayfabric_messages_ingress_total"));
    }
}
