use crate::config::Config;
use crate::storage::Store;
use crate::{alias, dedup, metrics, policy, queue, routes, storage, transform};
use alias::Aliaser;
use chrono::{DateTime, Duration as CDuration, Utc};
use relay_core::{Capabilities, Endpoint, Envelope, Sender};
use relay_ipc::DaemonToPlugin;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub struct PluginHandle {
    pub tx: mpsc::Sender<DaemonToPlugin>,
    pub capabilities: Capabilities,
    pub connected: bool,
}

pub struct Daemon {
    pub cfg: Config,
    pub store: Mutex<Store>,
    pub dedup: Mutex<dedup::Dedup>,
    pub aliaser: Aliaser,
    pub plugins: Mutex<HashMap<String, PluginHandle>>,
}

impl Daemon {
    pub fn new(cfg: Config, data_dir: &Path) -> std::io::Result<Daemon> {
        std::fs::create_dir_all(data_dir)?;
        let store = Store::open(&data_dir.join("relayfabric.db"))
            .map_err(std::io::Error::other)?;
        let recovered = store.recover().map_err(std::io::Error::other)?;
        if recovered > 0 {
            info!(recovered, "requeued in-flight deliveries from previous run");
        }
        let aliaser = Aliaser::load_or_create(&data_dir.join("alias.key"))?;
        let ttl = std::time::Duration::from_secs(cfg.dedup_ttl_secs);
        Ok(Daemon {
            cfg,
            store: Mutex::new(store),
            dedup: Mutex::new(dedup::Dedup::new(ttl)),
            aliaser,
            plugins: Mutex::new(HashMap::new()),
        })
    }
}

pub fn handle_inbound(
    d: &Daemon,
    plugin: &str,
    endpoint: String,
    sender: String,
    kind: String,
    body: String,
    created_at: Option<DateTime<Utc>>,
) {
    metrics::inc(&metrics::INGRESS);
    let key = dedup::key(plugin, &sender, &endpoint, &body, created_at);
    if !d.dedup.lock().unwrap().check(&key, Instant::now()) {
        metrics::inc(&metrics::DUPLICATES);
        return;
    }
    let now = Utc::now();
    let source = Endpoint { protocol: plugin.to_string(), endpoint };
    let targets: Vec<(String, Endpoint)> = routes::route(&d.cfg.routes, &source)
        .into_iter()
        .map(|(r, e)| (r.to_string(), e.clone()))
        .collect();
    if targets.is_empty() {
        metrics::inc(&metrics::DROPPED);
        warn!(%source, "dropping unrouted message (deny by default)");
        return;
    }
    let env = Envelope::new(
        source,
        Sender { native_ref: sender },
        kind,
        body,
        created_at.unwrap_or(now),
        now + CDuration::seconds(d.cfg.ttl_default_secs as i64),
        d.cfg.hop_limit,
    );
    let store = d.store.lock().unwrap();
    if let Err(e) = store.insert_message(&env) {
        warn!(error = %e, "failed to persist message");
        return;
    }
    for (route, dest) in &targets {
        if let Err(e) = store.insert_delivery(env.id, route, dest, now, env.expires_at) {
            warn!(error = %e, "failed to enqueue delivery");
        }
    }
    info!(id = %env.id, source = %env.source, targets = targets.len(), "message accepted");
}

/// Delivery-state writes are best-effort from the caller's point of view (the
/// pump will simply reconsider the row on its next pass), but a failure must
/// never be silent: log it with the delivery id and the state we tried to
/// write so a stuck row is diagnosable.
fn warn_if_mark_failed(delivery: i64, state: &str, result: rusqlite::Result<()>) {
    if let Err(e) = result {
        warn!(delivery, state, error = %e, "failed to persist delivery state change");
    }
}

pub fn handle_result(d: &Daemon, corr: i64, delivered: bool, detail: Option<String>) {
    let store = d.store.lock().unwrap();
    if delivered {
        metrics::inc(&metrics::EGRESS);
        warn_if_mark_failed(corr, "delivered", store.mark_delivered(corr));
        info!(delivery = corr, "delivered");
        return;
    }
    // look up attempt count to decide retry vs dead-letter
    let attempts = store
        .deliveries_for_id(corr)
        .map(|del| del.attempt_count)
        .unwrap_or(queue::MAX_ATTEMPTS);
    if attempts >= queue::MAX_ATTEMPTS {
        warn_if_mark_failed(corr, "dead_letter",
            store.mark_terminal(corr, "dead_letter", "RETRY_EXHAUSTED"));
        warn!(delivery = corr, detail = detail.as_deref().unwrap_or(""), "dead-lettered");
    } else {
        let next = Utc::now()
            + CDuration::from_std(queue::backoff(attempts)).unwrap_or(CDuration::seconds(5));
        warn_if_mark_failed(corr, "pending", store.mark_retry(corr, next));
        info!(delivery = corr, attempts, "delivery failed, will retry");
    }
}

pub async fn pump(d: Arc<Daemon>) {
    loop {
        let now = Utc::now();
        let due = {
            let store = d.store.lock().unwrap();
            let _ = store.reclaim_stale(now - CDuration::seconds(60));
            store.due_deliveries(now, 32).unwrap_or_default()
        };
        for del in due {
            process_due(&d, del, now).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn process_due(d: &Arc<Daemon>, del: storage::Delivery, now: DateTime<Utc>) {
    // Look up the message with its own short-lived lock, then drop the guard
    // before matching: the `_` arm below needs to take the lock again to
    // mark the row, and std::sync::Mutex is not reentrant — holding the
    // guard as the match scrutinee while re-locking in an arm deadlocks.
    let msg = {
        let store = d.store.lock().unwrap();
        store.get_message(del.message_id)
    };
    let env = match msg {
        Ok(Some(e)) => e,
        other => {
            if let Err(e) = &other {
                warn!(delivery = del.id, error = %e, "failed to load message for delivery");
            }
            let result = d.store.lock().unwrap()
                .mark_terminal(del.id, "failed", "DESTINATION_UNKNOWN");
            warn_if_mark_failed(del.id, "failed", result);
            return;
        }
    };
    if env.is_expired(now) {
        let result = d.store.lock().unwrap().mark_terminal(del.id, "expired", "TTL_EXPIRED");
        warn_if_mark_failed(del.id, "expired", result);
        return;
    }
    match policy::evaluate(&d.cfg.policies, &env, &del.destination) {
        policy::Decision::Deny { policy } => {
            metrics::inc(&metrics::POLICY_DENIALS);
            let result = d.store.lock().unwrap()
                .mark_terminal(del.id, "dead_letter", "POLICY_DENIED");
            warn_if_mark_failed(del.id, "dead_letter", result);
            info!(delivery = del.id, policy, "policy denied");
        }
        policy::Decision::Allow { max_payload } => {
            // capability + policy limits combine to the tighter one
            let (tx, cap_limit) = {
                let plugins = d.plugins.lock().unwrap();
                match plugins.get(&del.destination.protocol).filter(|h| h.connected) {
                    Some(h) => (
                        Some(h.tx.clone()),
                        h.capabilities.max_payload.map(|v| v as usize),
                    ),
                    None => (None, None),
                }
            };
            let Some(tx) = tx else {
                // plugin not connected: nudge next_attempt forward, stay pending
                let result = d.store.lock().unwrap()
                    .mark_retry(del.id, now + CDuration::seconds(5));
                warn_if_mark_failed(del.id, "pending", result);
                return;
            };
            let limit = match (max_payload, cap_limit) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let alias = d.aliaser.alias(
                &env.source.protocol, &env.sender.native_ref, &del.route);
            let body = transform::render(&alias, &env.body, limit);
            let result = d.store.lock().unwrap().mark_attempting(del.id);
            warn_if_mark_failed(del.id, "attempting", result);
            let send = DaemonToPlugin::Send {
                corr: del.id,
                endpoint: del.destination.endpoint.clone(),
                kind: env.kind.clone(),
                body,
            };
            if tx.send(send).await.is_err() {
                // channel closed under us; requeue
                let result = d.store.lock().unwrap()
                    .mark_retry(del.id, now + CDuration::seconds(5));
                warn_if_mark_failed(del.id, "pending", result);
            }
        }
    }
}

#[cfg(test)]
pub mod tests_support {
    use super::*;
    use crate::config::{Config, NodeConfig, PluginConfig, RouteConfig};
    use std::collections::BTreeMap;

    pub fn test_daemon(dir: &std::path::Path) -> Daemon {
        let mut plugins = BTreeMap::new();
        for name in ["mocka", "mockb"] {
            plugins.insert(name.to_string(), PluginConfig {
                enabled: true, command: None, config: serde_yaml::Value::Null,
            });
        }
        let cfg = Config {
            node: NodeConfig { name: "t".into(), data_dir: dir.to_path_buf() },
            plugins,
            routes: vec![RouteConfig {
                name: "general".into(),
                sources: vec!["mocka:chan".parse().unwrap(), "mockb:chan".parse().unwrap()],
                destinations: vec!["mocka:chan".parse().unwrap(), "mockb:chan".parse().unwrap()],
            }],
            policies: vec![],
            ttl_default_secs: 3600,
            dedup_ttl_secs: 3600,
            hop_limit: 8,
        };
        Daemon::new(cfg, dir).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests_support::test_daemon;

    #[test]
    fn inbound_routes_to_other_endpoint_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None);
        // one delivery row, to mockb, none echoed to mocka
        let store = d.store.lock().unwrap();
        let counts = store.queue_counts().unwrap();
        assert_eq!(counts, vec![("pending".to_string(), 1)]);
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(due[0].destination.protocol, "mockb");
        drop(store);
        // duplicate is dropped
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None);
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(),
                   vec![("pending".to_string(), 1)]);
        // unrouted endpoint is dropped (deny by default)
        handle_inbound(&d, "mocka", "elsewhere".into(), "!a".into(), "text".into(),
                       "hi".into(), None);
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(),
                   vec![("pending".to_string(), 1)]);
    }

    #[tokio::test]
    async fn process_due_marks_failed_when_message_missing_without_deadlocking() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relayfabric.db");
        let d = Arc::new(test_daemon(dir.path()));
        let now = Utc::now();
        let dest: Endpoint = "mockb:chan".parse().unwrap();

        // get_message() swallows envelope deserialize failures into Ok(None)
        // (storage.rs get_message), which is the realistic way a delivery row
        // sees a "missing" message while still satisfying the messages(id)
        // foreign key: the row exists but its envelope JSON is unreadable.
        // Insert such a row directly, bypassing Store::insert_message (which
        // can only ever write valid JSON).
        let ghost_id = uuid::Uuid::now_v7();
        {
            let raw = rusqlite::Connection::open(&db_path).unwrap();
            raw.execute(
                "INSERT INTO messages (id, envelope, created_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![ghost_id.to_string(), "not valid json", now.to_rfc3339()],
            ).unwrap();
        }
        let delivery_id = {
            let store = d.store.lock().unwrap();
            store
                .insert_delivery(ghost_id, "general", &dest, now, now + CDuration::hours(1))
                .unwrap()
        };
        let del = {
            let store = d.store.lock().unwrap();
            store.deliveries_for_id(delivery_id).unwrap()
        };

        // Regression guard for the self-deadlock: process_due's message-missing
        // fallback used to re-lock d.store while still holding the guard from
        // the match scrutinee, hanging forever. It must complete promptly.
        tokio::time::timeout(std::time::Duration::from_secs(2), process_due(&d, del, now))
            .await
            .expect("process_due hung instead of completing (self-deadlock)");

        let after = d.store.lock().unwrap().deliveries_for_id(delivery_id).unwrap();
        assert_eq!(after.state, "failed");
        assert_eq!(after.reason.as_deref(), Some("DESTINATION_UNKNOWN"));
    }
}
