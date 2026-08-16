use crate::cas::Cas;
use crate::config::Config;
use crate::storage::Store;
use crate::{alias, dedup, metrics, node_identity, policy, queue, routes, storage, transform};
use alias::Aliaser;
use node_identity::NodeIdentity;
use chrono::{DateTime, Duration as CDuration, Utc};
use relay_core::{AttachmentMeta, Capabilities, Endpoint, Envelope, Sender};
use relay_ipc::{DaemonToPlugin, IpcAttachment, MAX_FRAME};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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
    #[allow(dead_code)]
    // consumed by RFDP envelope signing/verification (v0.2); remove allow when used
    pub identity: NodeIdentity,
    pub node_id: String,
    pub plugins: Mutex<HashMap<String, PluginHandle>>,
    pub cas: Cas,
}

/// Creates `data_dir` (and any missing parents) with owner-only permissions
/// (0700). Message bodies, the SQLite DB, the plugin control socket, and the
/// content-addressed attachment store (cas.rs, which reuses this same
/// helper for its own subdirectory) all live under directories hardened
/// this way; a world- or group-readable dir would let any local user read
/// message content or connect to plugins.sock regardless of the individual
/// file modes SQLite/UnixListener happen to create (typically
/// umask-derived 0644/0755). `DirBuilder::mode` only governs freshly-created
/// directories, so the mode is re-asserted with `set_permissions` afterward
/// to also tighten a pre-existing dir left with looser permissions (e.g.
/// from an older install or a manual mkdir).
pub(crate) fn create_data_dir(data_dir: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(data_dir)?;
    std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
}

impl Daemon {
    pub fn new(cfg: Config, data_dir: &Path) -> std::io::Result<Daemon> {
        create_data_dir(data_dir)?;
        let store = Store::open(&data_dir.join("relayfabric.db"))
            .map_err(std::io::Error::other)?;
        let recovered = store.recover().map_err(std::io::Error::other)?;
        if recovered > 0 {
            info!(recovered, "requeued in-flight deliveries from previous run");
        }
        let aliaser = Aliaser::load_or_create(&data_dir.join("alias.key"))?;
        let identity = NodeIdentity::load_or_create(&data_dir.join("identity"))?;
        let node_id = identity.node_id();
        let ttl = std::time::Duration::from_secs(cfg.dedup_ttl_secs);
        let cas = Cas::new(&data_dir.join("attachments"))?;
        Ok(Daemon {
            cfg,
            store: Mutex::new(store),
            dedup: Mutex::new(dedup::Dedup::new(ttl)),
            aliaser,
            identity,
            node_id,
            plugins: Mutex::new(HashMap::new()),
            cas,
        })
    }
}

/// Oversize attachments are dropped and noted in the body; accepted ones are
/// written to the CAS immediately and get an `AttachmentMeta` on the
/// envelope. Attachment filenames/content are message content and may
/// appear in the drop note (part of the body), but must never reach a log
/// line — logs below only ever carry sizes and shas.
#[allow(clippy::too_many_arguments)]
pub fn handle_inbound(
    d: &Daemon,
    plugin: &str,
    endpoint: String,
    sender: String,
    kind: String,
    body: String,
    created_at: Option<DateTime<Utc>>,
    attachments: Vec<IpcAttachment>,
) {
    metrics::inc(&metrics::INGRESS);

    // Hash every attachment up front — a bare in-memory digest, no CAS I/O —
    // so the dedup key can be sensitive to the *full* attachment set,
    // including ones that will end up dropped for being oversize (two sends
    // differing only in which oversize attachment got dropped must not
    // dedup-collide). Nothing is written to the CAS yet: a message that
    // turns out to be a duplicate or unroutable must not write attachment
    // bytes to disk, because it never gets an `insert_attachment_refs` row,
    // which means the GC in `purge_terminal` could never find and reclaim
    // that blob again — a permanent leak, not just a stale one.
    struct Hashed { att: IpcAttachment, sha: String, oversize: bool }
    let hashed: Vec<Hashed> = attachments
        .into_iter()
        .map(|att| {
            let oversize = att.data.len() as u64 > d.cfg.max_attachment_bytes;
            let sha = hex::encode(Sha256::digest(&att.data));
            Hashed { att, sha, oversize }
        })
        .collect();
    let all_shas: Vec<String> = hashed.iter().map(|h| h.sha.clone()).collect();

    let key = dedup::key(plugin, &sender, &endpoint, &body, created_at, &all_shas);
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

    // Message is accepted (not a duplicate, has at least one route): only
    // now do in-cap attachments actually get written to the CAS.
    let mut metas: Vec<AttachmentMeta> = Vec::new();
    let mut shas: Vec<String> = Vec::new();
    let mut notes = String::new();
    for h in hashed {
        let size = h.att.data.len() as u64;
        if h.oversize {
            notes.push_str(&format!(
                "\n[dropped {}: {size} B over {} B limit]",
                h.att.filename, d.cfg.max_attachment_bytes
            ));
            continue;
        }
        match d.cas.put(&h.att.data) {
            Ok(sha) => {
                shas.push(sha.clone());
                metas.push(AttachmentMeta {
                    filename: h.att.filename, mime: h.att.mime, size, sha256: sha,
                });
            }
            Err(e) => {
                warn!(error = %e, size, "failed to store attachment, dropping it");
                notes.push_str(&format!("\n[attachment {} unavailable]", h.att.filename));
            }
        }
    }
    let body = format!("{body}{notes}");
    let mut env = Envelope::new(
        source,
        Sender { native_ref: sender },
        kind,
        body,
        created_at.unwrap_or(now),
        now + CDuration::seconds(d.cfg.ttl_default_secs as i64),
        d.cfg.hop_limit,
    );
    env.attachments = metas;
    let store = d.store.lock().unwrap();
    if let Err(e) = store.insert_message(&env) {
        warn!(error = %e, "failed to persist message");
        return;
    }
    if let Err(e) = store.insert_attachment_refs(env.id, &shas) {
        warn!(error = %e, "failed to persist attachment refs");
    }
    for (route, dest) in &targets {
        if let Err(e) = store.insert_delivery(env.id, route, dest, now, env.expires_at) {
            warn!(error = %e, "failed to enqueue delivery");
        }
    }
    info!(id = %env.id, source = %env.source, targets = targets.len(),
          attachments = env.attachments.len(), "message accepted");
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

const PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

pub async fn pump(d: Arc<Daemon>) {
    let mut last_purge = Instant::now();
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
        if last_purge.elapsed() >= PURGE_INTERVAL {
            last_purge = Instant::now();
            // ponytail: retention hardcoded to 24h; make retention
            // configurable is the upgrade path once there's an actual
            // disk-pressure signal to tune it by.
            let cutoff = now - CDuration::hours(24);
            let result = d.store.lock().unwrap().purge_terminal(cutoff);
            match result {
                Ok((n, orphans)) => {
                    if n > 0 {
                        info!(purged = n, "retention purge removed old deliveries");
                    }
                    for sha in &orphans {
                        if let Err(e) = d.cas.remove(sha) {
                            warn!(sha = %sha, error = %e, "failed to remove orphaned attachment");
                        }
                    }
                }
                Err(e) => warn!(error = %e, "retention purge failed"),
            }
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
        policy::Decision::Allow { max_payload, attachments_allowed, max_attachment_bytes } => {
            // capability + policy limits combine to the tighter one
            let (tx, cap_limit, dest_supports_attachments) = {
                let plugins = d.plugins.lock().unwrap();
                match plugins.get(&del.destination.protocol).filter(|h| h.connected) {
                    Some(h) => (
                        Some(h.tx.clone()),
                        h.capabilities.max_payload.map(|v| v as usize),
                        h.capabilities.attachments,
                    ),
                    None => (None, None, false),
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

            let (attachments, notes) = if env.attachments.is_empty() {
                (Vec::new(), String::new())
            } else if attachments_allowed && dest_supports_attachments {
                let frame_budget = u64::from(MAX_FRAME) - FRAME_HEADROOM_BYTES;
                load_attachments(d, &env.attachments, max_attachment_bytes, frame_budget)
            } else {
                // destination lacks the capability, or policy rejects
                // attachments outright: strip every attachment and note it
                // once per attachment, without naming any of them (a
                // blanket strip must not reveal which files existed).
                let dropped: Vec<(String, u64)> =
                    env.attachments.iter().map(|a| (a.filename.clone(), a.size)).collect();
                (Vec::new(), transform::attachment_notes(&dropped, "omitted"))
            };
            // Decision: notes (capability/policy strip, byte-cap drops, CAS
            // misses) are folded into the body BEFORE max_payload
            // truncation runs, not appended after — so that a note-inflated
            // body still respects the destination's byte cap instead of the
            // notes sneaking past it by arriving post-truncation. That does
            // mean a very tight cap can truncate a note away entirely; that
            // is the correct trade-off since the byte cap is the harder
            // constraint the plugin actually enforces on the wire.
            let body = transform::render(&alias, &format!("{}{notes}", env.body), limit);
            let result = d.store.lock().unwrap().mark_attempting(del.id);
            warn_if_mark_failed(del.id, "attempting", result);
            let send = DaemonToPlugin::Send {
                corr: del.id,
                endpoint: del.destination.endpoint.clone(),
                kind: env.kind.clone(),
                body,
                attachments,
            };
            // try_send, not send().await: this pump task is the single driver
            // of ALL plugins' deliveries plus reclaim_stale. Awaiting a full
            // per-plugin channel (e.g. one plugin's process wedged or just
            // slow) would block delivery to every other plugin indefinitely.
            // A full or closed channel just means "not right now" — requeue
            // and let the next pump tick retry.
            if let Err(e) = tx.try_send(send) {
                let closed_or_full = match e {
                    mpsc::error::TrySendError::Full(_) => "full",
                    mpsc::error::TrySendError::Closed(_) => "closed",
                };
                let result = d.store.lock().unwrap()
                    .mark_retry(del.id, now + CDuration::seconds(5));
                warn_if_mark_failed(del.id, "pending", result);
                warn!(delivery = del.id, plugin = %del.destination.protocol,
                      reason = closed_or_full, "plugin channel unavailable, requeued");
            }
        }
    }
}

/// Headroom subtracted from `MAX_FRAME` when budgeting cumulative attachment
/// bytes for a single Send: the frame also carries the CBOR envelope, the
/// body/notes text, and per-attachment filenames/mime types, none of which
/// count toward the raw attachment bytes summed in `load_attachments`. 64
/// KiB comfortably covers that overhead for any realistic body/note size.
const FRAME_HEADROOM_BYTES: u64 = 64 * 1024;

/// Rehydrates the accepted attachments of an outgoing message from the CAS,
/// applying (in cheapest-first order, to avoid disk I/O for anything that
/// will be dropped anyway):
/// 1. the per-attachment policy byte cap (`max_attachment_bytes`), then
/// 2. the cumulative `frame_budget` guard, so the whole Send frame stays
///    under `MAX_FRAME` even when several in-cap attachments are combined.
///
/// Anything that fails either check, plus anything whose blob has gone
/// missing from the CAS, is dropped from the attachment list and noted in
/// the returned string instead — never logged, since attachment
/// filenames/content are message content (see `handle_inbound`'s
/// module-level note on the same point).
fn load_attachments(
    d: &Daemon,
    metas: &[AttachmentMeta],
    max_attachment_bytes: Option<u64>,
    frame_budget: u64,
) -> (Vec<IpcAttachment>, String) {
    let mut attachments = Vec::new();
    let mut notes = String::new();
    let mut cumulative: u64 = 0;
    for meta in metas {
        if let Some(cap) = max_attachment_bytes {
            if meta.size > cap {
                notes.push_str(&transform::attachment_notes(
                    &[(meta.filename.clone(), meta.size)],
                    &format!("{cap} B limit"),
                ));
                continue;
            }
        }
        if cumulative + meta.size > frame_budget {
            notes.push_str(&transform::attachment_notes(
                &[(meta.filename.clone(), meta.size)],
                &format!("{frame_budget} B limit"),
            ));
            continue;
        }
        match d.cas.get(&meta.sha256) {
            Ok(data) => {
                cumulative += meta.size;
                attachments.push(IpcAttachment {
                    filename: meta.filename.clone(),
                    mime: meta.mime.clone(),
                    data,
                });
            }
            Err(e) => {
                warn!(sha = %meta.sha256, error = %e, "attachment missing from CAS");
                notes.push_str(&format!("\n[attachment {} unavailable]", meta.filename));
            }
        }
    }
    (attachments, notes)
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
            max_attachment_bytes: 8 * 1024 * 1024,
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
                       "hello".into(), None, vec![]);
        // one delivery row, to mockb, none echoed to mocka
        let store = d.store.lock().unwrap();
        let counts = store.queue_counts().unwrap();
        assert_eq!(counts, vec![("pending".to_string(), 1)]);
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(due[0].destination.protocol, "mockb");
        drop(store);
        // duplicate is dropped
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![]);
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(),
                   vec![("pending".to_string(), 1)]);
        // unrouted endpoint is dropped (deny by default)
        handle_inbound(&d, "mocka", "elsewhere".into(), "!a".into(), "text".into(),
                       "hi".into(), None, vec![]);
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

    #[test]
    fn data_dir_created_with_owner_only_perms() {
        let base = tempfile::tempdir().unwrap();

        // freshly created (possibly nested, non-existent) dir: DirBuilder's
        // mode must land as 0700 regardless of umask.
        let fresh = base.path().join("nested/data");
        create_data_dir(&fresh).unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "freshly created data dir must be 0700");

        // pre-existing dir left with looser permissions (e.g. an older
        // install, or a manual mkdir): must be tightened, not left alone.
        let loose = base.path().join("loose");
        std::fs::create_dir_all(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        create_data_dir(&loose).unwrap();
        let mode = std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "pre-existing loose-permission data dir must be tightened");
    }

    #[tokio::test]
    async fn process_due_requeues_instead_of_blocking_when_plugin_channel_is_full() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![]);
        // sample `now` after handle_inbound (which stamps next_attempt with
        // its own, slightly later, internal Utc::now()) so due_deliveries
        // actually finds the row.
        let now = Utc::now();
        let delivery_id = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(now, 1).unwrap()[0].id
        };

        // register mockb's handle with a capacity-1 channel and fill its one
        // slot, so any further try_send hits backpressure.
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(DaemonToPlugin::Shutdown).unwrap();
        d.plugins.lock().unwrap().insert("mockb".to_string(), PluginHandle {
            tx, capabilities: Capabilities::default(), connected: true,
        });

        let del = { let store = d.store.lock().unwrap(); store.deliveries_for_id(delivery_id).unwrap() };

        // Regression guard: process_due used to `.await` a send on this
        // channel, which would hang forever with the slot held. It must
        // return promptly and leave the delivery pending for the next tick.
        tokio::time::timeout(
            std::time::Duration::from_secs(2), process_due(&d, del, now))
            .await
            .expect("process_due hung on a full plugin channel");

        let after = d.store.lock().unwrap().deliveries_for_id(delivery_id).unwrap();
        assert_eq!(after.state, "pending");
    }

    #[test]
    fn inbound_drops_oversize_attachment_stores_accepted_one_and_notes_the_drop() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = test_daemon(dir.path());
        d.cfg.max_attachment_bytes = 16;

        let small = IpcAttachment {
            filename: "small.txt".into(),
            mime: "text/plain".into(),
            data: b"tiny".to_vec(),
        };
        let big = IpcAttachment {
            filename: "big.bin".into(),
            mime: "application/octet-stream".into(),
            data: vec![0u8; 64],
        };
        let expected_sha = hex::encode(Sha256::digest(&small.data));

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![small, big]);

        let store = d.store.lock().unwrap();
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(due.len(), 1);
        let env = store.get_message(due[0].message_id).unwrap().unwrap();

        assert_eq!(env.attachments.len(), 1, "only the in-cap attachment gets a meta");
        assert_eq!(env.attachments[0].sha256, expected_sha);
        assert_eq!(env.attachments[0].filename, "small.txt");
        assert_eq!(env.attachments[0].size, 4);

        assert!(
            env.body.contains("[dropped big.bin: 64 B over 16 B limit]"),
            "body did not carry the drop note: {}", env.body
        );

        // the accepted attachment's bytes actually landed in the CAS
        assert_eq!(d.cas.get(&expected_sha).unwrap(), b"tiny");
    }

    /// An unrouted (deny-by-default) inbound must never write attachment
    /// bytes to the CAS: it never gets an `insert_attachment_refs` row, so a
    /// blob written for it would be a permanent, un-GC-able leak.
    #[test]
    fn unrouted_inbound_with_attachment_never_touches_the_cas() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());

        let att = IpcAttachment {
            filename: "orphan-risk.bin".into(),
            mime: "application/octet-stream".into(),
            data: b"never stored".to_vec(),
        };
        let sha = hex::encode(Sha256::digest(&att.data));

        // "elsewhere" is not a configured route source for test_daemon.
        handle_inbound(&d, "mocka", "elsewhere".into(), "!a".into(), "text".into(),
                       "hi".into(), None, vec![att]);

        assert!(d.cas.get(&sha).is_err(),
            "unrouted message must not write attachment bytes to the CAS");
        let entries: Vec<_> = std::fs::read_dir(dir.path().join("attachments"))
            .unwrap().collect();
        assert!(entries.is_empty(),
            "CAS dir must contain no files for a dropped/unrouted message");
    }

    /// Companion to storage.rs's
    /// `purge_terminal_keeps_a_sha_shared_by_a_surviving_message`, but
    /// end-to-end through `handle_inbound` and the real CAS: two messages
    /// with byte-identical (so content-addressed to the same sha) attachments
    /// must not have that blob removed while either message is still alive.
    #[test]
    fn purge_and_gc_keeps_a_shared_attachment_alive_until_both_messages_are_gone() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());

        let shared = IpcAttachment {
            filename: "shared.bin".into(),
            mime: "application/octet-stream".into(),
            data: b"shared bytes".to_vec(),
        };
        let sha = hex::encode(Sha256::digest(&shared.data));

        // two independent messages (different bodies, so dedup doesn't
        // collapse them) carrying an attachment with identical bytes.
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "first".into(), None, vec![shared.clone()]);
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "second".into(), None, vec![shared]);
        assert_eq!(d.cas.get(&sha).unwrap(), b"shared bytes");

        let now = Utc::now();
        let (id1, id2) = {
            let store = d.store.lock().unwrap();
            let due = store.due_deliveries(now, 10).unwrap();
            assert_eq!(due.len(), 2);
            (due[0].id, due[1].id)
        };

        // terminate + purge only the FIRST message; the second is still
        // pending and still references the same sha.
        {
            let store = d.store.lock().unwrap();
            store.mark_attempting(id1).unwrap();
            store.mark_delivered(id1).unwrap();
        }
        let (purged1, orphans1) =
            d.store.lock().unwrap().purge_terminal(now + CDuration::hours(1)).unwrap();
        assert_eq!(purged1, 1);
        assert!(orphans1.is_empty(),
            "sha still referenced by the second (pending) message must survive: {orphans1:?}");
        for s in &orphans1 {
            d.cas.remove(s).unwrap();
        }
        assert_eq!(d.cas.get(&sha).unwrap(), b"shared bytes",
            "CAS blob must survive: a live message still references it");

        // now finish off the second message too and purge again: nothing
        // references the sha anymore, so it must come back as orphaned and
        // be removable.
        {
            let store = d.store.lock().unwrap();
            store.mark_attempting(id2).unwrap();
            store.mark_delivered(id2).unwrap();
        }
        let (purged2, orphans2) =
            d.store.lock().unwrap().purge_terminal(now + CDuration::hours(1)).unwrap();
        assert_eq!(purged2, 1);
        assert_eq!(orphans2, vec![sha.clone()]);
        for s in &orphans2 {
            d.cas.remove(s).unwrap();
        }
        assert!(d.cas.get(&sha).is_err(), "now-truly-orphaned blob must be removable");
    }

    /// Registers a connected mock plugin with the given `attachments`
    /// capability and a fresh channel, returning the receiving half so a
    /// test can inspect the `Send` frame `process_due` produces for it.
    fn register_plugin(d: &Daemon, name: &str, attachments: bool) -> mpsc::Receiver<DaemonToPlugin> {
        let (tx, rx) = mpsc::channel(8);
        d.plugins.lock().unwrap().insert(name.to_string(), PluginHandle {
            tx,
            capabilities: Capabilities { attachments, ..Capabilities::default() },
            connected: true,
        });
        rx
    }

    async fn recv_send(rx: &mut mpsc::Receiver<DaemonToPlugin>) -> DaemonToPlugin {
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for Send")
            .expect("channel closed without a Send")
    }

    #[tokio::test]
    async fn process_due_attaches_bytes_when_capability_and_policy_allow() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let mut rx = register_plugin(&d, "mockb", true);

        let att = IpcAttachment {
            filename: "photo.jpg".into(), mime: "image/jpeg".into(),
            data: b"just some bytes".to_vec(),
        };
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "look at this".into(), None, vec![att.clone()]);
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, attachments, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0].data, att.data);
        assert_eq!(attachments[0].filename, "photo.jpg");
        assert!(!body.contains("[attachment omitted]"), "body was: {body}");
    }

    #[tokio::test]
    async fn process_due_strips_attachments_and_notes_when_capability_missing() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let mut rx = register_plugin(&d, "mockb", false); // no attachments capability

        let att = IpcAttachment {
            filename: "photo.jpg".into(), mime: "image/jpeg".into(), data: b"bytes".to_vec(),
        };
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "look at this".into(), None, vec![att]);
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, attachments, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(attachments.is_empty());
        assert!(body.contains("[attachment omitted]"), "body was: {body}");
        assert!(!body.contains("photo.jpg"),
            "a blanket capability strip must not name the dropped file: {body}");
    }

    #[tokio::test]
    async fn process_due_strips_attachments_when_policy_rejects_them_even_if_capability_allows() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = test_daemon(dir.path());
        d.cfg.policies = vec![crate::config::Policy {
            name: "no-attachments-for-b".into(),
            r#match: crate::config::PolicyMatch { destination_protocol: vec!["mockb".into()] },
            rules: crate::config::PolicyRules {
                attachments: Some("reject".into()), ..Default::default()
            },
        }];
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", true); // capability says yes...

        let att = IpcAttachment {
            filename: "photo.jpg".into(), mime: "image/jpeg".into(), data: b"bytes".to_vec(),
        };
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "look at this".into(), None, vec![att]);
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, attachments, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(attachments.is_empty(), "...but policy says no, and policy wins");
        assert!(body.contains("[attachment omitted]"), "body was: {body}");
    }

    #[tokio::test]
    async fn process_due_drops_attachment_over_the_policy_byte_cap_and_notes_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = test_daemon(dir.path());
        d.cfg.policies = vec![crate::config::Policy {
            name: "small-attachments-for-b".into(),
            r#match: crate::config::PolicyMatch { destination_protocol: vec!["mockb".into()] },
            rules: crate::config::PolicyRules {
                max_attachment_bytes: Some(10), ..Default::default()
            },
        }];
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", true);

        let att = IpcAttachment {
            filename: "toobig.bin".into(), mime: "application/octet-stream".into(),
            data: vec![0u8; 20], // over the 10 B policy cap, under the ingress cap
        };
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "look at this".into(), None, vec![att]);
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, attachments, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(attachments.is_empty());
        assert!(
            body.contains("[dropped toobig.bin: 20 B over 10 B limit]"),
            "body was: {body}"
        );
    }

    #[tokio::test]
    async fn process_due_notes_unavailable_when_the_cas_blob_has_gone_missing() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let mut rx = register_plugin(&d, "mockb", true);

        let att = IpcAttachment {
            filename: "gone.bin".into(), mime: "application/octet-stream".into(),
            data: b"will vanish".to_vec(),
        };
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "look at this".into(), None, vec![att]);
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap()
        };
        let env = d.store.lock().unwrap().get_message(del.message_id).unwrap().unwrap();
        let sha = env.attachments[0].sha256.clone();
        d.cas.remove(&sha).unwrap(); // simulate the blob having gone missing

        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, attachments, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(attachments.is_empty());
        assert!(body.contains("[attachment gone.bin unavailable]"), "body was: {body}");
    }

    #[test]
    fn load_attachments_drops_whatever_would_exceed_the_cumulative_frame_budget() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());

        let sha_a = d.cas.put(&[1u8; 10]).unwrap();
        let sha_b = d.cas.put(&[2u8; 10]).unwrap();
        let metas = vec![
            AttachmentMeta {
                filename: "a.bin".into(), mime: "application/octet-stream".into(),
                size: 10, sha256: sha_a,
            },
            AttachmentMeta {
                filename: "b.bin".into(), mime: "application/octet-stream".into(),
                size: 10, sha256: sha_b,
            },
        ];

        // budget only has room for the first attachment's 10 bytes.
        let (attachments, notes) = load_attachments(&d, &metas, None, 15);

        assert_eq!(attachments.len(), 1, "only the first fits under the frame budget");
        assert_eq!(attachments[0].filename, "a.bin");
        assert!(
            notes.contains("[dropped b.bin: 10 B over 15 B limit]"),
            "notes was: {notes}"
        );
    }

    /// Two inbound sends that are identical except for which oversize
    /// (dropped) attachment they carry must not be treated as duplicates:
    /// the dedup key must be sensitive to every attachment's sha, not just
    /// the ones that made it past the size cap.
    #[test]
    fn dedup_key_is_sensitive_to_dropped_attachments_not_just_accepted_ones() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = test_daemon(dir.path());
        d.cfg.max_attachment_bytes = 16;

        let a = IpcAttachment {
            filename: "a.bin".into(), mime: "application/octet-stream".into(),
            data: vec![0u8; 64], // oversize -> dropped
        };
        let b = IpcAttachment {
            filename: "b.bin".into(), mime: "application/octet-stream".into(),
            data: vec![1u8; 64], // different bytes, also oversize -> dropped
        };
        let same_created_at = Utc::now();

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), Some(same_created_at), vec![a]);
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), Some(same_created_at), vec![b]);

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert_eq!(counts, vec![("pending".to_string(), 2)],
            "differing dropped attachments must not dedup-collide: {counts:?}");
    }
}
