use crate::cas::{self, Cas};
use crate::config::{Config, RouteConfig, IDENTITY_ROUTE};
use crate::limits::{BudgetLimiter, SenderLimiter};
use crate::storage::Store;
use crate::{
    alias, dedup, identity_links, metrics, node_identity, policy, queue, routes, storage,
    transform,
};
use alias::Aliaser;
use node_identity::NodeIdentity;
use chrono::{DateTime, Duration as CDuration, Utc};
use relay_core::{AttachmentMeta, Capabilities, Endpoint, Envelope, Sender};
use relay_ipc::{DaemonToPlugin, IpcAttachment, MAX_FRAME};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub struct PluginHandle {
    pub tx: mpsc::Sender<DaemonToPlugin>,
    pub capabilities: Capabilities,
    pub connected: bool,
}

/// Result of `Daemon::apply_config` (design §1): names of plugins that were
/// added, removed, or had their `{command, config, enabled}` changed (the
/// running plugin process is NOT restarted by apply -- `supervise` keeps
/// the old set running; this is purely informational for the caller/UI to
/// act on), plus the `"daemon"` pseudo-entry when a restart-only field
/// (`node.*` / the data-dir-derived socket paths) changed. Empty when
/// nothing in `new` requires a restart to take effect.
#[allow(dead_code)]
// consumed by admin `PUT /v1/config` / `POST /v1/config/rollback` (Task 3);
// remove allow once those handlers call `apply_config` and return this.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub restart_required: Vec<String>,
}

/// Config lives behind a `std::sync::RwLock` (design §1) so
/// `Daemon::apply_config` can hot-swap it while readers throughout
/// engine.rs/admin.rs/plugins.rs/main.rs see the new values on their very
/// next read -- no restart needed for routes/policies/limits/render/
/// identity_mode/public_services/transport_budgets. LOCK ORDER: a `cfg`
/// read (or write) guard must never be held while acquiring `store`/
/// `dedup`/`plugins`/`sender_limiter`/`budget_limiter`, and never across an
/// `.await` -- every call site here either uses `cfg_snapshot`/`route_cfg`
/// (which copy out what's needed and drop the guard before returning) or
/// binds the guard to a throwaway temporary that drops at the end of its
/// own statement, before any other lock is touched.
pub struct Daemon {
    pub cfg: RwLock<Config>,
    pub store: Mutex<Store>,
    pub dedup: Mutex<dedup::Dedup>,
    pub aliaser: Aliaser,
    #[allow(dead_code)]
    // consumed when RFDP/federation lands; remove allow when used
    pub identity: NodeIdentity,
    pub node_id: String,
    pub plugins: Mutex<HashMap<String, PluginHandle>>,
    pub cas: Cas,
    pub sender_limiter: Mutex<SenderLimiter>,
    pub budget_limiter: Mutex<BudgetLimiter>,
    pub gauges: metrics::PluginGauges,
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
        let cas = Cas::new(&data_dir.join("attachments"), cfg.limits.global.cas_max_bytes)?;
        let sender_limiter = SenderLimiter::new(
            cfg.limits.per_sender.messages_per_minute, cfg.limits.per_sender.bytes_per_hour);
        Ok(Daemon {
            cfg: RwLock::new(cfg),
            store: Mutex::new(store),
            dedup: Mutex::new(dedup::Dedup::new(ttl)),
            aliaser,
            identity,
            node_id,
            plugins: Mutex::new(HashMap::new()),
            cas,
            sender_limiter: Mutex::new(sender_limiter),
            budget_limiter: Mutex::new(BudgetLimiter::new()),
            gauges: metrics::PluginGauges::new(),
        })
    }

    /// Clones the current config's snapshot for route `name`, if any --
    /// cuts the noise of a `cfg.read()...find()` at every `process_due`-style
    /// call site while keeping the returned value fully owned (no borrow
    /// tying the caller to the read guard), so it's safe to hold across
    /// subsequent store/plugins lock acquisitions.
    pub fn route_cfg(&self, name: &str) -> Option<RouteConfig> {
        self.cfg.read().unwrap().routes.iter().find(|r| r.name == name).cloned()
    }

    /// Runs `f` against a read guard on the current config and returns
    /// whatever it computes -- `f` should copy out owned values (clones of
    /// small fields, or `Copy` numbers/strings), never return or retain a
    /// borrow into the config. The read guard is dropped the moment `f`
    /// returns, before the caller can acquire any other lock, which is what
    /// keeps this safe to call from anywhere without violating the lock
    /// order documented on `Daemon::cfg`.
    pub fn cfg_snapshot<T>(&self, f: impl FnOnce(&Config) -> T) -> T {
        f(&self.cfg.read().unwrap())
    }

    /// Hot-swaps `cfg` under the write lock (design §1): computes
    /// `restart_required` from the OLD config (plugin names whose
    /// `{command, config, enabled}` changed, plus added/removed plugin
    /// names, plus `"daemon"` if any `node.*` field changed -- data_dir in
    /// particular, since the plugin/admin socket paths are derived from it
    /// at startup and never re-bound), swaps in `new`, then -- OUTSIDE the
    /// write lock, so this never holds `cfg` while taking another lock --
    /// rebuilds `sender_limiter` from the new per-sender numbers, resets
    /// `budget_limiter`'s windows, and pushes the new dedup TTL into
    /// `dedup` via `set_ttl` (affects only entries recorded from this point
    /// on; entries already recorded keep aging out under whatever TTL was
    /// in effect when they were recorded -- see `dedup::Dedup::set_ttl`).
    /// Routes/policies/limits/render/identity_mode/public_services/
    /// transport_budgets need no explicit action here: every reader goes
    /// through `cfg.read()`/`cfg_snapshot`/`route_cfg`, so they see `new`'s
    /// values on their very next call. Callers are responsible for having
    /// already validated `new` (see `config::validate`) -- this method
    /// trusts it as-is and never fails.
    #[allow(dead_code)]
    // consumed by admin `PUT /v1/config` / `POST /v1/config/rollback`
    // (Task 3); remove allow once those handlers call this.
    pub fn apply_config(&self, new: Config) -> ApplyOutcome {
        let mut restart_required = Vec::new();
        let (dedup_ttl_secs, sender_mm, sender_bph) = {
            let mut cfg = self.cfg.write().unwrap();
            if cfg.node != new.node {
                restart_required.push("daemon".to_string());
            }
            let old_names: BTreeSet<&String> = cfg.plugins.keys().collect();
            let new_names: BTreeSet<&String> = new.plugins.keys().collect();
            for name in old_names.difference(&new_names) {
                restart_required.push((*name).clone());
            }
            for name in new_names.difference(&old_names) {
                restart_required.push((*name).clone());
            }
            for name in old_names.intersection(&new_names) {
                if cfg.plugins[*name] != new.plugins[*name] {
                    restart_required.push((*name).clone());
                }
            }
            let dedup_ttl_secs = new.dedup_ttl_secs;
            let sender_mm = new.limits.per_sender.messages_per_minute;
            let sender_bph = new.limits.per_sender.bytes_per_hour;
            *cfg = new;
            (dedup_ttl_secs, sender_mm, sender_bph)
        };
        *self.sender_limiter.lock().unwrap() = SenderLimiter::new(sender_mm, sender_bph);
        *self.budget_limiter.lock().unwrap() = BudgetLimiter::new();
        self.dedup.lock().unwrap().set_ttl(std::time::Duration::from_secs(dedup_ttl_secs));
        restart_required.sort();
        restart_required.dedup();
        ApplyOutcome { restart_required }
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
    priority: Option<String>,
) {
    metrics::inc(&metrics::INGRESS);

    // Snapshot every config value this call needs, up front, in one read-lock
    // acquisition (lock discipline: never hold the cfg read guard while
    // taking the dedup/sender_limiter/store locks below, or across the
    // .await points elsewhere in this module) -- `routes` is the one
    // non-trivial clone (a `Vec<RouteConfig>`), everything else is Copy.
    let (max_attachment_bytes, ttl_default_secs, hop_limit, routes_snapshot, route_max, global_max) =
        d.cfg_snapshot(|c| (
            c.max_attachment_bytes, c.ttl_default_secs, c.hop_limit, c.routes.clone(),
            c.limits.per_route.queue_max, c.limits.global.queue_max,
        ));

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
            let oversize = att.data.len() as u64 > max_attachment_bytes;
            let sha = hex::encode(Sha256::digest(&att.data));
            Hashed { att, sha, oversize }
        })
        .collect();
    let all_shas: Vec<String> = hashed.iter().map(|h| h.sha.clone()).collect();

    // Peek only (no insert yet): a message that turns out to be
    // rate-limited below must not be recorded as seen, or its retransmission
    // after the limit window clears would be silently swallowed as a
    // "duplicate" for the rest of the dedup TTL.
    let key = dedup::key(plugin, &sender, &endpoint, &body, created_at, &all_shas);
    if d.dedup.lock().unwrap().is_duplicate(&key, Instant::now()) {
        metrics::inc(&metrics::DUPLICATES);
        return;
    }

    // Sender quota (spec §45 per-sender rate limiting): keyed on the
    // (plugin, native_ref) pair, so distinct senders sharing a transport
    // don't share a budget. Bytes cover the body plus every attachment as
    // sent, including ones that will be dropped below for being oversize —
    // those bytes still crossed the wire and consumed ingress capacity.
    // Zero config (both dimensions 0, the default) always allows and never
    // touches the limiter's per-key state (see `SenderLimiter::allow`).
    // Applies to every priority class, emergency included — there is no
    // ingress bypass; the egress emergency bypass (see priority scheduling)
    // is scheduling-only and never lets a message skip this gate.
    let sender_bytes = body.len() as u64
        + hashed.iter().map(|h| h.att.data.len() as u64).sum::<u64>();
    let sender_key = format!("{plugin}|{sender}");
    if !d.sender_limiter.lock().unwrap().allow(&sender_key, sender_bytes, Instant::now()) {
        metrics::inc(&metrics::RATELIMITED);
        let prefix: String = sender.chars().take(8).collect();
        warn!(plugin, sender = %prefix, "sender rate limit exceeded, dropping message");
        return;
    }
    // Accepted by both dedup and the rate limiter: record now, before
    // routing/persistence. A message with no matching route still gets
    // recorded here (dedup for unrouted repeats is desirable — no point
    // re-evaluating the same unroutable message every retry).
    d.dedup.lock().unwrap().record(&key, Instant::now());
    let now = Utc::now();

    // Identity-link confirm interception (design §Lifecycle step 2): checked
    // after dedup/rate-limit, strictly before routing — a confirmation reply
    // is a verification round-trip, not chat content, and must never reach a
    // route destination. Only a body that is EXACTLY 6 ASCII digits after
    // trimming is even looked up against the challenge table, so a
    // non-numeric or wrong-length message never risks a false match (and
    // never touches find_active_challenge at all) and someone typing an
    // ordinary 6-digit string with no active challenge bound to THEM falls
    // straight through to normal routing below.
    let trimmed_body = body.trim();
    if trimmed_body.len() == 6 && trimmed_body.chars().all(|c| c.is_ascii_digit()) {
        let matched = match d.store.lock().unwrap()
            .find_active_challenge(plugin, &sender, trimmed_body, now)
        {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "failed to check identity challenge for inbound reply");
                None
            }
        };
        if let Some(challenge) = matched {
            confirm_link(d, challenge, now);
            return;
        }
    }

    let source = Endpoint { protocol: plugin.to_string(), endpoint };
    let targets: Vec<(String, Endpoint)> = routes::route(&routes_snapshot, &source)
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
                h.att.filename, max_attachment_bytes
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
            Err(e) if cas::is_budget_exceeded(&e) => {
                // Expected steady-state quota enforcement, not a failure —
                // no warn (mirrors the oversize-attachment branch above,
                // which also doesn't log): the filename is message content
                // and only ever belongs in the body note, never a log line.
                notes.push_str(&format!("\n[dropped {}: cas budget exceeded]", h.att.filename));
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
        now + CDuration::seconds(ttl_default_secs as i64),
        hop_limit,
    );
    env.attachments = metas;
    // The envelope keeps whatever the plugin actually sent (defaulted to
    // "normal" only when it sent nothing at all) — useful as-is for
    // diagnostics (e.g. a trace showing a plugin sent a typo'd class name).
    // `relay_core::priority_rank` is the single source of what counts as a
    // recognized class: it's the only place an unrecognized value gets
    // folded to the "normal" scheduling rank, so the DB's numeric ordering
    // is never out of step with this mapping.
    env.priority = priority.unwrap_or_else(|| "normal".to_string());
    let priority_rank = relay_core::priority_rank(&env.priority);
    let store = d.store.lock().unwrap();
    if let Err(e) = store.insert_message(&env) {
        warn!(error = %e, "failed to persist message");
        return;
    }
    if let Err(e) = store.insert_attachment_refs(env.id, &shas) {
        warn!(error = %e, "failed to persist attachment refs");
    }
    for (route, dest) in &targets {
        // Queue quotas (spec §45): per-route checked first (the tighter,
        // more actionable signal), then the global ceiling — checked fresh
        // for every target, so a message fanning out to several
        // destinations on the same over-quota route can't slip more than
        // one past the cap in a single call. A rejected delivery still gets
        // a row, straight into dead_letter/QUEUE_FULL, so it's visible in
        // queue_counts/admin status rather than silently vanishing the way
        // a rate-limited message does — deliberate: a full queue is
        // operationally interesting in a way a sender's own excess traffic
        // isn't.
        let over_route = route_max > 0
            && store.pending_count(Some(route.as_str())).unwrap_or(0) >= i64::from(route_max);
        let over_global = !over_route
            && global_max > 0
            && store.pending_count(None).unwrap_or(0) >= i64::from(global_max);
        if over_route || over_global {
            metrics::inc(&metrics::QUEUE_REJECTED);
            if let Err(e) = store.insert_dead_delivery(
                env.id, route, dest, now, env.expires_at, "QUEUE_FULL")
            {
                warn!(error = %e, "failed to record queue-full delivery");
            }
            warn!(route = %route, destination = %dest, "queue full, delivery rejected");
            continue;
        }
        if let Err(e) =
            store.insert_delivery(env.id, route, dest, now, env.expires_at, priority_rank)
        {
            warn!(error = %e, "failed to enqueue delivery");
        }
    }
    info!(id = %env.id, source = %env.source, targets = targets.len(),
          attachments = env.attachments.len(), "message accepted");
}

/// Initiates an identity-link challenge (design §Lifecycle step 1, admin API
/// or ctl — an operator/user-via-UI action, never implicit): validates that
/// `target`'s plugin is connected and advertises `capabilities.direct_messages`,
/// generates a 6-digit code, persists the challenge, and enqueues a
/// best-effort `SendDirect` carrying it to the target. Returns the challenge
/// id — NEVER the code itself, which only ever appears in the SendDirect
/// body (see `identity_links::generate_code`'s callers). Called by the admin
/// API's `POST /v1/identities/link` (Task 4).
pub fn initiate_link(
    d: &Daemon,
    requester: Endpoint,
    target: Endpoint,
    display_name: &str,
) -> Result<i64, String> {
    let direct_capable: Vec<String> = {
        let plugins = d.plugins.lock().unwrap();
        plugins.iter()
            .filter(|(_, h)| h.connected && h.capabilities.direct_messages)
            .map(|(name, _)| name.clone())
            .collect()
    };
    if !direct_capable.iter().any(|p| p == &target.protocol) {
        return Err(if direct_capable.is_empty() {
            "target plugin is not connected or does not support direct messages; \
             no currently-connected plugins support direct messages".to_string()
        } else {
            format!(
                "target plugin '{}' is not connected or does not support direct messages; \
                 currently direct-capable: {}",
                target.protocol, direct_capable.join(", ")
            )
        });
    }

    let code = identity_links::generate_code();
    let now = Utc::now();
    let expires = now + CDuration::minutes(15);
    let challenge_id = {
        let store = d.store.lock().unwrap();
        store.create_challenge(
            &code, &target.protocol, &target.endpoint,
            &requester.protocol, &requester.endpoint,
            display_name, now, expires,
        ).map_err(|e| e.to_string())?
    };

    // Masked per design §Lifecycle step 1's exact body wording: the target
    // sees who is asking to link, but never the requester's full ref.
    // RULING 2: protocol stays visible, only the ref is masked — "signal:****921A"
    // style, not `mask_ref` applied to the whole "proto:ref" string.
    let masked_requester =
        format!("{}:{}", requester.protocol, identity_links::mask_ref(&requester.endpoint));
    let body = format!(
        "RelayFabric verification code: {code} — reply with this code to link {masked_requester}. Ignore to refuse."
    );
    // RULING 1: the @identity route is reserved and exempt from the
    // per-route cap, but not from the global one — a queue-full rejection
    // here must surface to the caller rather than silently vanishing (the
    // challenge row above already exists, but its delivery never reaches
    // the target).
    enqueue_identity_send(d, target, body, now, expires)?;

    Ok(challenge_id)
}

/// Enqueues a best-effort delivery to `dest` (protocol + plugin-native ref)
/// via the reserved `IDENTITY_ROUTE` sentinel: synthesizes a "notice"
/// envelope carrying `body`, persists it, and queues one delivery row that
/// `process_due`'s identity-dispatch branch (see `process_due_identity`)
/// sends via `DaemonToPlugin::SendDirect` instead of the normal
/// `Send`/alias/render path — `dest.endpoint` is stored verbatim in
/// `dest_endpoint` and reused as the SendDirect `native_ref`. Used for both
/// challenge delivery (`initiate_link`) and confirmation notices
/// (`confirm_link`); a message-persistence or delivery-insert failure is
/// logged and swallowed (`Ok(())`), matching the "best-effort" posture the
/// design calls for — by the time this runs the challenge has already been
/// consumed/created, so a failure here must not unwind that.
///
/// RULING 1 (Task 3 review): the reserved `@identity` route is exempt from
/// the PER-ROUTE queue cap (deliberately never checked here), but not from
/// the GLOBAL one — the same `pending_count` comparison `handle_inbound`
/// uses for its own global check. Over cap, the insert becomes a
/// `dead_letter` row with reason `QUEUE_FULL` (still visible in
/// `queue_counts`/admin status rather than vanishing) and this returns
/// `Err("queue full")` so `initiate_link` can surface it to its caller;
/// `confirm_link`'s best-effort calls simply discard the `Err`.
fn enqueue_identity_send(
    d: &Daemon, dest: Endpoint, body: String, now: DateTime<Utc>, expires: DateTime<Utc>,
) -> Result<(), String> {
    let (hop_limit, global_max) = d.cfg_snapshot(|c| (c.hop_limit, c.limits.global.queue_max));
    let env = Envelope::new(
        Endpoint { protocol: IDENTITY_ROUTE.trim_start_matches('@').to_string(), endpoint: "system".to_string() },
        Sender { native_ref: IDENTITY_ROUTE.to_string() },
        "notice".to_string(),
        body,
        now,
        expires,
        hop_limit,
    );
    let store = d.store.lock().unwrap();
    if let Err(e) = store.insert_message(&env) {
        warn!(error = %e, "failed to persist identity notice message");
        return Ok(());
    }
    let over_global = global_max > 0
        && store.pending_count(None).unwrap_or(0) >= i64::from(global_max);
    if over_global {
        metrics::inc(&metrics::QUEUE_REJECTED);
        if let Err(e) = store.insert_dead_delivery(
            env.id, IDENTITY_ROUTE, &dest, now, expires, "QUEUE_FULL")
        {
            warn!(error = %e, "failed to record queue-full identity delivery");
        }
        warn!(destination = %format!("{}:{}", dest.protocol, identity_links::mask_ref(&dest.endpoint)),
              "queue full, identity delivery rejected");
        return Err("queue full".to_string());
    }
    if let Err(e) = store.insert_delivery(env.id, IDENTITY_ROUTE, &dest, now, expires,
        relay_core::priority_rank(&env.priority))
    {
        warn!(error = %e, "failed to enqueue identity notice delivery");
    }
    Ok(())
}

/// Handles an inbound reply whose trimmed body matched an active challenge
/// (see `handle_inbound`'s confirm interception, design §Lifecycle step 2):
/// consumes the challenge (a code is never replayable, win or lose),
/// enforces one-link-per-identity replace semantics (a fresh confirmation
/// supersedes any existing link touching either party — a re-link
/// supersedes rather than stacking a second link), inserts the new link, and
/// enqueues best-effort confirmation notices to both parties via
/// `IDENTITY_ROUTE`. The confirming message itself is never routed further.
fn confirm_link(d: &Daemon, challenge: storage::Challenge, now: DateTime<Utc>) {
    {
        let store = d.store.lock().unwrap();
        // Consume first: whatever happens below, this code must not be
        // usable a second time.
        if let Err(e) = store.delete_challenge(challenge.id) {
            warn!(error = %e, "failed to consume identity challenge");
        }

        // One-link-per-identity: delete any existing link(s) touching
        // either party before inserting the new one (replace, not stack).
        for (proto, r) in [
            (challenge.target_protocol.as_str(), challenge.target_ref.as_str()),
            (challenge.requester_protocol.as_str(), challenge.requester_ref.as_str()),
        ] {
            if let Ok(Some(existing)) = store.link_for_identity(proto, r) {
                if let Err(e) = store.delete_link(existing.id) {
                    warn!(error = %e, "failed to delete superseded identity link");
                }
            }
        }

        if let Err(e) = store.insert_link(
            &challenge.target_protocol, &challenge.target_ref,
            &challenge.requester_protocol, &challenge.requester_ref,
            &challenge.display_name, now,
        ) {
            warn!(error = %e, "failed to persist identity link");
            return;
        }
    }

    metrics::inc(&metrics::LINKS_VERIFIED);
    // RULING 2: unify on the same compound "protocol:masked_ref" convention
    // as the response/notice bodies below — protocol stays visible, only
    // the ref is masked. Codes still never appear in a log line.
    info!(target = %format!("{}:{}", challenge.target_protocol,
                             identity_links::mask_ref(&challenge.target_ref)),
          requester = %format!("{}:{}", challenge.requester_protocol,
                                identity_links::mask_ref(&challenge.requester_ref)),
          "identity link verified");

    let masked_requester = format!("{}:{}", challenge.requester_protocol,
        identity_links::mask_ref(&challenge.requester_ref));
    let masked_target = format!("{}:{}", challenge.target_protocol,
        identity_links::mask_ref(&challenge.target_ref));
    let expires = now + CDuration::seconds(d.cfg_snapshot(|c| c.ttl_default_secs) as i64);

    // Best-effort (design §Lifecycle step 2): a queue-full rejection here
    // (RULING 1) dead-letters the notice but must not undo the link that
    // was just confirmed, so the Result is deliberately discarded.
    let _ = enqueue_identity_send(
        d,
        Endpoint { protocol: challenge.target_protocol.clone(), endpoint: challenge.target_ref.clone() },
        format!(
            "RelayFabric: identity link confirmed with {masked_requester} as \"{}\".",
            challenge.display_name
        ),
        now, expires,
    );
    let _ = enqueue_identity_send(
        d,
        Endpoint { protocol: challenge.requester_protocol.clone(), endpoint: challenge.requester_ref.clone() },
        format!(
            "RelayFabric: {masked_target} confirmed the identity link as \"{}\".",
            challenge.display_name
        ),
        now, expires,
    );
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
        // Route counter + delivery latency (design §3): looked up from the
        // delivery/message rows before the state flip below, though the
        // flip's own 'attempting'-only guard means these two are
        // best-effort like EGRESS just above (a late/duplicate delivered
        // ack that the guard silently ignores still bumps these, exactly
        // as it already bumps EGRESS) -- not worth a second query to
        // detect that rare, harmless double-count.
        if let Some(delivery) = store.deliveries_for_id(corr) {
            metrics::inc_route(&delivery.route);
            if let Ok(Some(env)) = store.get_message(delivery.message_id) {
                // Fabric-internal latency only: `created_at` is whatever the
                // remote sender's clock claims (meshtastic MQTT `timestamp`,
                // meshcore `sender_timestamp`, signal `ts`), unclamped and
                // untrusted. A node with a wrong/epoch-0 RTC would otherwise
                // poison this process-lifetime sum permanently. `received_at`
                // is stamped by us at ingestion (`Envelope::new`) and is the
                // only honest measurement of how long delivery took.
                metrics::record_latency(Utc::now() - env.received_at);
            }
        }
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
            // retention is hardcoded to 24h; making it configurable
            // is the upgrade path once there's an actual
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
            // Expired challenges (15-min TTL, design §Security invariants):
            // swept on the same hourly cadence as the retention purge above
            // rather than a dedicated timer — an unconfirmed challenge is
            // already unusable past its expiry (find_active_challenge checks
            // it live), so this is disk hygiene, not a correctness gate.
            match d.store.lock().unwrap().purge_expired_challenges(now) {
                Ok(n) => {
                    if n > 0 {
                        info!(purged = n, "purged expired identity-link challenges");
                    }
                }
                Err(e) => warn!(error = %e, "expired challenge purge failed"),
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
    if del.route == IDENTITY_ROUTE {
        process_due_identity(d, del, env, now).await;
        return;
    }
    // Cloned out (not read live inline in the `match`): a `d.cfg.read()`
    // temporary would otherwise live for the whole match expression (every
    // arm, per Rust's temporary-lifetime rules), and the Allow arm below
    // takes the plugins/store/budget_limiter locks -- exactly the
    // cfg-guard-held-across-other-locks pattern the lock order forbids.
    let policies = d.cfg_snapshot(|c| c.policies.clone());
    match policy::evaluate(&policies, &env, &del.destination) {
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

            // Transport egress budget (spec §4/§45): a per-protocol cap on
            // sends-per-minute, independent of the sender-side and queue
            // quotas above (those gate what gets *accepted*; this gates what
            // gets *sent out*, so a route with slow/expensive egress -
            // meshtastic airtime, a metered uplink - can't be saturated by a
            // burst that already made it into the queue). Priority 0
            // (emergency) bypasses this check entirely, including the
            // recording `allow` would otherwise do — life-safety traffic
            // must never wait behind a transport's throughput cap, and
            // spending emergency sends against the budget would also let a
            // flood of them starve everything else out from behind the
            // bypass. A protocol with no configured budget always allows
            // (see `BudgetLimiter::allow`) and never checks priority.
            if del.priority > 0 {
                let per_minute = d.cfg_snapshot(|c| c.transport_budgets
                    .get(&del.destination.protocol)
                    .map(|b| b.messages_per_minute)
                    .unwrap_or(0));
                let allowed = d.budget_limiter.lock().unwrap()
                    .allow(&del.destination.protocol, per_minute, Instant::now());
                if !allowed {
                    metrics::inc(&metrics::BUDGET_DEFERRED);
                    let result = d.store.lock().unwrap()
                        .mark_retry(del.id, now + CDuration::seconds(10));
                    warn_if_mark_failed(del.id, "pending", result);
                    return;
                }
            }

            let limit = match (max_payload, cap_limit) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let alias = d.aliaser.alias(
                &env.source.protocol, &env.sender.native_ref, &del.route);

            // Rendering (design §Rendering): a route explicitly opted into
            // "linked" mode AND a verified link connecting this envelope's
            // (source protocol, native_ref) to some identity swaps the tag
            // from the HMAC alias to that link's display_name. The link
            // lookup is live (not cached) on every send, so an unlink
            // reverts rendering to the pseudonym on the very next delivery
            // (design §95/§22) — no link, or the route stayed
            // "pseudonymous" (the default, backward-compatible with configs
            // that predate this field), and the alias is used exactly as
            // before.
            // Owned clone (`Daemon::route_cfg`), not a borrow into a cfg
            // read guard: `linked_mode` below takes the store lock while
            // this is still in scope, and `render_tag`/`render_max_chars`
            // further down need it too -- an `Option<&RouteConfig>` tied to
            // a live read guard would hold that guard across all of it.
            let route_cfg = d.route_cfg(&del.route);
            let linked_mode = route_cfg.as_ref().map(|r| r.identity_mode == "linked").unwrap_or(false);
            let tag = if linked_mode {
                let link = d.store.lock().unwrap()
                    .link_for_identity(&env.source.protocol, &env.sender.native_ref)
                    .unwrap_or(None);
                link.map(|l| l.display_name).unwrap_or_else(|| alias.clone())
            } else {
                alias.clone()
            };
            // Design §4: `render.tag == "none"` means the route opted out
            // of tags altogether, suppressing whichever of the alias/
            // display_name `tag` above resolved to. `render.max_chars`
            // (0 = disabled) is a route-level, BODY-ONLY char-count
            // truncation (fix round 1) — applied to `env.body` below,
            // BEFORE the tag is assembled and BEFORE attachment notes are
            // appended, so neither the tag (which has no length cap
            // anywhere — a linked `display_name` could be arbitrarily long)
            // nor the notes are ever eaten by it; see `transform::
            // truncate_body`'s doc comment for why an earlier ruling that
            // truncated the assembled `"[tag]\nbody"` string was reverted.
            let render_tag = match route_cfg.as_ref().map(|r| r.render.tag.as_str()) {
                Some("none") => None,
                _ => Some(tag.as_str()),
            };
            let render_max_chars = route_cfg
                .as_ref()
                .and_then(|r| (r.render.max_chars > 0).then_some(r.render.max_chars));

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
            // Decision: `env.body` is route-level `max_chars`-truncated
            // FIRST (fix round 1: body-only, never touches the tag), THEN
            // notes (capability/policy strip, byte-cap drops, CAS misses)
            // are appended — so notes are NEVER counted toward the
            // max_chars budget (a dropped-attachment note must reliably
            // reach the recipient even when the body itself had to shrink
            // to fit). The resulting body+notes is folded together BEFORE
            // max_payload truncation runs, not appended after — so a
            // note-inflated body still respects the destination's byte cap
            // instead of the notes sneaking past it by arriving
            // post-truncation. That does mean a very tight transport cap
            // can truncate a note away entirely, and — unlike max_chars —
            // CAN truncate into the tag too; that is the correct trade-off
            // since the byte cap is the harder constraint the plugin
            // actually enforces on the wire (pre-existing v0.1 behavior,
            // unrelated to the route-level max_chars knob).
            let truncated_body = match render_max_chars {
                Some(mc) => transform::truncate_body(&env.body, mc),
                None => env.body.clone(),
            };
            let body = transform::render(
                render_tag, &format!("{truncated_body}{notes}"), limit);
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

/// Delivers an `IDENTITY_ROUTE` envelope (a challenge or confirmation
/// notice, queued by `enqueue_identity_send`) via
/// `DaemonToPlugin::SendDirect` instead of the normal `Send`/alias/render
/// path — `del.destination.endpoint` holds the plugin-native ref to deliver
/// to, not a route endpoint. Reuses the same connectivity check, transport
/// budget, `mark_attempting`, and try_send-backpressure-requeue machinery as
/// the ordinary path in `process_due` above (retry/backoff on failure and
/// TTL expiry — checked by the caller before this is reached — are
/// identical), but skips policy evaluation, aliasing, and attachment
/// handling: these are daemon-generated system notices with no attachments
/// and no user-content policy to apply. Additionally requires
/// `capabilities.direct_messages` on the destination plugin (an ordinary
/// `Send` never checks this) since `SendDirect` is only ever handled by
/// direct-capable plugins.
///
/// Finding 2 (whole-branch review): only the TARGET's capability is checked
/// up front, at `initiate_link` — the REQUESTER-side confirmation notice
/// `confirm_link` enqueues is never capability-checked before it lands here,
/// and today only LXMF is direct-capable, so "requester's plugin is
/// connected but not direct-capable" is the common case, not an edge case.
/// A plugin that's connected but lacks the capability is never going to
/// grow it by reconnecting, so that case dead-letters promptly with
/// `NOT_DIRECT_CAPABLE` instead of retrying every 5s until the delivery's
/// TTL (24h by default, ~17k attempts of pure churn). A genuinely
/// disconnected plugin MAY reconnect before the TTL, so that case keeps the
/// existing retry posture.
async fn process_due_identity(
    d: &Arc<Daemon>, del: storage::Delivery, env: Envelope, now: DateTime<Utc>,
) {
    enum Readiness {
        Ready(mpsc::Sender<DaemonToPlugin>),
        Disconnected,
        NotDirectCapable,
    }
    let readiness = {
        let plugins = d.plugins.lock().unwrap();
        match plugins.get(&del.destination.protocol) {
            Some(h) if h.connected && h.capabilities.direct_messages => Readiness::Ready(h.tx.clone()),
            Some(h) if h.connected => Readiness::NotDirectCapable,
            _ => Readiness::Disconnected,
        }
    };
    let tx = match readiness {
        Readiness::Ready(tx) => tx,
        Readiness::NotDirectCapable => {
            let result = d.store.lock().unwrap()
                .mark_terminal(del.id, "dead_letter", "NOT_DIRECT_CAPABLE");
            warn_if_mark_failed(del.id, "dead_letter", result);
            warn!(delivery = del.id, plugin = %del.destination.protocol,
                  "identity delivery dead-lettered: plugin connected but not direct-capable");
            return;
        }
        Readiness::Disconnected => {
            let result = d.store.lock().unwrap()
                .mark_retry(del.id, now + CDuration::seconds(5));
            warn_if_mark_failed(del.id, "pending", result);
            return;
        }
    };

    if del.priority > 0 {
        let per_minute = d.cfg_snapshot(|c| c.transport_budgets
            .get(&del.destination.protocol)
            .map(|b| b.messages_per_minute)
            .unwrap_or(0));
        let allowed = d.budget_limiter.lock().unwrap()
            .allow(&del.destination.protocol, per_minute, Instant::now());
        if !allowed {
            metrics::inc(&metrics::BUDGET_DEFERRED);
            let result = d.store.lock().unwrap()
                .mark_retry(del.id, now + CDuration::seconds(10));
            warn_if_mark_failed(del.id, "pending", result);
            return;
        }
    }

    let result = d.store.lock().unwrap().mark_attempting(del.id);
    warn_if_mark_failed(del.id, "attempting", result);
    let send = DaemonToPlugin::SendDirect {
        corr: del.id,
        native_ref: del.destination.endpoint.clone(),
        body: env.body,
    };
    // try_send, not send().await — see process_due's identical rationale
    // above: this pump task must never block on one plugin's channel.
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
    use crate::config::{
        Budget, Config, Limits, NodeConfig, PluginConfig, PublicService, RenderConfig, RouteConfig,
    };
    use std::collections::BTreeMap;

    pub fn test_daemon(dir: &std::path::Path) -> Daemon {
        test_daemon_full(dir, Limits::default(), BTreeMap::new(), false, vec![])
    }

    /// Like `test_daemon`, but with a caller-supplied `Limits` baked into the
    /// `Config` before `Daemon::new` runs. Needed (rather than mutating
    /// `d.cfg.limits` after construction, the way other tests tweak e.g.
    /// `d.cfg.max_attachment_bytes`) for anything that's read once at
    /// construction time and cached in daemon state — `sender_limiter`
    /// (bakes in `messages_per_minute`/`bytes_per_hour`) and `cas`'s budget
    /// — rather than re-read live from `d.cfg` on every call the way the
    /// queue-cap checks are.
    pub fn test_daemon_with_limits(dir: &std::path::Path, limits: Limits) -> Daemon {
        test_daemon_full(dir, limits, BTreeMap::new(), false, vec![])
    }

    /// Like `test_daemon`, but with caller-supplied `transport_budgets`.
    /// `BudgetLimiter` is re-read live from `d.cfg.transport_budgets` on
    /// every pump tick (unlike `sender_limiter`/`cas`, which cache their
    /// config at construction) — this only exists so budget tests don't have
    /// to spell out the full `Config` literal.
    pub fn test_daemon_with_budgets(
        dir: &std::path::Path, transport_budgets: BTreeMap<String, Budget>,
    ) -> Daemon {
        test_daemon_full(dir, Limits::default(), transport_budgets, false, vec![])
    }

    /// Like `test_daemon`, but with caller-supplied `node.public` and
    /// `public_services` — for admin `/v1/public` tests. `config::validate`
    /// is not run here (these build the `Config` literal directly, the way
    /// every other `test_daemon_*` helper does), so unlike a config loaded
    /// from disk, `public: true` with services that don't actually cover
    /// the fixture's `general` route is accepted at construction time.
    pub fn test_daemon_with_public(
        dir: &std::path::Path, public: bool, services: Vec<PublicService>,
    ) -> Daemon {
        test_daemon_full(dir, Limits::default(), BTreeMap::new(), public, services)
    }

    fn test_daemon_full(
        dir: &std::path::Path, limits: Limits, transport_budgets: BTreeMap<String, Budget>,
        public: bool, public_services: Vec<PublicService>,
    ) -> Daemon {
        let mut plugins = BTreeMap::new();
        for name in ["mocka", "mockb"] {
            plugins.insert(name.to_string(), PluginConfig {
                enabled: true, command: None, config: serde_yaml::Value::Null,
            });
        }
        let cfg = Config {
            node: NodeConfig { name: "t".into(), data_dir: dir.to_path_buf(), public },
            plugins,
            raw_plugin_configs: BTreeMap::new(),
            raw_yaml: String::new(),
            routes: vec![RouteConfig {
                name: "general".into(),
                sources: vec!["mocka:chan".parse().unwrap(), "mockb:chan".parse().unwrap()],
                destinations: vec!["mocka:chan".parse().unwrap(), "mockb:chan".parse().unwrap()],
                identity_mode: "pseudonymous".into(),
                render: RenderConfig::default(),
            }],
            policies: vec![],
            ttl_default_secs: 3600,
            dedup_ttl_secs: 3600,
            hop_limit: 8,
            max_attachment_bytes: 8 * 1024 * 1024,
            public_services,
            limits,
            transport_budgets,
        };
        Daemon::new(cfg, dir).unwrap()
    }

    /// Registers a connected mock plugin with (optionally) the `attachments`
    /// capability — shared by engine's own tests and admin.rs's Tower-oneshot
    /// tests (identity-link admin endpoints need a way to stand up a
    /// non-direct-capable plugin for the 409 rejection path).
    pub fn register_plugin(d: &Daemon, name: &str, attachments: bool) -> mpsc::Receiver<DaemonToPlugin> {
        let (tx, rx) = mpsc::channel(8);
        d.plugins.lock().unwrap().insert(name.to_string(), PluginHandle {
            tx,
            capabilities: Capabilities { attachments, ..Capabilities::default() },
            connected: true,
        });
        rx
    }

    /// Registers a connected mock plugin that advertises
    /// `capabilities.direct_messages` — shared by engine's own tests and
    /// admin.rs's Tower-oneshot tests for `POST /v1/identities/link`.
    pub fn register_direct_plugin(d: &Daemon, name: &str) -> mpsc::Receiver<DaemonToPlugin> {
        let (tx, rx) = mpsc::channel(8);
        d.plugins.lock().unwrap().insert(name.to_string(), PluginHandle {
            tx,
            capabilities: Capabilities { direct_messages: true, ..Capabilities::default() },
            connected: true,
        });
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests_support::{
        register_direct_plugin, register_plugin, test_daemon, test_daemon_with_budgets,
        test_daemon_with_limits,
    };

    #[test]
    fn inbound_routes_to_other_endpoint_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        // one delivery row, to mockb, none echoed to mocka
        let store = d.store.lock().unwrap();
        let counts = store.queue_counts().unwrap();
        assert_eq!(counts, vec![("pending".to_string(), 1)]);
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(due[0].destination.protocol, "mockb");
        drop(store);
        // duplicate is dropped
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(),
                   vec![("pending".to_string(), 1)]);
        // unrouted endpoint is dropped (deny by default)
        handle_inbound(&d, "mocka", "elsewhere".into(), "!a".into(), "text".into(),
                       "hi".into(), None, vec![], None);
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(),
                   vec![("pending".to_string(), 1)]);
    }

    /// A missing priority defaults the envelope's stored class to "normal";
    /// an unrecognized one (a plugin's typo, or a class this daemon version
    /// predates) is stored verbatim rather than silently rewritten — but
    /// either way `relay_core::priority_rank` is the only place the
    /// "unknown means normal" fallback applies, so both schedule at rank 2.
    #[test]
    fn inbound_priority_missing_or_unrecognized_both_schedule_at_the_normal_rank() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "no priority sent".into(), None, vec![], None);
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "typo'd priority".into(), None, vec![], Some("urgent".into()));

        let store = d.store.lock().unwrap();
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(due.len(), 2);
        assert!(due.iter().all(|d| d.priority == 2),
            "both a missing and an unrecognized priority must schedule at the normal rank");

        let envs: Vec<_> = due.iter()
            .map(|d| store.get_message(d.message_id).unwrap().unwrap())
            .collect();
        assert!(envs.iter().any(|e| e.priority == "normal"),
            "a missing priority must default the stored class to \"normal\"");
        assert!(envs.iter().any(|e| e.priority == "urgent"),
            "an unrecognized class name must be stored verbatim, not silently rewritten");
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
                .insert_delivery(ghost_id, "general", &dest, now, now + CDuration::hours(1), 2)
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
                       "hello".into(), None, vec![], None);
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
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().max_attachment_bytes = 16;

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
                       "hello".into(), None, vec![small, big], None);

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
                       "hi".into(), None, vec![att], None);

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
                       "first".into(), None, vec![shared.clone()], None);
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "second".into(), None, vec![shared], None);
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

    // register_plugin/register_direct_plugin moved to tests_support (shared
    // with admin.rs's Tower-oneshot tests for the identity-link admin
    // endpoints); re-imported below via `use tests_support::{...}`.

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
                       "look at this".into(), None, vec![att.clone()], None);
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
                       "look at this".into(), None, vec![att], None);
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
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().policies = vec![crate::config::Policy {
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
                       "look at this".into(), None, vec![att], None);
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
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().policies = vec![crate::config::Policy {
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
                       "look at this".into(), None, vec![att], None);
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
                       "look at this".into(), None, vec![att], None);
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
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().max_attachment_bytes = 16;

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
                       "hello".into(), Some(same_created_at), vec![a], None);
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), Some(same_created_at), vec![b], None);

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert_eq!(counts, vec![("pending".to_string(), 2)],
            "differing dropped attachments must not dedup-collide: {counts:?}");
    }

    #[test]
    fn inbound_over_per_route_queue_max_dead_letters_with_queue_full_reason() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relayfabric.db");
        let d = test_daemon_with_limits(dir.path(), crate::config::Limits {
            per_route: crate::config::PerRoute { queue_max: 1 },
            ..Default::default()
        });
        let before = metrics::QUEUE_REJECTED.load(std::sync::atomic::Ordering::Relaxed);

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "first".into(), None, vec![], None);
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "second".into(), None, vec![], None);

        let after = metrics::QUEUE_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        // QUEUE_REJECTED is a process-global counter shared by every test in
        // this binary's parallel run, so only a monotonic ">" check is safe
        // here (an exact +1 delta flakes when another test bumps the same
        // counter concurrently) -- the real, race-free proof that exactly
        // this test's rejection happened is the dead_letter row + QUEUE_FULL
        // reason asserted below, which only this test's own over-quota
        // delivery could have produced.
        assert!(after > before, "the second delivery must bump QUEUE_REJECTED");

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert!(counts.contains(&("pending".to_string(), 1)), "counts was {counts:?}");
        assert!(counts.contains(&("dead_letter".to_string(), 1)),
            "over-quota delivery must land dead_letter and stay visible in queue_counts: {counts:?}");

        // the dead-lettered row must carry QUEUE_FULL specifically, not just
        // any dead_letter reason.
        let raw = rusqlite::Connection::open(&db_path).unwrap();
        let reason: String = raw
            .query_row("SELECT reason FROM deliveries WHERE state = 'dead_letter'", [],
                       |r| r.get(0))
            .unwrap();
        assert_eq!(reason, "QUEUE_FULL");
    }

    /// design §3: a delivered message bumps `relayfabric_route_messages_total`
    /// for its route and contributes to the `delivery_latency_seconds`
    /// sum/count pair, computed from the envelope's daemon-stamped
    /// `received_at` (not the sender-controlled `created_at` -- see the
    /// poisoning regression test below).
    #[test]
    fn handle_result_delivered_records_route_counter_and_delivery_latency() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());

        // created_at is sender-controlled and, in this test, deliberately a
        // lie (2s in the past); received_at is stamped internally by
        // `Envelope::new` at roughly "now". If the recorded latency ever
        // tracked created_at again, this test's contribution to the sum
        // would be >= 2s instead of near-zero.
        let created_at = Utc::now() - CDuration::seconds(2);
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), Some(created_at), vec![], None);

        let due = { let store = d.store.lock().unwrap(); store.due_deliveries(Utc::now(), 10).unwrap() };
        assert_eq!(due.len(), 1);
        let delivery_id = due[0].id;
        assert_eq!(due[0].route, "general");
        d.store.lock().unwrap().mark_attempting(delivery_id).unwrap();

        let route_before =
            metrics::ROUTE_MESSAGES.lock().unwrap().get("general").copied().unwrap_or(0);
        let latency_count_before =
            metrics::DELIVERY_LATENCY_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        let latency_sum_before =
            metrics::DELIVERY_LATENCY_MICROS_SUM.load(std::sync::atomic::Ordering::Relaxed);

        handle_result(&d, delivery_id, true, None);

        let route_after =
            metrics::ROUTE_MESSAGES.lock().unwrap().get("general").copied().unwrap_or(0);
        let latency_count_after =
            metrics::DELIVERY_LATENCY_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        let latency_sum_after =
            metrics::DELIVERY_LATENCY_MICROS_SUM.load(std::sync::atomic::Ordering::Relaxed);

        // ROUTE_MESSAGES/DELIVERY_LATENCY_* are process-globals, same
        // reasoning as the QUEUE_REJECTED/BUDGET_DEFERRED fixes above: only
        // monotonic checks are safe under this binary's parallel test run.
        // The sum is additive-only (record_latency never subtracts), so an
        // upper bound generous enough to absorb concurrent tests' own
        // (real, small) contributions still catches the 2s-lie this test
        // planted in created_at: 1 minute is orders of magnitude more than
        // this in-process round trip takes, and orders of magnitude less
        // than the fake 2s would have contributed had created_at leaked in.
        assert!(route_after > route_before, "a delivered message must bump its route's counter");
        assert!(latency_count_after > latency_count_before);
        assert!(latency_sum_after < latency_sum_before + 60_000_000,
            "recorded latency must track received_at, not the lied-about \
             created_at: before={latency_sum_before} after={latency_sum_after}");

        let state = d.store.lock().unwrap().deliveries_for_id(delivery_id).unwrap().state;
        assert_eq!(state, "delivered");
    }

    /// Finding: `created_at` is remote-sender-controlled (meshtastic MQTT
    /// `timestamp`, meshcore `sender_timestamp`, signal `ts`) and arrives
    /// unclamped. A node reporting the Unix epoch would, under the old
    /// created_at-based computation, inflate the process-lifetime latency
    /// sum by ~56 years *permanently*. `received_at` is stamped by us at
    /// ingestion and is immune -- assert the recorded contribution stays
    /// small (well under an hour), not decades.
    #[test]
    fn handle_result_latency_ignores_sender_controlled_epoch_zero_created_at() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());

        let epoch_zero = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), Some(epoch_zero), vec![], None);

        let due = { let store = d.store.lock().unwrap(); store.due_deliveries(Utc::now(), 10).unwrap() };
        assert_eq!(due.len(), 1);
        let delivery_id = due[0].id;
        d.store.lock().unwrap().mark_attempting(delivery_id).unwrap();

        let latency_sum_before =
            metrics::DELIVERY_LATENCY_MICROS_SUM.load(std::sync::atomic::Ordering::Relaxed);

        handle_result(&d, delivery_id, true, None);

        let latency_sum_after =
            metrics::DELIVERY_LATENCY_MICROS_SUM.load(std::sync::atomic::Ordering::Relaxed);

        // 1 hour in micros: comfortably larger than any real in-process
        // latency (including concurrent tests' own small contributions to
        // this shared counter) and comfortably smaller than the ~56 years
        // an epoch-0 created_at would have contributed.
        const ONE_HOUR_MICROS: u64 = 3_600_000_000;
        assert!(latency_sum_after < latency_sum_before + ONE_HOUR_MICROS,
            "an epoch-0 created_at must not poison the latency metric: \
             before={latency_sum_before} after={latency_sum_after}");
    }

    #[test]
    fn inbound_over_sender_per_minute_limit_drops_second_message_and_bumps_metric() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(dir.path(), crate::config::Limits {
            per_sender: crate::config::PerSender { messages_per_minute: 1, bytes_per_hour: 0 },
            ..Default::default()
        });
        let before = metrics::RATELIMITED.load(std::sync::atomic::Ordering::Relaxed);

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "first".into(), None, vec![], None);
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "second".into(), None, vec![], None);

        let after = metrics::RATELIMITED.load(std::sync::atomic::Ordering::Relaxed);
        // ">" not an exact +1 delta: RATELIMITED is a process-global counter
        // that other tests in this binary's parallel run (e.g. the identity-
        // link confirm/rate-limit ordering test) also legitimately bump —
        // a real increment from this test's own action still guarantees
        // after > before regardless of what else the counter is doing
        // concurrently, so this stays a precise, non-flaky assertion.
        assert!(after > before, "the second message from the same sender must bump RATELIMITED");

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert_eq!(counts, vec![("pending".to_string(), 1)],
            "a rate-limited message must vanish entirely, not enqueue or dead-letter: {counts:?}");
    }

    /// A different sender on the same plugin must not share the rate-limited
    /// sender's budget: the limiter key is (plugin, native_ref), not just
    /// plugin.
    #[test]
    fn sender_rate_limit_does_not_bleed_across_senders() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(dir.path(), crate::config::Limits {
            per_sender: crate::config::PerSender { messages_per_minute: 1, bytes_per_hour: 0 },
            ..Default::default()
        });

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "from a".into(), None, vec![], None);
        handle_inbound(&d, "mocka", "chan".into(), "!b".into(), "text".into(),
                       "from b".into(), None, vec![], None);

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert_eq!(counts, vec![("pending".to_string(), 2)],
            "a different sender must get its own budget: {counts:?}");
    }

    #[test]
    fn inbound_drops_attachment_over_cas_budget_and_notes_it_but_message_still_flows() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(dir.path(), crate::config::Limits {
            global: crate::config::GlobalLimits { queue_max: 0, cas_max_bytes: 5 },
            ..Default::default()
        });

        let att = IpcAttachment {
            filename: "over-budget.bin".into(),
            mime: "application/octet-stream".into(),
            data: vec![0u8; 20], // over the 5-byte CAS budget, under the ingress size cap
        };
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![att], None);

        let store = d.store.lock().unwrap();
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(due.len(), 1, "message must still flow despite the dropped attachment");
        let env = store.get_message(due[0].message_id).unwrap().unwrap();
        assert!(env.attachments.is_empty(), "the over-budget attachment must not get a meta");
        assert!(
            env.body.contains("[dropped over-budget.bin: cas budget exceeded]"),
            "body was: {}", env.body
        );
    }

    #[tokio::test]
    async fn transport_budget_defers_the_send_over_it_and_emergency_bypasses() {
        let dir = tempfile::tempdir().unwrap();
        let mut budgets = std::collections::BTreeMap::new();
        budgets.insert("mockb".to_string(), crate::config::Budget { messages_per_minute: 2 });
        let d = Arc::new(test_daemon_with_budgets(dir.path(), budgets));
        let mut rx = register_plugin(&d, "mockb", false);

        // three normal-priority messages queued for mockb, a 2/minute budget.
        for body in ["one", "two", "three"] {
            handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                           body.into(), None, vec![], None);
        }
        let now = Utc::now();
        let dues = { let store = d.store.lock().unwrap(); store.due_deliveries(now, 10).unwrap() };
        assert_eq!(dues.len(), 3);
        assert!(dues.iter().all(|d| d.priority == 2), "these are all normal priority");
        let ids: Vec<i64> = dues.iter().map(|d| d.id).collect();

        let before = metrics::BUDGET_DEFERRED.load(std::sync::atomic::Ordering::Relaxed);
        for del in dues {
            process_due(&d, del, now).await;
        }
        let after = metrics::BUDGET_DEFERRED.load(std::sync::atomic::Ordering::Relaxed);
        // BUDGET_DEFERRED is a process-global counter shared by every test in
        // this binary's parallel run, so only a monotonic ">" check is safe
        // here (an exact +1 delta flakes when another test bumps the same
        // counter concurrently) -- the real, race-free proof that exactly
        // one of these three deliveries was deferred is the Send-count
        // assertion below (exactly two Sends, then an empty channel).
        assert!(after > before, "only the third send within the minute must be deferred");

        // the first two budget slots went out as real Sends...
        recv_send(&mut rx).await;
        recv_send(&mut rx).await;
        // ...and nothing else: the third never called try_send at all.
        assert!(matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "the budget-deferred delivery must not have produced a Send");

        // the deferred delivery (whichever of the three it was) must still be
        // 'pending' with its next_attempt pushed ~10s out, not immediately
        // due again and not dead-lettered.
        let deferred_id = ids[2];
        {
            let store = d.store.lock().unwrap();
            assert!(store.due_deliveries(now + CDuration::seconds(9), 10).unwrap()
                .iter().all(|d| d.id != deferred_id),
                "must not be due again before the ~10s budget backoff elapses");
            assert!(store.due_deliveries(now + CDuration::seconds(11), 10).unwrap()
                .iter().any(|d| d.id == deferred_id),
                "must be due again once the ~10s budget backoff has elapsed");
        }

        // an emergency send for the same over-budget destination must
        // bypass the check entirely and go out immediately.
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "urgent".into(), None, vec![], Some("emergency".into()));
        let now2 = Utc::now();
        let emergency_del = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(now2, 10).unwrap().into_iter()
                .find(|d| d.priority == 0)
                .expect("the emergency delivery must be immediately due")
        };
        process_due(&d, emergency_del, now2).await;
        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(body.contains("urgent"), "body was: {body}");
    }

    // ---- identity linking: initiate_link ----------------------------------

    #[test]
    fn initiate_link_rejects_target_without_direct_messages_and_names_direct_capable_plugins() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        // "mocka" is connected and direct-capable; "mockb" is connected but
        // only has the attachments capability, not direct_messages.
        let _rx_a = register_direct_plugin(&d, "mocka");
        let _rx_b = register_plugin(&d, "mockb", false);

        let requester: Endpoint = "mockb:!req".parse().unwrap();
        let target: Endpoint = "mockb:!target-secret".parse().unwrap();
        let err = initiate_link(&d, requester, target, "Jascha").unwrap_err();

        assert!(err.contains("mocka"), "err must name the direct-capable plugin: {err}");
        assert!(!err.contains("!target-secret"), "err must never leak the target ref: {err}");
    }

    #[test]
    fn initiate_link_rejects_when_no_plugin_is_direct_capable() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let _rx = register_plugin(&d, "mocka", false); // connected, not direct-capable

        let requester: Endpoint = "mocka:!req".parse().unwrap();
        let target: Endpoint = "mocka:!target".parse().unwrap();
        let err = initiate_link(&d, requester, target, "Jascha").unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn initiate_link_rejects_when_target_plugin_is_not_connected_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let _rx = register_direct_plugin(&d, "mocka"); // direct-capable, but a different protocol

        let requester: Endpoint = "mocka:!req".parse().unwrap();
        let target: Endpoint = "ghost:!target".parse().unwrap();
        let err = initiate_link(&d, requester, target, "Jascha").unwrap_err();
        assert!(err.contains("mocka"), "err must still name the direct-capable plugins that ARE connected: {err}");
    }

    #[test]
    fn initiate_link_error_path_creates_no_challenge_or_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let requester: Endpoint = "mocka:!req".parse().unwrap();
        let target: Endpoint = "mockb:!target".parse().unwrap();
        assert!(initiate_link(&d, requester, target, "Jascha").is_err());

        let due = d.store.lock().unwrap().due_deliveries(Utc::now(), 10).unwrap();
        assert!(due.iter().all(|de| de.route != IDENTITY_ROUTE),
            "a rejected initiate_link must not enqueue an @identity delivery");
    }

    #[tokio::test]
    async fn initiate_link_creates_challenge_and_delivers_masked_code_via_send_direct() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let mut rx = register_direct_plugin(&d, "mockb");

        let requester: Endpoint = "mocka:+15551234567".parse().unwrap();
        let target: Endpoint = "mockb:+15559876543".parse().unwrap();
        let challenge_id = initiate_link(&d, requester, target, "Jascha").unwrap();
        assert!(challenge_id > 0);

        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(now, 10).unwrap().into_iter()
                .find(|de| de.route == IDENTITY_ROUTE)
                .expect("challenge delivery must be queued on the @identity route")
        };
        assert_eq!(del.destination.protocol, "mockb");
        assert_eq!(del.destination.endpoint, "+15559876543",
            "the target's native_ref must be stored in dest_endpoint");

        process_due(&d, del, now).await;
        let DaemonToPlugin::SendDirect { native_ref, body, .. } = recv_send(&mut rx).await else {
            panic!("expected SendDirect");
        };
        assert_eq!(native_ref, "+15559876543");
        assert!(body.contains("RelayFabric verification code:"), "body was: {body}");
        assert!(!body.contains("+15551234567"),
            "the requester's full ref must never appear in the challenge body: {body}");

        let code = body.split("code: ").nth(1).unwrap().split(' ').next().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        let found = d.store.lock().unwrap()
            .find_active_challenge("mockb", "+15559876543", code, now).unwrap();
        assert!(found.is_some(), "the code in the SendDirect body must match the stored challenge");
    }

    /// RULING 1 (Task 3 review): `enqueue_identity_send` must respect the
    /// GLOBAL queue cap exactly like `handle_inbound`'s own check — an
    /// @identity delivery queued while the global queue is already at
    /// capacity must dead-letter with QUEUE_FULL (visible, not silently
    /// dropped) and `initiate_link` must surface the rejection instead of
    /// claiming success. The per-route cap deliberately does not apply (the
    /// route is reserved), so this only exercises the global one.
    #[test]
    fn initiate_link_over_global_queue_cap_dead_letters_and_returns_queue_full() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relayfabric.db");
        let d = test_daemon_with_limits(dir.path(), crate::config::Limits {
            global: crate::config::GlobalLimits { queue_max: 1, ..Default::default() },
            ..Default::default()
        });
        let _rx = register_direct_plugin(&d, "mockb");

        // fill the global queue to its cap of 1 with an ordinary routed message
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(),
            vec![("pending".to_string(), 1)]);

        let requester: Endpoint = "mocka:!req".parse().unwrap();
        let target: Endpoint = "mockb:!target".parse().unwrap();
        let err = initiate_link(&d, requester, target, "Jascha").unwrap_err();
        assert_eq!(err, "queue full");

        // the @identity delivery landed dead_letter with QUEUE_FULL, not
        // silently dropped (same visibility contract as the per-route case).
        let raw = rusqlite::Connection::open(&db_path).unwrap();
        let reason: String = raw.query_row(
            "SELECT reason FROM deliveries WHERE route = '@identity' AND state = 'dead_letter'",
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(reason, "QUEUE_FULL");
    }

    /// The same cap applies to `confirm_link`'s best-effort notices, but a
    /// queue-full rejection there must not unwind the link that was just
    /// verified — the link itself has nothing to do with delivery capacity.
    #[test]
    fn confirm_link_over_global_queue_cap_dead_letters_notices_but_still_confirms_link() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(dir.path(), crate::config::Limits {
            global: crate::config::GlobalLimits { queue_max: 1, ..Default::default() },
            ..Default::default()
        });
        let now = Utc::now();
        seed_challenge(&d, ("mockb", "!target"), ("mocka", "!req"), "424242", "Jascha", now, 15);

        // fill the global queue to its cap of 1
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);

        handle_inbound(&d, "mockb", "chan".into(), "!target".into(), "text".into(),
                       "424242".into(), None, vec![], None);

        let link = d.store.lock().unwrap().link_for_identity("mockb", "!target").unwrap();
        assert!(link.is_some(),
            "the link must still be confirmed even when both notices are queue-capped");

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert!(counts.contains(&("dead_letter".to_string(), 2)),
            "both best-effort confirmation notices must dead-letter with QUEUE_FULL: {counts:?}");
    }

    // ---- identity linking: confirm interception ----------------------------

    fn seed_challenge(
        d: &Daemon, target: (&str, &str), requester: (&str, &str),
        code: &str, display_name: &str, now: DateTime<Utc>, ttl_minutes: i64,
    ) -> i64 {
        d.store.lock().unwrap().create_challenge(
            code, target.0, target.1, requester.0, requester.1,
            display_name, now, now + CDuration::minutes(ttl_minutes),
        ).unwrap()
    }

    #[test]
    fn confirm_right_sender_and_code_creates_link_and_does_not_route() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();
        seed_challenge(&d, ("mockb", "!target"), ("mocka", "!req"), "424242", "Jascha", now, 15);

        // LINKS_VERIFIED is a process-global counter shared by every test in
        // this binary's parallel run, so only a monotonic ">" check is safe
        // here (an exact +1 delta would be racy against any other test
        // touching the same counter concurrently) — the real, race-free
        // proof that exactly one confirmation happened is the due_deliveries
        // count assertion below (confirm_link enqueues a fresh, non-dedup'd
        // row per call, so a double-fire would show up as 4 rows, not 2).
        let before = metrics::LINKS_VERIFIED.load(std::sync::atomic::Ordering::Relaxed);
        handle_inbound(&d, "mockb", "chan".into(), "!target".into(), "text".into(),
                       "424242".into(), None, vec![], None);
        let after = metrics::LINKS_VERIFIED.load(std::sync::atomic::Ordering::Relaxed);
        assert!(after > before, "LINKS_VERIFIED must bump");

        let link = d.store.lock().unwrap().link_for_identity("mockb", "!target").unwrap();
        assert_eq!(link.unwrap().display_name, "Jascha");

        // Not routed: the "general" route (mockb:chan -> mocka:chan) would
        // otherwise have produced a delivery for this exact inbound. Only
        // the two best-effort @identity confirmation notices are queued.
        let due = d.store.lock().unwrap().due_deliveries(Utc::now(), 10).unwrap();
        assert!(due.iter().all(|de| de.route == IDENTITY_ROUTE),
            "the confirming message itself must never be routed: {due:?}");
        assert_eq!(due.len(), 2, "one confirmation notice per party: {due:?}");
    }

    #[test]
    fn confirm_wrong_sender_does_not_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();
        seed_challenge(&d, ("mockb", "!target"), ("mocka", "!req"), "424242", "Jascha", now, 15);

        // same protocol, same code, but a DIFFERENT native ref replying.
        handle_inbound(&d, "mockb", "chan".into(), "!someone-else".into(), "text".into(),
                       "424242".into(), None, vec![], None);

        assert!(d.store.lock().unwrap().link_for_identity("mockb", "!target").unwrap().is_none(),
            "a third party sending the code must not confirm the link");
        assert!(d.store.lock().unwrap()
            .find_active_challenge("mockb", "!target", "424242", Utc::now()).unwrap().is_some(),
            "the real target's challenge must remain active");
    }

    #[test]
    fn confirm_wrong_code_does_not_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();
        seed_challenge(&d, ("mockb", "!target"), ("mocka", "!req"), "424242", "Jascha", now, 15);

        handle_inbound(&d, "mockb", "chan".into(), "!target".into(), "text".into(),
                       "999999".into(), None, vec![], None);

        assert!(d.store.lock().unwrap().link_for_identity("mockb", "!target").unwrap().is_none());
        assert!(d.store.lock().unwrap()
            .find_active_challenge("mockb", "!target", "424242", Utc::now()).unwrap().is_some(),
            "the real code must remain valid after a wrong-code attempt");
    }

    #[test]
    fn confirm_expired_challenge_does_not_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let past = Utc::now() - CDuration::minutes(30);
        // expires_at = past + 15min, still in the past relative to "now" below.
        seed_challenge(&d, ("mockb", "!target"), ("mocka", "!req"), "424242", "Jascha", past, 15);

        handle_inbound(&d, "mockb", "chan".into(), "!target".into(), "text".into(),
                       "424242".into(), None, vec![], None);

        assert!(d.store.lock().unwrap().link_for_identity("mockb", "!target").unwrap().is_none(),
            "an expired challenge must not confirm");
    }

    #[test]
    fn confirm_non_matching_six_digit_body_routes_normally() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        // no active challenge at all for this sender.
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "123456".into(), None, vec![], None);

        let due = d.store.lock().unwrap().due_deliveries(Utc::now(), 10).unwrap();
        assert_eq!(due.len(), 1,
            "a 6-digit body with no active challenge bound to the sender must route normally, not vanish");
        assert_eq!(due[0].route, "general");
        assert_eq!(due[0].destination.protocol, "mockb");
    }

    #[test]
    fn confirm_non_numeric_or_wrong_length_bodies_are_never_intercepted() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();
        seed_challenge(&d, ("mocka", "!a"), ("mockb", "!req"), "424242", "Jascha", now, 15);

        for body in ["42424", "4242422", "42424a", "abcdef", " 424242a"] {
            handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                           body.into(), None, vec![], None);
            assert!(
                d.store.lock().unwrap()
                    .find_active_challenge("mocka", "!a", "424242", Utc::now()).unwrap().is_some(),
                "body {body:?} must never consume the active challenge"
            );
        }
        assert!(d.store.lock().unwrap().link_for_identity("mocka", "!a").unwrap().is_none());
    }

    #[test]
    fn confirm_interception_is_gated_by_the_sender_rate_limit() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(dir.path(), crate::config::Limits {
            per_sender: crate::config::PerSender { messages_per_minute: 1, bytes_per_hour: 0 },
            ..Default::default()
        });
        let now = Utc::now();
        seed_challenge(&d, ("mocka", "!a"), ("mockb", "!req"), "424242", "Jascha", now, 15);

        // first message from "!a" consumes the 1/minute budget.
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);

        // the confirming code, from the SAME sender, right after: must be
        // rate-limited before it ever reaches the confirm check. RATELIMITED
        // is a process-global counter also touched by other tests running
        // concurrently in this binary, so the real, race-free proof here is
        // the challenge-still-active assertion below: if the confirm check
        // had run for this second message (i.e. the rate limiter did NOT
        // gate it first), the challenge would have been consumed.
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "424242".into(), None, vec![], None);

        assert!(d.store.lock().unwrap()
            .find_active_challenge("mocka", "!a", "424242", Utc::now()).unwrap().is_some(),
            "a rate-limited confirm attempt must not consume the challenge");
    }

    #[test]
    fn confirm_interception_is_gated_by_dedup_a_replayed_confirm_only_confirms_once() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();
        seed_challenge(&d, ("mocka", "!a"), ("mockb", "!req"), "424242", "Jascha", now, 15);

        for _ in 0..2 {
            // identical args each call -> identical dedup key.
            handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                           "424242".into(), None, vec![], None);
        }

        // confirm_link's insert_delivery calls are NOT dedup'd/idempotent
        // (unlike insert_link's ON CONFLICT replace) — a second real
        // confirm_link run would double the confirmation notices to 4. This
        // is a race-free, per-test-isolated proxy for "confirmed exactly
        // once" (LINKS_VERIFIED is a process-global counter shared with
        // other concurrently-running tests, so it isn't a safe signal here).
        let due = d.store.lock().unwrap().due_deliveries(Utc::now(), 10).unwrap();
        assert_eq!(due.iter().filter(|de| de.route == IDENTITY_ROUTE).count(), 2,
            "an exact-duplicate replay of the confirming message must be swallowed by dedup, not re-confirmed");
    }

    #[test]
    fn one_link_per_identity_replace_covers_both_the_target_and_requester_sides() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();

        // target already linked to some old partner...
        d.store.lock().unwrap()
            .insert_link("mocka", "!a", "mockc", "!old-a", "Old A", now).unwrap();
        // ...and the requester ALSO already linked to some other old partner.
        d.store.lock().unwrap()
            .insert_link("mockb", "!req", "mockd", "!old-req", "Old Req", now).unwrap();

        seed_challenge(&d, ("mocka", "!a"), ("mockb", "!req"), "111222", "Fresh", now, 15);
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "111222".into(), None, vec![], None);

        let store = d.store.lock().unwrap();
        assert!(store.link_for_identity("mockc", "!old-a").unwrap().is_none(),
            "the target's old partner must be unlinked (replace, not stack)");
        assert!(store.link_for_identity("mockd", "!old-req").unwrap().is_none(),
            "the requester's old partner must be unlinked (replace, not stack)");
        let fresh = store.link_for_identity("mocka", "!a").unwrap().unwrap();
        assert_eq!(fresh.display_name, "Fresh");
        assert!(store.link_for_identity("mockb", "!req").unwrap().is_some());
    }

    /// Finding 2 (whole-branch review): a plugin that is CONNECTED but
    /// lacks `capabilities.direct_messages` is never going to become
    /// direct-capable by reconnecting — unlike a disconnected plugin, there
    /// is nothing to wait for. Retrying every 5s for up to the TTL (24h by
    /// default, ~17k attempts) is pure churn, so this must dead-letter
    /// promptly with a reason an operator can act on, not mark_retry.
    #[tokio::test]
    async fn process_due_identity_dead_letters_promptly_when_plugin_connected_but_not_direct_capable() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let _rx = register_plugin(&d, "mockb", false); // connected, but NOT direct-capable

        let target: Endpoint = "mockb:!target".parse().unwrap();
        let now = Utc::now();
        let env = Envelope::new(
            "identity:system".parse().unwrap(), Sender { native_ref: "@identity".into() },
            "notice".into(), "code".into(), now, now + CDuration::minutes(15), 8,
        );
        d.store.lock().unwrap().insert_message(&env).unwrap();
        let del_id = d.store.lock().unwrap()
            .insert_delivery(env.id, IDENTITY_ROUTE, &target, now, env.expires_at, 2).unwrap();
        let del = d.store.lock().unwrap().deliveries_for_id(del_id).unwrap();

        process_due(&d, del, now).await;

        let after = d.store.lock().unwrap().deliveries_for_id(del_id).unwrap();
        assert_eq!(after.state, "dead_letter",
            "a connected-but-not-direct-capable plugin must dead-letter promptly, not churn retries");
        assert_eq!(after.reason.as_deref(), Some("NOT_DIRECT_CAPABLE"));
    }

    /// The disconnected case is different: the plugin MAY reconnect (and
    /// become usable) before the delivery's TTL expires, so the existing
    /// retry posture must be preserved there — only the "connected but
    /// incapable" case above gets the prompt dead-letter treatment.
    #[tokio::test]
    async fn process_due_identity_still_retries_when_plugin_is_not_connected_at_all() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        // "mockb" is never registered at all -- not connected.

        let target: Endpoint = "mockb:!target".parse().unwrap();
        let now = Utc::now();
        let env = Envelope::new(
            "identity:system".parse().unwrap(), Sender { native_ref: "@identity".into() },
            "notice".into(), "code".into(), now, now + CDuration::minutes(15), 8,
        );
        d.store.lock().unwrap().insert_message(&env).unwrap();
        let del_id = d.store.lock().unwrap()
            .insert_delivery(env.id, IDENTITY_ROUTE, &target, now, env.expires_at, 2).unwrap();
        let del = d.store.lock().unwrap().deliveries_for_id(del_id).unwrap();

        process_due(&d, del, now).await;

        let after = d.store.lock().unwrap().deliveries_for_id(del_id).unwrap();
        assert_eq!(after.state, "pending",
            "a disconnected plugin may still reconnect, so this must keep retrying, not dead-letter");
        assert!(after.next_attempt > now, "retry must be scheduled in the future");
    }

    /// End-to-end through `confirm_link` (design §Lifecycle step 2): today
    /// only LXMF is direct-capable, so the common case is a requester whose
    /// plugin is connected but not direct-capable (e.g. signal/mocka-style
    /// chat plugins) receiving the confirmation notice. That notice must
    /// dead-letter promptly instead of retrying for 24h, while the
    /// target-side notice (whose plugin IS direct-capable, checked at
    /// initiate) still gets attempted, and the link row exists regardless of
    /// either notice's fate.
    #[tokio::test]
    async fn confirm_link_dead_letters_requester_notice_when_requester_plugin_lacks_direct_messages() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let mut target_rx = register_direct_plugin(&d, "mockb"); // target: direct-capable
        let _requester_rx = register_plugin(&d, "mocka", false); // requester: connected, NOT direct-capable

        let now = Utc::now();
        seed_challenge(&d, ("mockb", "!target"), ("mocka", "!req"), "424242", "Jascha", now, 15);

        handle_inbound(&d, "mockb", "chan".into(), "!target".into(), "text".into(),
                       "424242".into(), None, vec![], None);

        // link exists regardless of either notice's fate
        assert!(d.store.lock().unwrap().link_for_identity("mockb", "!target").unwrap().is_some(),
            "the link must be confirmed even though the requester's plugin can't take the notice");

        let due = d.store.lock().unwrap().due_deliveries(Utc::now(), 10).unwrap();
        assert_eq!(due.len(), 2, "one confirmation notice per party: {due:?}");
        let target_del = due.iter().find(|de| de.destination.protocol == "mockb").unwrap().clone();
        let requester_del = due.iter().find(|de| de.destination.protocol == "mocka").unwrap().clone();

        process_due(&d, requester_del.clone(), now).await;
        let after_requester = d.store.lock().unwrap().deliveries_for_id(requester_del.id).unwrap();
        assert_eq!(after_requester.state, "dead_letter",
            "the requester-side notice must dead-letter promptly, not retry for 24h");
        assert_eq!(after_requester.reason.as_deref(), Some("NOT_DIRECT_CAPABLE"));

        process_due(&d, target_del, now).await;
        let DaemonToPlugin::SendDirect { native_ref, .. } = recv_send(&mut target_rx).await else {
            panic!("expected SendDirect");
        };
        assert_eq!(native_ref, "!target", "the target-side notice must still be attempted");
    }

    // ---- identity linking: rendering ---------------------------------------

    #[tokio::test]
    async fn process_due_renders_display_name_when_route_is_linked_and_a_verified_link_exists() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().routes[0].identity_mode = "linked".to_string();
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false);

        d.store.lock().unwrap()
            .insert_link("mocka", "!a", "signal", "+1", "Jascha", Utc::now()).unwrap();

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        let now = Utc::now();
        let del = { let store = d.store.lock().unwrap(); store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap() };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(body.starts_with("[Jascha]\n"), "body was: {body}");
    }

    #[tokio::test]
    async fn process_due_never_renders_display_name_on_a_route_that_has_not_opted_into_linked_mode() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path())); // default identity_mode: "pseudonymous"
        let mut rx = register_plugin(&d, "mockb", false);

        d.store.lock().unwrap()
            .insert_link("mocka", "!a", "signal", "+1", "Jascha", Utc::now()).unwrap();

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        let now = Utc::now();
        let del = { let store = d.store.lock().unwrap(); store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap() };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(!body.contains("Jascha"),
            "§107: a route must explicitly opt into linked rendering, even with a verified link present: {body}");
    }

    #[tokio::test]
    async fn process_due_renders_alias_in_linked_mode_when_no_link_exists() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().routes[0].identity_mode = "linked".to_string();
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false);

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        let now = Utc::now();
        let del = { let store = d.store.lock().unwrap(); store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap() };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(!body.contains("Jascha"), "with no verified link, linked mode must fall back to the alias: {body}");
    }

    #[tokio::test]
    async fn unlink_reverts_rendering_to_pseudonym_on_the_next_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().routes[0].identity_mode = "linked".to_string();
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false);

        let link_id = d.store.lock().unwrap()
            .insert_link("mocka", "!a", "signal", "+1", "Jascha", Utc::now()).unwrap();

        // first message: linked, renders display_name.
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "first".into(), None, vec![], None);
        let now = Utc::now();
        let del1 = { let store = d.store.lock().unwrap(); store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap() };
        process_due(&d, del1, now).await;
        let DaemonToPlugin::Send { body: body1, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(body1.starts_with("[Jascha]\n"), "body was: {body1}");

        // unlink is storage-only this task (Task 4 wires the admin/ctl API
        // around delete_link) — call it directly.
        assert!(d.store.lock().unwrap().delete_link(link_id).unwrap());

        // second message from the same identity must revert to the
        // pseudonym immediately: rendering reads links live (§95/§22), never
        // cached from the first delivery.
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "second".into(), None, vec![], None);
        let now2 = Utc::now();
        let del2 = { let store = d.store.lock().unwrap(); store.due_deliveries(now2, 1).unwrap().into_iter().next().unwrap() };
        process_due(&d, del2, now2).await;
        let DaemonToPlugin::Send { body: body2, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(!body2.contains("Jascha"), "after unlink, rendering must revert to the pseudonym: {body2}");
    }

    // ---- design §4: route render knobs (tag: none, max_chars) -------------

    #[tokio::test]
    async fn render_tag_none_suppresses_the_alias_prefix_on_a_pseudonymous_route() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path()); // default identity_mode: "pseudonymous"
        d.cfg.write().unwrap().routes[0].render.tag = "none".to_string();
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false);

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        let now = Utc::now();
        let del = { let store = d.store.lock().unwrap(); store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap() };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert_eq!(body, "hello", "tag: none must omit the [alias]\\n prefix entirely: {body}");
    }

    /// design §4: "the route opted out of tags altogether" — `tag: none`
    /// must suppress the sender tag even when the route is in `linked` mode
    /// AND a verified link exists (the case that would otherwise render the
    /// display_name, per `process_due_renders_display_name_when_route_is_
    /// linked_and_a_verified_link_exists` above).
    #[tokio::test]
    async fn render_tag_none_suppresses_the_display_name_on_a_linked_route_with_a_verified_link() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().routes[0].identity_mode = "linked".to_string();
        d.cfg.write().unwrap().routes[0].render.tag = "none".to_string();
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false);

        d.store.lock().unwrap()
            .insert_link("mocka", "!a", "signal", "+1", "Jascha", Utc::now()).unwrap();

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None, vec![], None);
        let now = Utc::now();
        let del = { let store = d.store.lock().unwrap(); store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap() };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert_eq!(body, "hello",
            "tag: none must suppress the linked display_name too, not just the pseudonym: {body}");
    }

    /// Fix round 1: `max_chars` truncates the BODY only, so the `[alias]\n`
    /// tag prefix must always come through untouched -- only the text
    /// after the newline is capped at `max_chars`.
    #[tokio::test]
    async fn render_max_chars_truncates_the_body_only_leaving_the_tag_intact() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().routes[0].render.max_chars = 20;
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false);

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "this body is much longer than twenty characters".into(), None, vec![], None);
        let now = Utc::now();
        let del = { let store = d.store.lock().unwrap(); store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap() };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(body.starts_with('['), "tag prefix must still be present: {body}");
        let after_tag = body.split_once('\n').expect("tag prefix followed by a newline").1;
        assert_eq!(after_tag.chars().count(), 20,
            "route-level max_chars must truncate only the body (post-tag) to exactly 20 chars: {body}");
        assert!(after_tag.ends_with('…'), "body was: {body}");
    }

    /// The exact regression fix round 1 targets: a route in `linked` mode
    /// with a verified link whose `display_name` is much longer than
    /// `max_chars` (no length cap exists on `display_name` anywhere) must
    /// still render the display_name fully intact -- only the body may be
    /// truncated, never the tag, no matter how long the tag is relative to
    /// the configured floor.
    #[tokio::test]
    async fn render_max_chars_at_the_16_floor_never_truncates_a_long_linked_display_name() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().routes[0].identity_mode = "linked".to_string();
        d.cfg.write().unwrap().routes[0].render.max_chars = 16;
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false);

        d.store.lock().unwrap()
            .insert_link("mocka", "!a", "signal", "+1", "AVeryLongDisplayNameIndeed", Utc::now()).unwrap();

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "this body is much longer than sixteen characters".into(), None, vec![], None);
        let now = Utc::now();
        let del = { let store = d.store.lock().unwrap(); store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap() };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(body.starts_with("[AVeryLongDisplayNameIndeed]\n"),
            "a long linked display_name must never be truncated by render.max_chars: {body}");
        assert!(body.contains('…'), "the body must still be truncated: {body}");
    }

    /// design decision (fix round 1, point 4): attachment-strip notes are
    /// appended AFTER `max_chars` truncates the body, so notes are NOT
    /// counted toward the `max_chars` budget -- a note explaining a dropped
    /// attachment must reliably reach the recipient even when the body
    /// itself is truncated to make room.
    #[tokio::test]
    async fn render_max_chars_truncates_body_before_notes_are_appended_notes_not_counted_toward_max_chars() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().routes[0].render.max_chars = 16;
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false); // no attachments capability

        let att = IpcAttachment {
            filename: "photo.jpg".into(), mime: "image/jpeg".into(), data: b"bytes".to_vec(),
        };
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "this body is much longer than sixteen characters".into(), None, vec![att], None);
        let now = Utc::now();
        let del = { let store = d.store.lock().unwrap(); store.due_deliveries(now, 1).unwrap().into_iter().next().unwrap() };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(body.contains("[attachment omitted]"),
            "the note must survive even though the body was truncated to make room: {body}");
        // The truncated-body portion (everything after the tag, up through
        // the truncation ellipsis) is exactly 16 chars -- the note text
        // itself is not counted toward that budget.
        let note_start = body.find("\n[attachment omitted]").expect("note present");
        let body_only = &body[body.find('\n').unwrap() + 1..note_start];
        assert_eq!(body_only.chars().count(), 16,
            "max_chars must bound the body alone, not the body+note total: {body}");
    }

    // ---- apply_config (design §1: hot-reloadable config behind RwLock) ----

    #[test]
    fn apply_config_unchanged_config_has_no_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let new_cfg = d.cfg.read().unwrap().clone();
        let outcome = d.apply_config(new_cfg);
        assert!(outcome.restart_required.is_empty(), "outcome was: {outcome:?}");
    }

    #[test]
    fn apply_config_plugin_command_change_is_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.plugins.get_mut("mockb").unwrap().command = Some("new-command".into());
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required, vec!["mockb".to_string()]);
    }

    #[test]
    fn apply_config_plugin_config_block_change_is_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.plugins.get_mut("mocka").unwrap().config =
            serde_yaml::Value::String("changed".into());
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required, vec!["mocka".to_string()]);
    }

    #[test]
    fn apply_config_plugin_enabled_change_is_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.plugins.get_mut("mockb").unwrap().enabled = false;
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required, vec!["mockb".to_string()]);
    }

    #[test]
    fn apply_config_added_plugin_is_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.plugins.insert("mockc".to_string(), crate::config::PluginConfig {
            enabled: true, command: None, config: serde_yaml::Value::Null,
        });
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required, vec!["mockc".to_string()]);
    }

    #[test]
    fn apply_config_removed_plugin_is_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.plugins.remove("mockb");
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required, vec!["mockb".to_string()]);
    }

    #[test]
    fn apply_config_node_data_dir_change_is_restart_required_under_daemon_pseudo_entry() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.node.data_dir = dir.path().join("moved");
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required, vec!["daemon".to_string()]);
    }

    #[test]
    fn apply_config_node_public_change_is_restart_required_under_daemon_pseudo_entry() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.node.public = !new_cfg.node.public;
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required, vec!["daemon".to_string()]);
    }

    #[test]
    fn apply_config_multiple_changes_are_all_reported_sorted_and_deduped() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.node.public = !new_cfg.node.public;
        new_cfg.plugins.get_mut("mockb").unwrap().enabled = false;
        new_cfg.plugins.insert("aaa-new".to_string(), crate::config::PluginConfig {
            enabled: true, command: None, config: serde_yaml::Value::Null,
        });
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required,
            vec!["aaa-new".to_string(), "daemon".to_string(), "mockb".to_string()]);
    }

    /// Live-effect half of the matrix: a route added via `apply_config` must
    /// route the very next inbound message with no restart in between.
    #[test]
    fn apply_config_route_added_is_live_for_the_next_message_no_restart() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());

        // "newchan" isn't wired into any route in the base config: dropped.
        handle_inbound(&d, "mocka", "newchan".into(), "!a".into(), "text".into(),
                       "before".into(), None, vec![], None);
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(), vec![]);

        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.routes.push(crate::config::RouteConfig {
            name: "extra".into(),
            sources: vec!["mocka:newchan".parse().unwrap()],
            destinations: vec!["mockb:chan".parse().unwrap()],
            identity_mode: "pseudonymous".into(),
            render: crate::config::RenderConfig::default(),
        });
        let outcome = d.apply_config(new_cfg);
        assert!(outcome.restart_required.is_empty(),
            "a route addition alone must never require a restart: {outcome:?}");

        handle_inbound(&d, "mocka", "newchan".into(), "!a".into(), "text".into(),
                       "after".into(), None, vec![], None);
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(),
            vec![("pending".to_string(), 1)],
            "the new route must be live without a restart");
    }

    /// Live-effect half of the matrix: tightening `per_sender` must rebuild
    /// `sender_limiter` so the new, tighter numbers apply to the very next
    /// message -- driven end to end through `handle_inbound` rather than
    /// asserted against the limiter's internals directly.
    #[test]
    fn apply_config_per_sender_tightened_rebuilds_the_sender_limiter() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path()); // Limits::default(): unlimited

        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.limits.per_sender.messages_per_minute = 1;
        d.apply_config(new_cfg);

        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "one".into(), None, vec![], None);
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "two".into(), None, vec![], None);

        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(),
            vec![("pending".to_string(), 1)],
            "the second message from the same sender must be rate-limited \
             immediately after tightening, no restart involved");
    }

    /// `apply_config` must store the incoming config's `raw_yaml` (Task 3's
    /// PUT will have set it via `config::load_from_str` before calling this)
    /// so a subsequent `GET /v1/config` (Task 2) serves the newly-applied
    /// text, not the config the daemon booted with.
    #[test]
    fn apply_config_stores_the_new_configs_raw_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        assert_eq!(d.cfg.read().unwrap().raw_yaml, "", "test_daemon's Config has no raw_yaml");

        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.raw_yaml = "node:\n  name: applied\n".to_string();
        d.apply_config(new_cfg);

        assert_eq!(d.cfg.read().unwrap().raw_yaml, "node:\n  name: applied\n");
    }
}
