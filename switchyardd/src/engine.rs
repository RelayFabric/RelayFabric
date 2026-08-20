use crate::cas::{self, Cas};
use crate::config::{
    effective_allow_gateway_decryption, Config, RouteConfig, FED_PROTOCOL, IDENTITY_ROUTE,
};
use crate::events::Event;
use crate::limits::{BudgetLimiter, SenderLimiter};
use crate::storage::Store;
use crate::{
    alias, dedup, fed, identity_links, metrics, node_identity, policy, queue, routes, storage,
    transform,
};
use alias::Aliaser;
use chrono::{DateTime, Duration as CDuration, Utc};
use node_identity::NodeIdentity;
use relay_core::{AttachmentMeta, Capabilities, Endpoint, Envelope, Sender};
use relay_ipc::{DaemonToPlugin, IpcAttachment, MAX_FRAME};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::sync::{broadcast, mpsc};
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
    pub identity: NodeIdentity,
    pub node_id: String,
    /// Sealed-routing X25519 static keypair (design §1, SPEC §113.3, cycle
    /// H): loaded/created unconditionally in `Daemon::new`, same posture as
    /// `identity`/`aliaser` -- every node has one, whether or not
    /// federation/discovery are configured, so `fed::advert::
    /// build_from_config`'s `security.sealed`/`sealed_key` are always
    /// populated (see `fed::conn::build_signed_advert`).
    pub sealed_key: fed::sealkey::SealedKey,
    pub plugins: Mutex<HashMap<String, PluginHandle>>,
    pub cas: Cas,
    pub sender_limiter: Mutex<SenderLimiter>,
    pub budget_limiter: Mutex<BudgetLimiter>,
    pub gauges: metrics::PluginGauges,
    /// Serializes `apply_config`'s ENTIRE body end-to-end (design §1 review
    /// finding, Task 1 -> Task 3): the cfg swap happens under `cfg`'s write
    /// lock, but the limiter rebuilds that follow it happen OUTSIDE that
    /// lock (by design -- see `apply_config`'s doc comment on why cfg is
    /// never held across another lock acquisition). Without this mutex, two
    /// overlapping `apply_config` calls can interleave: both swap `cfg` (in
    /// some order), then both rebuild the limiters (in a DIFFERENT,
    /// independent order), so the config left in `cfg` and the numbers
    /// baked into `sender_limiter`/`budget_limiter` can end up from two
    /// different calls. Holding this for the whole function guarantees
    /// whichever call finishes last leaves `cfg` and the limiters mutually
    /// consistent with EACH OTHER, regardless of which call that turns out
    /// to be.
    apply_lock: Mutex<()>,
    /// Live event feed (design §4): `GET /v1/events` (admin.rs) and
    /// `switchyardctl events` both `subscribe()` here. Capacity 256 -- a
    /// deliberately small ring buffer, since SSE is advisory (the REST
    /// surface stays the source of truth): a subscriber that falls behind
    /// just skips ahead on its next read (`RecvError::Lagged`, handled in
    /// admin.rs's stream adapter, never fatal) rather than the daemon
    /// growing an unbounded backlog for one slow/stalled UI tab. Never sent
    /// to directly outside this module -- every call site goes through
    /// `emit_event`, which is what makes emission near-zero-cost when
    /// nobody's subscribed (design §4's "must cost ~nothing" requirement).
    pub events: broadcast::Sender<Event>,
    /// Federation runtime state (design §1, cycle F): `None` when the
    /// `federation` config block is absent (feature entirely off, the
    /// `Daemon::new` default) or `Some(FedState::default())` when it's
    /// present — `fed::conn::spawn_federation` populates `conns` as
    /// connections come up; nothing else on `Daemon` mutates it. Fixed for
    /// the lifetime of this `Daemon` instance regardless of a later
    /// `apply_config` call (live fed reconfig is deferred to a later
    /// cycle, same as `apply_config`'s own `"daemon"` restart-required
    /// posture for this whole block — see its doc comment).
    pub fed: Option<crate::fed::conn::FedState>,
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
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data_dir)?;
    std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
}

impl Daemon {
    pub fn new(cfg: Config, data_dir: &Path) -> std::io::Result<Daemon> {
        create_data_dir(data_dir)?;
        let store = Store::open(&data_dir.join("relayfabric.db")).map_err(std::io::Error::other)?;
        let recovered = store.recover().map_err(std::io::Error::other)?;
        if recovered > 0 {
            info!(recovered, "requeued in-flight deliveries from previous run");
        }
        let aliaser = Aliaser::load_or_create(&data_dir.join("alias.key"))?;
        let identity = NodeIdentity::load_or_create(&data_dir.join("identity"))?;
        let node_id = identity.node_id();
        let sealed_key = fed::sealkey::SealedKey::load_or_create(&data_dir.join("sealed.key"))?;
        let ttl = std::time::Duration::from_secs(cfg.dedup_ttl_secs);
        let cas = Cas::new(
            &data_dir.join("attachments"),
            cfg.limits.global.cas_max_bytes,
        )?;
        let sender_limiter = SenderLimiter::new(
            cfg.limits.per_sender.messages_per_minute,
            cfg.limits.per_sender.bytes_per_hour,
        );
        // The initial `Receiver` `channel()` hands back is discarded
        // immediately: a broadcast channel works fine with zero live
        // receivers (every `send` from `emit_event` is already gated on
        // `receiver_count() > 0`), and every real subscriber (`GET
        // /v1/events`, `switchyardctl events`) calls `events.subscribe()`
        // fresh, later.
        let (events, _initial_events_rx) = broadcast::channel(256);
        let fed = cfg
            .federation
            .is_some()
            .then(|| crate::fed::conn::FedState {
                conns: Mutex::new(HashMap::new()),
            });
        Ok(Daemon {
            cfg: RwLock::new(cfg),
            store: Mutex::new(store),
            dedup: Mutex::new(dedup::Dedup::new(ttl)),
            aliaser,
            identity,
            node_id,
            sealed_key,
            plugins: Mutex::new(HashMap::new()),
            cas,
            sender_limiter: Mutex::new(sender_limiter),
            budget_limiter: Mutex::new(BudgetLimiter::new()),
            gauges: metrics::PluginGauges::new(),
            apply_lock: Mutex::new(()),
            events,
            fed,
        })
    }

    /// Best-effort emission for the design §4 live event feed: `f` builds
    /// the `Event` (typically a couple of small string clones/`format!`
    /// calls -- see e.g. `Event::Ingress`'s `sender_masked`) and is only
    /// ever CALLED when at least one subscriber is currently attached, so
    /// the ordinary case -- nobody listening -- costs one atomic load
    /// (`receiver_count`) and nothing else, satisfying design §4's "must
    /// cost ~nothing" requirement with zero subscribers. `send`'s own
    /// result is discarded: a subscriber that disconnects in the gap
    /// between the count check and the send just means the event reaches
    /// nobody, which is exactly SSE's advisory posture here, never an error
    /// worth surfacing to the caller.
    pub fn emit_event(&self, f: impl FnOnce() -> Event) {
        if self.events.receiver_count() > 0 {
            let _ = self.events.send(f());
        }
    }

    /// Clones the current config's snapshot for route `name`, if any --
    /// cuts the noise of a `cfg.read()...find()` at every `process_due`-style
    /// call site while keeping the returned value fully owned (no borrow
    /// tying the caller to the read guard), so it's safe to hold across
    /// subsequent store/plugins lock acquisitions.
    pub fn route_cfg(&self, name: &str) -> Option<RouteConfig> {
        self.cfg
            .read()
            .unwrap()
            .routes
            .iter()
            .find(|r| r.name == name)
            .cloned()
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
    /// `budget_limiter`'s windows (both the `transport_budgets` protocol
    /// keys AND `process_due_fed`'s "fed/<peer_name>" keys -- one shared
    /// instance, one unconditional reset, design §5 Task 3), and pushes the
    /// new dedup TTL into
    /// `dedup` via `set_ttl` (affects only entries recorded from this point
    /// on; entries already recorded keep aging out under whatever TTL was
    /// in effect when they were recorded -- see `dedup::Dedup::set_ttl`).
    /// Routes/policies/limits/render/identity_mode/public_services/
    /// transport_budgets need no explicit action here: every reader goes
    /// through `cfg.read()`/`cfg_snapshot`/`route_cfg`, so they see `new`'s
    /// values on their very next call. Callers are responsible for having
    /// already validated `new` (see `config::validate`) -- this method
    /// trusts it as-is and never fails.
    ///
    /// `federation` (design §3/§4, cycle F) is the one exception to "no
    /// restart needed": ANY change to the block -- listener address, peer
    /// list, accept_from, ingress_routes, anything -- reports the
    /// `"daemon"` restart entry, the same as `node.*`. Live fed reconfig
    /// (rebinding the Noise listener, tearing down/renegotiating already-
    /// connected peers whose config just changed) is deferred to a later
    /// cycle; this cycle a federation config edit only takes effect on the
    /// next daemon start. `discovery` (design §1/§4, cycle G) gets the
    /// same "daemon" restart treatment for the same reason -- live advert
    /// re-issue on a mode/ttl change is a later cycle-G task.
    ///
    /// CALLERS MUST CONSTRUCT `new` VIA `config::load_from_str`, never a
    /// bare parse: the restart-required diff below compares `cfg.plugins`
    /// (always resolved -- it's whatever the daemon is running with) against
    /// `new.plugins` field-by-field, including each plugin's `config:`
    /// block. `load_from_str` runs `resolve_secrets` before returning, so
    /// `new.plugins[_].config` is resolved too, and a config re-applied with
    /// unchanged secret-yielding env vars compares equal. Skip that pipeline
    /// (e.g. `serde_yaml::from_str` + `validate` by hand) and `new.plugins[_]
    /// .config` still holds the unresolved `${...}` reference string, which
    /// will never equal the resolved value in `cfg` -- a false-positive
    /// restart_required entry every single time that plugin's config block
    /// contains any secret reference at all, resolved or not.
    ///
    /// Serialized end-to-end by `apply_lock` (see its doc comment) -- this
    /// is the ONE Daemon method that acquires two of its own locks in
    /// sequence (`apply_lock` then, inside, `cfg`'s write lock) rather than
    /// just one; that's safe specifically because `apply_lock` is never
    /// acquired from anywhere else, so there's no second call site that
    /// could ever try to take them in the opposite order.
    ///
    /// Finding 4 (whole-branch review): a delivery already `pending` for a
    /// route this call renames or removes is NOT retried or rewritten here
    /// -- it keeps its stored `route` string and rides out its existing TTL.
    /// `process_due` resolves `route_cfg(&del.route)` fresh on every attempt
    /// (never cached across an `apply_config` swap), so a miss there just
    /// falls through to render's default/pseudonymous tag semantics instead
    /// of the route's configured one, exactly as an always-unconfigured
    /// route would. This is transient (the row still expires normally) and
    /// loses no data -- only the display tag of any in-flight attempt made
    /// during that window is affected.
    pub fn apply_config(&self, new: Config) -> ApplyOutcome {
        let _apply_guard = self.apply_lock.lock().unwrap();
        let mut restart_required = Vec::new();
        let (dedup_ttl_secs, sender_mm, sender_bph) = {
            let mut cfg = self.cfg.write().unwrap();
            if cfg.node != new.node {
                restart_required.push("daemon".to_string());
            }
            if cfg.federation != new.federation {
                restart_required.push("daemon".to_string());
            }
            if cfg.discovery != new.discovery {
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
        self.dedup
            .lock()
            .unwrap()
            .set_ttl(std::time::Duration::from_secs(dedup_ttl_secs));
        restart_required.sort();
        restart_required.dedup();
        let outcome = ApplyOutcome { restart_required };
        // Emitted from INSIDE apply_config, not by its callers (design §4):
        // both `PUT /v1/config` and `POST /v1/config/rollback` call this
        // method, so emitting here -- once -- covers both without either
        // admin.rs handler needing its own copy of this logic.
        self.emit_event(|| Event::ConfigApplied {
            restart_required: outcome.restart_required.clone(),
            ts: Utc::now(),
        });
        outcome
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
        d.cfg_snapshot(|c| {
            (
                c.max_attachment_bytes,
                c.ttl_default_secs,
                c.hop_limit,
                c.routes.clone(),
                c.limits.per_route.queue_max,
                c.limits.global.queue_max,
            )
        });

    // Hash every attachment up front — a bare in-memory digest, no CAS I/O —
    // so the dedup key can be sensitive to the *full* attachment set,
    // including ones that will end up dropped for being oversize (two sends
    // differing only in which oversize attachment got dropped must not
    // dedup-collide). Nothing is written to the CAS yet: a message that
    // turns out to be a duplicate or unroutable must not write attachment
    // bytes to disk, because it never gets an `insert_attachment_refs` row,
    // which means the GC in `purge_terminal` could never find and reclaim
    // that blob again — a permanent leak, not just a stale one.
    struct Hashed {
        att: IpcAttachment,
        sha: String,
        oversize: bool,
    }
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
    let sender_bytes =
        body.len() as u64 + hashed.iter().map(|h| h.att.data.len() as u64).sum::<u64>();
    let sender_key = format!("{plugin}|{sender}");
    if !d
        .sender_limiter
        .lock()
        .unwrap()
        .allow(&sender_key, sender_bytes, Instant::now())
    {
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
        let matched =
            match d
                .store
                .lock()
                .unwrap()
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

    let source = Endpoint {
        protocol: plugin.to_string(),
        endpoint,
    };
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
                    filename: h.att.filename,
                    mime: h.att.mime,
                    size,
                    sha256: sha,
                });
            }
            Err(e) if cas::is_budget_exceeded(&e) => {
                // Expected steady-state quota enforcement, not a failure —
                // no warn (mirrors the oversize-attachment branch above,
                // which also doesn't log): the filename is message content
                // and only ever belongs in the body note, never a log line.
                notes.push_str(&format!(
                    "\n[dropped {}: cas budget exceeded]",
                    h.att.filename
                ));
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
    // Finding 1 (whole-branch review): every route that lands directly in
    // dead_letter/QUEUE_FULL below needs its own Delivery event -- but
    // `store` is held across the whole loop (every target needs fresh
    // pending_count reads), so emission can't happen inline without
    // violating "never emit while a store guard is live" (see
    // `emit_delivery`'s doc comment). Collected here and emitted after
    // `drop(store)`, alongside the Ingress event this function already
    // sends post-loop.
    let queue_full_routes = fan_out_deliveries(
        &store,
        env.id,
        env.expires_at,
        priority_rank,
        &targets,
        route_max,
        global_max,
        now,
    );
    // Finding 3 (whole-branch review, minor): dropped explicitly BEFORE
    // either emission below, mirroring `handle_result`'s `drop(store)`
    // pattern -- emitting while this guard is still live would hold the
    // store lock across `Daemon.events`'s broadcast send for no reason.
    drop(store);
    for route in &queue_full_routes {
        emit_delivery(d, env.id, route.clone(), "dead_letter");
    }
    // design §4: emitted post-accept, once the fan-out route list is known
    // -- `id` is the internal message UUID (safe to expose; names nothing
    // about sender or content), `sender_masked` is the established
    // "protocol:masked_ref" compound form, never the raw native ref.
    d.emit_event(|| Event::Ingress {
        id: env.id,
        protocol: env.source.protocol.clone(),
        sender_masked: format!(
            "{}:{}",
            env.source.protocol,
            identity_links::mask_ref(&env.sender.native_ref)
        ),
        routes: targets.iter().map(|(r, _)| r.clone()).collect(),
        ts: now,
    });
    info!(id = %env.id, source = %env.source, targets = targets.len(),
          attachments = env.attachments.len(), "message accepted");
}

/// Per-route fan-out shared by `handle_inbound` (design §Routing, plugin
/// ingress) and `fed_ingress` (design §5, federation ingress): given the
/// envelope's already-persisted `env_id`/`expires_at`/resolved
/// `priority_rank`, and an explicit list of `(route_name, destination)`
/// pairs to fan out to, enqueues one delivery row per target — or, when a
/// route or the global queue cap is already at capacity, a
/// `dead_letter`/`QUEUE_FULL` row instead (still visible via
/// `queue_counts`/admin status, matching every other queue-cap rejection
/// in this codebase). Takes an already-held `store` guard (never acquires
/// its own lock) so callers keep the exact lock-holding shape
/// `handle_inbound` always had: one acquisition spanning
/// `insert_message`/`insert_attachment_refs`/this loop, released once by
/// the caller. Returns the route names that landed in `dead_letter` so the
/// caller can emit a `Delivery` event for each, AFTER dropping `store`
/// (Finding 1/3 whole-branch review precedent).
///
/// MECHANICAL EXTRACTION (Task 4, design §5 "reuse handle_inbound's
/// per-route body by refactoring its fan-out loop into a callable that
/// takes an explicit route list"): this is byte-for-byte the loop body
/// `handle_inbound` ran inline before this task — only the route/target
/// selection upstream of the call differs between callers
/// (`routes::route`-matched targets for plugin ingress; a single
/// federation `ingress_routes` route's own `destinations`, all under the
/// SAME route name, for `fed_ingress`). Every existing `handle_inbound`
/// test stays green unmodified against this extraction.
#[allow(clippy::too_many_arguments)]
fn fan_out_deliveries(
    store: &storage::Store,
    env_id: uuid::Uuid,
    expires_at: DateTime<Utc>,
    priority_rank: u8,
    targets: &[(String, Endpoint)],
    route_max: u32,
    global_max: u32,
    now: DateTime<Utc>,
) -> Vec<String> {
    let mut queue_full_routes: Vec<String> = Vec::new();
    for (route, dest) in targets {
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
            match store.insert_dead_delivery(env_id, route, dest, now, expires_at, "QUEUE_FULL") {
                Ok(_) => queue_full_routes.push(route.clone()),
                Err(e) => warn!(error = %e, "failed to record queue-full delivery"),
            }
            warn!(route = %route, destination = %dest, "queue full, delivery rejected");
            continue;
        }
        if let Err(e) = store.insert_delivery(env_id, route, dest, now, expires_at, priority_rank) {
            warn!(error = %e, "failed to enqueue delivery");
        }
    }
    queue_full_routes
}

/// Outcome of `fed_ingress`, below — the caller (`fed::conn`'s read loop)
/// only needs to know whether to send `Fed::Ack{id}` back on the
/// connection (`Accepted` only) or not (every `Rejected` case). The
/// `&'static str` on `Rejected` is a short reason for logs/tests, NOT
/// necessarily the same string written to a `dead_letter` delivery row's
/// `reason` column — see `fed_ingress`'s doc comment for which rejections
/// get a dead_letter row (the four design-named reasons) versus a silent
/// drop (`DUPLICATE`, `RATE_LIMITED`: no row at all, mirroring
/// `handle_inbound`'s own pre-persistence dedup/rate-limit gates).
#[derive(Debug, PartialEq, Eq)]
pub enum FedIngressOutcome {
    Accepted(uuid::Uuid),
    Rejected(&'static str),
}

/// `unknown|seen|verified|trusted|blocked` (design §112.7) ordered by
/// increasing trust, EXCEPT `blocked` which ranks below everything
/// (including `unknown`) so it always fails an `accept_from` comparison
/// regardless of how low `accept_from` is configured. Shared by
/// `fed_ingress`'s trust gate (comparing a peer's stored level against
/// `federation.accept_from`) below. `pub(crate)` (not private): `fed::conn`
/// reuses this exact ranking for RFDP discovery's `federation`-scope gate
/// (design §2 "same gate as fed_ingress", cycle G) rather than duplicating
/// the ordering.
pub(crate) fn trust_rank(level: &str) -> u8 {
    match level {
        "blocked" => 0,
        "seen" => 2,
        "verified" => 3,
        "trusted" => 4,
        _ => 1, // "unknown" (never actually stored as a row) or anything unrecognized
    }
}

/// Whether a `reject()` call may write to storage (Task 4 review fix
/// round 1, DoS hardening — binding controller ruling). `Persist` is for
/// reasons that either already imply the sender passed the trust gate
/// (`HOP_LIMIT`, `ROUTE_NOT_FEDERATED` — operationally useful and safe:
/// only a peer this daemon has decided to trust could ever trigger them)
/// or are a config-invariant violation this daemon's own operator caused,
/// never an untrusted peer (`FED_CONFIG_MISSING`). `NoPersist` is for
/// `BAD_SIGNATURE`/`TRUST_DENIED`, which ANY peer that merely completes a
/// bare Noise handshake can trigger with zero trust established — an
/// untrusted flood of garbage/unrecognized envelopes must not be able to
/// write unbounded rows to SQLite (`messages`/`deliveries`); it gets a
/// metric bump and a per-peer THROTTLED warn log line instead (see
/// `warn_pre_trust_rejection`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Persistence {
    Persist,
    NoPersist,
}

/// Per-peer throttle for `NoPersist` rejections' warn log line (Task 4
/// review fix round 1): at most one warn per peer per minute, so an
/// untrusted flood can't also flood the log the way it's barred from
/// flooding SQLite. Keyed by the FULL node_id (never truncated — a
/// truncated key could conflate two distinct peers' throttles); unbounded
/// key growth over the daemon's lifetime is an accepted trade-off for
/// this fix round (peers are already rate-limited in practice by
/// `fed::conn::MAX_INBOUND_CONNS` plus the cost of completing a fresh
/// Noise handshake per distinct identity) rather than the eviction
/// machinery `dedup`/`limits` use for their own attacker-mintable-key
/// maps.
static PRE_TRUST_REJECT_WARN_THROTTLE: std::sync::LazyLock<Mutex<HashMap<String, Instant>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

const PRE_TRUST_REJECT_WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

fn warn_pre_trust_rejection(peer_node_id: &str, reason: &str) {
    if fed::warn_throttle_due(
        &PRE_TRUST_REJECT_WARN_THROTTLE,
        peer_node_id,
        PRE_TRUST_REJECT_WARN_INTERVAL,
    ) {
        warn!(peer = %fed::short_node_id(peer_node_id), reason,
              "federation ingress rejected pre-trust (not persisted; further repeats from this \
               peer are throttled to 1/min)");
    }
}

/// Records a rejection: `Persistence::Persist` (design §5's `HOP_LIMIT`/
/// `ROUTE_NOT_FEDERATED`, plus `FED_CONFIG_MISSING`) persists the envelope
/// (so it's inspectable, same as any other dead-lettered message in this
/// codebase), writes a `dead_letter` delivery row tagged `reason` under
/// `target_route` addressed to a synthetic `fed:<node_short>` destination
/// (there is no real per-destination target yet at this point in
/// `fed_ingress`'s gate order -- rejection is a ROUTE-level decision,
/// upstream of ever resolving a route's actual `destinations`), and emits
/// the existing `Delivery` event (`enqueue_identity_send`'s
/// drop-store-before-emit pattern). `Persistence::NoPersist`
/// (`BAD_SIGNATURE`/`TRUST_DENIED`) touches storage NOT AT ALL — see
/// `Persistence`'s doc comment for why. Either way, `FED_REJECTED` bumps
/// unconditionally.
fn reject(
    d: &Daemon,
    env: &Envelope,
    target_route: &str,
    peer_node_id: &str,
    reason: &'static str,
    persistence: Persistence,
) -> FedIngressOutcome {
    metrics::inc(&metrics::FED_REJECTED);
    if persistence == Persistence::NoPersist {
        warn_pre_trust_rejection(peer_node_id, reason);
        return FedIngressOutcome::Rejected(reason);
    }

    let now = Utc::now();
    let dest = Endpoint {
        protocol: "fed".to_string(),
        endpoint: crate::fed::short_node_id(peer_node_id),
    };
    let store = d.store.lock().unwrap();
    if let Err(e) = store.insert_message(env) {
        warn!(error = %e, reason, "failed to persist rejected federated message");
        drop(store);
        return FedIngressOutcome::Rejected(reason);
    }
    let inserted =
        store.insert_dead_delivery(env.id, target_route, &dest, now, env.expires_at, reason);
    drop(store);
    match &inserted {
        Ok(_) => {
            warn!(reason, route = target_route, "federation ingress rejected");
            emit_delivery(d, env.id, target_route.to_string(), "dead_letter");
        }
        Err(e) => warn!(error = %e, reason, "failed to record rejected federation delivery"),
    }
    FedIngressOutcome::Rejected(reason)
}

/// The trust gate `fed_ingress` and `fed_sealed_ingress` share: true when
/// `peer_node_id`'s stored trust level ranks below the configured
/// `accept_from` floor.
fn fed_trust_denied(d: &Daemon, peer_node_id: &str, accept_from: &str) -> bool {
    let level = d
        .store
        .lock()
        .unwrap()
        .trust_level(peer_node_id)
        .unwrap_or(None);
    let level_str = level.as_deref().unwrap_or("unknown");
    trust_rank(level_str) < trust_rank(accept_from)
}

/// Replay-window bound + TTL clamp shared verbatim by `fed_ingress` and
/// `fed_sealed_ingress` (final-review I-1, SPEC §113.5): effective expiry
/// is computed from the SIGNED `created_at` + this accept side's OWN
/// `max_ttl_secs` -- NEVER from the envelope's `expires_at`/TTL claim,
/// which is deliberately unsigned (any on-path relay can rewrite it) and
/// therefore worthless as a replay defense. A far-future `created_at` is
/// rejected too (clock-skew abuse: a window that only STARTS later would
/// outlive the bound); honest inter-node skew gets a small fixed
/// allowance. On success, clamps `env.expires_at` DOWN to `max_ttl_secs`
/// from now -- never extended, never a rejection.
fn bound_replay_and_clamp_ttl(env: &mut Envelope, max_ttl_secs: u64) -> Result<(), &'static str> {
    const MAX_CREATED_AT_SKEW_SECS: i64 = 300;
    let ingress_now = Utc::now();
    let stale = env.created_at + CDuration::seconds(max_ttl_secs as i64) < ingress_now;
    let far_future = env.created_at > ingress_now + CDuration::seconds(MAX_CREATED_AT_SKEW_SECS);
    if stale || far_future {
        return Err("EXPIRED");
    }
    let capped = Utc::now() + CDuration::seconds(max_ttl_secs as i64);
    if env.expires_at > capped {
        env.expires_at = capped;
    }
    Ok(())
}

/// The persist + fan-out tail shared verbatim by `fed_ingress` and
/// `fed_sealed_ingress` once every gate has passed: insert the message and
/// its attachment refs, fan deliveries into the route's destinations, emit
/// dead_letter events for queue-full routes, bump `accept_metric`. `what`
/// labels the storage-failure warns.
fn persist_and_fan_out(
    d: &Daemon,
    env: &Envelope,
    target_route: &str,
    route_cfg: &RouteConfig,
    what: &str,
    accept_metric: &std::sync::atomic::AtomicU64,
) -> FedIngressOutcome {
    let now = Utc::now();
    let priority_rank = relay_core::priority_rank(&env.priority);
    let targets: Vec<(String, Endpoint)> = route_cfg
        .destinations
        .iter()
        .map(|dest| (target_route.to_string(), dest.clone()))
        .collect();
    let (route_max, global_max) =
        d.cfg_snapshot(|c| (c.limits.per_route.queue_max, c.limits.global.queue_max));

    let store = d.store.lock().unwrap();
    if let Err(e) = store.insert_message(env) {
        warn!(error = %e, "failed to persist {what} message");
        drop(store);
        return FedIngressOutcome::Rejected("STORAGE_ERROR");
    }
    let shas: Vec<String> = env.attachments.iter().map(|a| a.sha256.clone()).collect();
    if let Err(e) = store.insert_attachment_refs(env.id, &shas) {
        warn!(error = %e, "failed to persist {what} attachment refs");
    }
    let queue_full_routes = fan_out_deliveries(
        &store,
        env.id,
        env.expires_at,
        priority_rank,
        &targets,
        route_max,
        global_max,
        now,
    );
    drop(store);
    for route in &queue_full_routes {
        emit_delivery(d, env.id, route.clone(), "dead_letter");
    }

    metrics::inc(accept_metric);
    FedIngressOutcome::Accepted(env.id)
}

/// Federation ingress (design §5): dispatches a verified `Fed::Envelope`
/// received over a live peer connection (`fed::conn::run_conn`) into a
/// SINGLE named local route's fan-out. Runs its own gate order (design §5,
/// Task 4 controller ruling on priority): signature chain -> trust level
/// -> replay-window bound (signed `created_at` vs local `max_ttl_secs`,
/// final-review I-1) -> hop cap -> TTL clamp -> `target_route` must be one
/// of `federation.ingress_routes` -> dedup (by envelope id, preserved
/// end-to-end across hops) -> per-sender limits -> [accept: dedup record,
/// fan-out, `FED_INGRESS` metric].
///
/// PERSISTENCE SPLIT (Task 4 review fix round 1, DoS hardening — binding
/// controller ruling): `BAD_SIGNATURE`/`TRUST_DENIED` are reachable by ANY
/// peer that merely completes a bare Noise handshake -- no trust
/// established at all -- so they are a `Persistence::NoPersist` rejection:
/// `FED_REJECTED` bumps and a per-peer THROTTLED warn logs, but NOTHING
/// is written to `messages`/`deliveries`. An untrusted flood of garbage or
/// unrecognized-signer envelopes must not be able to grow this daemon's
/// SQLite database without bound. `HOP_LIMIT`/`ROUTE_NOT_FEDERATED` (both
/// only reachable once a peer has ALREADY cleared the trust gate) and the
/// defensive `FED_CONFIG_MISSING` (a config-invariant violation this
/// daemon's own operator caused, never an untrusted peer) stay
/// `Persistence::Persist`: a real `dead_letter` delivery row (visible via
/// the existing `queue_counts`/DLQ admin surface), same as before this fix
/// round. A dedup replay or a per-sender-limit denial is a separate,
/// still-silent drop (no dead_letter row, no `FED_REJECTED` bump either --
/// see their own call sites below) -- this mirrors `handle_inbound`'s own
/// dedup/rate-limit gates, which run before anything is persisted and
/// never dead_letter either.
///
/// CONTROLLER RULING (Task 2 review, binding on Task 4): federation
/// ingress unconditionally STRIPS whatever `priority` the remote peer's
/// envelope claims and re-stamps the design's default ("normal") before
/// ANYTHING is persisted -- `priority` is deliberately unsigned (see
/// `fed::sign::canonical_bytes`'s doc comment), so any on-path relay could
/// otherwise set `priority: "emergency"` on a forwarded envelope to hit
/// the local emergency transport-budget bypass
/// (`process_due`'s `del.priority > 0` check) without invalidating the
/// origin signature. Applied FIRST, before any gate below runs, so every
/// persisted/dead-lettered copy of a federation-received envelope --
/// accepted or rejected -- already carries the stripped value; delivery
/// rows created on acceptance are inserted at `relay_core::priority_rank`
/// of that stripped ("normal") value, i.e. the DEFAULT rank, never
/// whatever the remote peer claimed.
pub fn fed_ingress(
    d: &Daemon,
    peer_node_id: &str,
    mut env: Envelope,
    target_route: String,
) -> FedIngressOutcome {
    env.priority = "normal".to_string();

    if fed::sign::verify_chain(&env).is_err() {
        return reject(
            d,
            &env,
            &target_route,
            peer_node_id,
            "BAD_SIGNATURE",
            Persistence::NoPersist,
        );
    }

    let fed_cfg = d.cfg_snapshot(|c| c.federation.clone());
    let Some(fed_cfg) = fed_cfg else {
        // Federation config vanished from under a live connection (e.g. a
        // hot-swapped config that dropped the block entirely, or a test/
        // caller bug) -- a config-invariant violation this daemon's own
        // operator caused, never an untrusted peer, so it's still
        // persisted (Persistence::Persist) under its own distinct reason
        // -- `ROUTE_NOT_FEDERATED` is reserved for a genuine policy
        // rejection, not this defensive branch (Task 4 review Minor).
        return reject(
            d,
            &env,
            &target_route,
            peer_node_id,
            "FED_CONFIG_MISSING",
            Persistence::Persist,
        );
    };

    if fed_trust_denied(d, peer_node_id, &fed_cfg.accept_from) {
        return reject(
            d,
            &env,
            &target_route,
            peer_node_id,
            "TRUST_DENIED",
            Persistence::NoPersist,
        );
    }

    // Replay-window bound + TTL clamp (see `bound_replay_and_clamp_ttl`).
    // The in-memory dedup below is only a within-window guard (TTL-bounded,
    // cleared on restart); this bounds the replay window to `max_ttl_secs`
    // regardless of dedup state. Post-trust, so `Persistence::Persist`
    // (dead_letter row) -- reachable only by a peer that already cleared
    // the trust gate. The hop check sits between the bound and the clamp
    // by original gate order; `bound_replay_and_clamp_ttl` only mutates
    // `expires_at` AFTER its rejection check, so splitting it around the
    // hop check is unnecessary.
    if let Err(reason) = bound_replay_and_clamp_ttl(&mut env, fed_cfg.max_ttl_secs) {
        return reject(
            d,
            &env,
            &target_route,
            peer_node_id,
            reason,
            Persistence::Persist,
        );
    }

    if env.hops >= fed_cfg.max_hops {
        return reject(
            d,
            &env,
            &target_route,
            peer_node_id,
            "HOP_LIMIT",
            Persistence::Persist,
        );
    }

    if !fed_cfg.ingress_routes.contains(&target_route) {
        return reject(
            d,
            &env,
            &target_route,
            peer_node_id,
            "ROUTE_NOT_FEDERATED",
            Persistence::Persist,
        );
    }
    let Some(route_cfg) = d.route_cfg(&target_route) else {
        // Defensive: config validation guarantees every `ingress_routes`
        // name resolves to a real route for whatever `cfg` currently
        // holds (`validate_federation` checks this on every load/apply),
        // so this should be unreachable in practice -- same
        // `FED_CONFIG_MISSING` reason and Persist posture as the fed_cfg
        // check above, for the same rationale (operator config bug, not
        // an untrusted-peer-reachable path -- this point is only reached
        // after the trust gate already passed).
        return reject(
            d,
            &env,
            &target_route,
            peer_node_id,
            "FED_CONFIG_MISSING",
            Persistence::Persist,
        );
    };

    // Dedup peek (design §5: "envelope id preserved end-to-end" — the
    // dedup key IS the envelope id, not a content hash; a federation
    // envelope's id never changes as it's forwarded hop to hop, which is
    // exactly what makes id-based dedup work as the primary loop-killer,
    // hop cap being only the backstop). Peek-only, same split as
    // `handle_inbound`: a message that ends up rate-limited below must not
    // be recorded as seen yet.
    let dedup_key = env.id.to_string();
    if d.dedup
        .lock()
        .unwrap()
        .is_duplicate(&dedup_key, Instant::now())
    {
        metrics::inc(&metrics::DUPLICATES);
        return FedIngressOutcome::Rejected("DUPLICATE");
    }

    // Per-sender limits (design §5 / Task 4 exact sender key): reuses the
    // SAME `SenderLimiter` (and therefore the SAME `limits.per_sender`
    // config) plugin ingress uses, keyed `"fed|<node_id first 8 hex
    // chars>:<env.sender.native_ref>"` so a federated sender's quota is
    // independent of any local sender sharing the same native_ref on a
    // different transport.
    let node_short = fed::short_node_id(peer_node_id);
    let sender_key = format!("fed|{node_short}:{}", env.sender.native_ref);
    let sender_bytes = env.body.len() as u64 + env.attachments.iter().map(|a| a.size).sum::<u64>();
    if !d
        .sender_limiter
        .lock()
        .unwrap()
        .allow(&sender_key, sender_bytes, Instant::now())
    {
        metrics::inc(&metrics::RATELIMITED);
        return FedIngressOutcome::Rejected("RATE_LIMITED");
    }
    // Accepted by both dedup and the rate limiter: record now, mirroring
    // `handle_inbound`'s own ordering.
    d.dedup.lock().unwrap().record(&dedup_key, Instant::now());

    persist_and_fan_out(
        d,
        &env,
        &target_route,
        &route_cfg,
        "federated",
        &metrics::FED_INGRESS,
    )
}

/// Per-peer throttle for `fed_sealed_ingress`'s rejection warn lines --
/// same shape/rationale as `PRE_TRUST_REJECT_WARN_THROTTLE`/
/// `warn_pre_trust_rejection` above (Task 4 review fix round 1), kept in
/// its OWN map rather than sharing that one: EVERY `fed_sealed_ingress`
/// rejection reason (alg/expiry/bad-seal/bad-binding/bad-sig/trust/route/
/// downgrade-refused) is `Persistence::NoPersist` here, not just the
/// pre-trust subset cycle-F's own split names -- see `sealed_reject`'s doc
/// comment for why.
static SEALED_REJECT_WARN_THROTTLE: std::sync::LazyLock<Mutex<HashMap<String, Instant>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Rejects a `fed_sealed_ingress` gate failure (design §5): bumps
/// `SEALED_REJECTED` unconditionally, logs a per-peer-throttled warn (1/min,
/// reusing `PRE_TRUST_REJECT_WARN_INTERVAL`), and returns the `Rejected`
/// outcome -- NEVER touches storage, for every named reason this returns.
///
/// This is a stricter posture than `fed_ingress`'s own `Persistence` split:
/// there, `HOP_LIMIT`/`ROUTE_NOT_FEDERATED` persist a dead_letter row
/// because they're only reachable once a peer has already cleared the
/// trust gate. `fed_sealed_ingress` never persists ANY rejection, even
/// post-trust ones (`ROUTE_NOT_FEDERATED`/`SECURITY_DOWNGRADE_REFUSED`),
/// for two independent reasons: (1) the pre-decode gates (alg/header-
/// expiry/bad-seal/bad-binding/malformed-decode) run BEFORE signature
/// verification, so -- unlike cycle-F's HOP_LIMIT/ROUTE_NOT_FEDERATED --
/// they're reachable by ANY peer that merely completed a Noise handshake,
/// the identical DoS concern that motivates `Persistence::NoPersist` in
/// the first place; (2) `SECURITY_DOWNGRADE_REFUSED` specifically means
/// "this route will not be a sealed->plaintext termination point" (design
/// §113.2) -- writing the just-decrypted envelope into this daemon's own
/// `dead_letter` table (queryable via the admin DLQ surface) on that exact
/// path would make the refusal cosmetic, not real. Keeping the posture
/// uniform across every reason (rather than splitting pre-/post-trust
/// like `fed_ingress` does) means "sealed ingress never persists a
/// rejection, full stop" is a single, easily-audited invariant.
fn sealed_reject(peer_node_id: &str, reason: &'static str) -> FedIngressOutcome {
    metrics::inc(&metrics::SEALED_REJECTED);
    if fed::warn_throttle_due(
        &SEALED_REJECT_WARN_THROTTLE,
        peer_node_id,
        PRE_TRUST_REJECT_WARN_INTERVAL,
    ) {
        warn!(peer = %fed::short_node_id(peer_node_id), reason,
              "sealed federation ingress rejected (not persisted; further repeats from this \
               peer are throttled to 1/min)");
    }
    FedIngressOutcome::Rejected(reason)
}

/// Sealed federation ingress (design §5, SPEC §113.2/§113.5, cycle H, Task
/// 5): the receive side of `Fed::Sealed` (egress: `process_due_fed_sealed`,
/// Task 4). Unlike `fed_ingress`'s single verified `Envelope`, this starts
/// from OPAQUE ciphertext plus a small cleartext header (`SealedEnvelope`'s
/// `alg`/`id`/`expires_at`) and must earn its way to a decrypted `Envelope`
/// before any of `fed_ingress`'s own gates even apply. Full gate order,
/// FAIL CLOSED at every step (`sealed_reject` -- see its doc comment for
/// why NOTHING here ever persists a rejection, unlike `fed_ingress`):
///
/// 1. `sealed.alg` supported -> else `UNSUPPORTED_SEAL_ALG`.
/// 2. `sealed.expires_at` (cleartext header) > now -> else `EXPIRED`
///    (mirrors cycle-F's own header-level expiry check, but this is the
///    SEALED header, unsigned and sender-set -- the SIGNED inner
///    `created_at` gets its own independent bound at step 10, below).
/// 3. Dedup PEEK on `id+expiry` (design §113.5: "dedup keys on id+expiry,
///    NOT sender -- sealed sender is opaque"). Duplicate -> silent drop
///    (`DUPLICATE`, mirrors `fed_ingress`'s own dedup category: no
///    `sealed_reject`, no persistence, just the shared `DUPLICATES`
///    metric). Peek-only: anything rejected below must not be recorded as
///    seen yet.
/// 4. `federation` config present -> else `FED_CONFIG_MISSING`; trust gate
///    (`peer_node_id`'s stored level >= `accept_from`) -> else
///    `TRUST_DENIED`. BEFORE unseal (2026-08-20 hardening): an untrusted
///    peer never reaches the asymmetric crypto below.
/// 5. `fed::seal::unseal` with THIS node's OWN `sealed_key` -> `SealError`
///    maps to `UNSUPPORTED_SEAL_ALG`/`BAD_SEAL`/`BAD_BINDING` (the header/
///    inner id+expiry binding check is inside `unseal` itself).
/// 6. CBOR-decode the unsealed plaintext as an `Envelope` -> malformed
///    (decrypted-but-not-a-valid-Envelope) -> `BAD_SEAL`, via
///    `ciborium::from_reader`'s own `Result`, never a panic on
///    attacker-shaped-but-successfully-decrypted bytes.
/// 7. Priority strip (cycle-F's CONTROLLER RULING, design §5: applies
///    identically here -- `priority` is deliberately unsigned, so a sealed
///    envelope must not carry an emergency-budget bypass any more than a
///    cleartext federated one can). Applied before `verify_chain` (safe:
///    `fed::sign::canonical_bytes` never includes `priority`) and before
///    every gate below, so nothing downstream ever sees the remote-claimed
///    value.
/// 8. `fed::sign::verify_chain` (origin sig over the DECODED envelope) ->
///    else `BAD_SIGNATURE`.
/// 10. Replay-window bound (final-review I-1's cycle-F fix, reused
///     verbatim here on the now-decrypted, SIGNED `created_at`): stale
///     (older than `max_ttl_secs`) or far-future (clock-skew abuse) ->
///     `EXPIRED`. This is INDEPENDENT of step 2's header-level check --
///     step 2 only bounds the unsigned sealed header, which the connected
///     peer fully controls; this step bounds the SIGNED inner timestamp,
///     closing the same post-restart/post-dedup-eviction replay gap I-1
///     closed for cycle-F.
/// 11. TTL clamp: `env.expires_at` (also unsigned, also attacker-settable)
///     clamped DOWN to `max_ttl_secs` from now, never extended, never a
///     rejection -- same posture as `fed_ingress`'s own clamp.
/// 12. `target_route` ∈ `federation.ingress_routes` -> else
///     `ROUTE_NOT_FEDERATED`.
/// 13. `target_route` resolves to a real `RouteConfig` -> else
///     `FED_CONFIG_MISSING` (defensive, same as `fed_ingress`).
/// 14. **DOWNGRADE REFUSAL (design §113.2, the reason this task exists):**
///     `config::effective_allow_gateway_decryption` resolves the target
///     route's floor (route override wins over the node's
///     `privacy.allow_gateway_decryption` default) -> `false` ->
///     `SECURITY_DOWNGRADE_REFUSED`, and the decrypted content is NEVER
///     persisted or fanned out -- phase 1 has no sealed relay-onward, so a
///     route that refuses to be a sealed->plaintext termination point
///     simply, honestly refuses (design §113.3's "delivering to a local
///     plaintext plugin IS a gateway decryption at the destination edge").
/// 15. Per-sender quota (design §113.5): sealed has no cleartext sender,
///     so this keys the SAME `SenderLimiter` plugin/`fed_ingress` ingress
///     uses on `("fed-sealed", peer_node_id)` instead of a native_ref --
///     documented: sealed traffic is rate-limited per-PEER, not
///     per-origin-user, since the origin is opaque by design. Exceeded ->
///     silent drop (`RATE_LIMITED`, shared `RATELIMITED` metric, mirrors
///     `fed_ingress`'s own category -- no `sealed_reject`).
/// 16. Dedup RECORD, persist the decrypted envelope + attachment refs,
///     `fan_out_deliveries` into `target_route`'s destinations (the EXACT
///     same helper `fed_ingress` uses -- the delivered envelope is the
///     decrypted one, indistinguishable downstream from any other
///     federated arrival), `SEALED_INGRESS` metric, `Accepted(env.id)` ->
///     the caller (`fed::conn::handle_frame`) replies `Fed::Ack{id}`,
///     exactly mirroring `fed_ingress`'s own Accepted handling.
pub fn fed_sealed_ingress(
    d: &Daemon,
    peer_node_id: &str,
    sealed: fed::seal::SealedEnvelope,
    target_route: String,
) -> FedIngressOutcome {
    if sealed.alg != fed::seal::SEAL_ALG_V1 {
        return sealed_reject(peer_node_id, "UNSUPPORTED_SEAL_ALG");
    }

    if sealed.expires_at <= Utc::now().timestamp() {
        return sealed_reject(peer_node_id, "EXPIRED");
    }

    // Dedup peek (design §113.5: "dedup keys on id+expiry, NOT sender --
    // sealed sender is opaque"). Both fields are the CLEARTEXT sealed
    // header (readable pre-decrypt), matching `fed_ingress`'s own
    // peek-before-persist split: anything rejected below must not be
    // recorded as seen yet.
    let dedup_key = format!("sealed:{}:{}", sealed.id, sealed.expires_at);
    if d.dedup
        .lock()
        .unwrap()
        .is_duplicate(&dedup_key, Instant::now())
    {
        metrics::inc(&metrics::DUPLICATES);
        return FedIngressOutcome::Rejected("DUPLICATE");
    }

    // Trust gate BEFORE unseal (public-node security review, 2026-08-20):
    // `peer_node_id` comes from the Noise handshake, not the envelope, so
    // nothing about trust needs the decrypted payload -- and running it
    // here means an untrusted peer can never make this node spend
    // X25519+AEAD cycles on its ciphertext. `fed_cfg` is fetched here for
    // the same reason and reused by every later gate.
    let fed_cfg = d.cfg_snapshot(|c| c.federation.clone());
    let Some(fed_cfg) = fed_cfg else {
        // Federation config vanished from under a live connection -- a
        // config-invariant violation this daemon's own operator caused,
        // never an untrusted peer (same defensive posture as
        // `fed_ingress`'s identical check).
        return sealed_reject(peer_node_id, "FED_CONFIG_MISSING");
    };

    if fed_trust_denied(d, peer_node_id, &fed_cfg.accept_from) {
        return sealed_reject(peer_node_id, "TRUST_DENIED");
    }

    let canonical_env_cbor = match fed::seal::unseal(&sealed, d.sealed_key.secret()) {
        Ok(bytes) => bytes,
        // Defensive/unreachable in practice: step 1 above already checked
        // `sealed.alg`, so `unseal`'s own identical first check can never
        // actually fire here -- kept as an explicit arm (not folded into
        // `BAD_SEAL`) so the mapping stays exhaustive and self-documenting
        // if `unseal`'s gate order ever changes.
        Err(fed::seal::SealError::UnsupportedAlg) => {
            return sealed_reject(peer_node_id, "UNSUPPORTED_SEAL_ALG");
        }
        Err(fed::seal::SealError::BadSeal) => return sealed_reject(peer_node_id, "BAD_SEAL"),
        Err(fed::seal::SealError::BadBinding) => return sealed_reject(peer_node_id, "BAD_BINDING"),
    };

    // Malformed-but-successfully-decrypted plaintext (the "tampered
    // ciphertext that happens to decrypt to non-Envelope CBOR" case is
    // cryptographically implausible under AEAD, but a HONEST sender could
    // still seal garbage) must fail closed via `Result`, never panic.
    let mut env: Envelope = match ciborium::from_reader(canonical_env_cbor.as_slice()) {
        Ok(env) => env,
        Err(_) => return sealed_reject(peer_node_id, "BAD_SEAL"),
    };

    // CONTROLLER RULING (cycle-F, Task 2 review; applies identically to
    // sealed ingress, design §5): strip the decrypted envelope's priority
    // to the default BEFORE anything else runs -- `priority` is
    // deliberately unsigned (`fed::sign::canonical_bytes` never includes
    // it), so this is safe to do before `verify_chain` below, and doing it
    // this early means no downstream gate/log/persisted copy ever sees
    // the remote-claimed value.
    env.priority = "normal".to_string();

    if fed::sign::verify_chain(&env).is_err() {
        return sealed_reject(peer_node_id, "BAD_SIGNATURE");
    }

    // Replay-window bound + TTL clamp (`bound_replay_and_clamp_ttl`,
    // shared with `fed_ingress` -- see this function's doc comment, step
    // 10, for why this is independent of the header-level expiry check
    // above): the SIGNED `created_at` is the only trustworthy time claim;
    // the sealed header's `expires_at` and the envelope's own `expires_at`
    // are both unsigned and peer-controlled.
    if let Err(reason) = bound_replay_and_clamp_ttl(&mut env, fed_cfg.max_ttl_secs) {
        return sealed_reject(peer_node_id, reason);
    }

    if !fed_cfg.ingress_routes.contains(&target_route) {
        return sealed_reject(peer_node_id, "ROUTE_NOT_FEDERATED");
    }
    let Some(route_cfg) = d.route_cfg(&target_route) else {
        // Defensive: same rationale as `fed_ingress`'s identical check --
        // config validation guarantees every `ingress_routes` name
        // resolves to a real route, so this should be unreachable.
        return sealed_reject(peer_node_id, "FED_CONFIG_MISSING");
    };

    // DOWNGRADE REFUSAL (design §5/§113.2, the reason this task exists):
    // a route/node that refuses to be a sealed->plaintext termination
    // point dead-letters (NEVER delivers) rather than silently
    // downgrading -- phase 1 has no sealed relay-onward, so there is no
    // other honest option than refusal.
    let allow_decrypt = d.cfg_snapshot(|c| effective_allow_gateway_decryption(c, &route_cfg));
    if !allow_decrypt {
        return sealed_reject(peer_node_id, "SECURITY_DOWNGRADE_REFUSED");
    }

    // Per-sender quota (design §113.5): sealed has no cleartext sender, so
    // this keys the SAME `SenderLimiter` on `("fed-sealed", peer_node_id)`
    // instead of `fed_ingress`'s `"fed|<node_short>:<native_ref>"` --
    // documented: sealed traffic is rate-limited per-PEER, not
    // per-origin-user, since the origin is opaque by design.
    let node_short = fed::short_node_id(peer_node_id);
    let sender_key = format!("fed-sealed|{node_short}");
    let sender_bytes = env.body.len() as u64 + env.attachments.iter().map(|a| a.size).sum::<u64>();
    if !d
        .sender_limiter
        .lock()
        .unwrap()
        .allow(&sender_key, sender_bytes, Instant::now())
    {
        metrics::inc(&metrics::RATELIMITED);
        return FedIngressOutcome::Rejected("RATE_LIMITED");
    }
    // Accepted by both dedup and the rate limiter: record now, mirroring
    // `fed_ingress`'s own ordering.
    d.dedup.lock().unwrap().record(&dedup_key, Instant::now());

    persist_and_fan_out(
        d,
        &env,
        &target_route,
        &route_cfg,
        "sealed federated",
        &metrics::SEALED_INGRESS,
    )
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
        plugins
            .iter()
            .filter(|(_, h)| h.connected && h.capabilities.direct_messages)
            .map(|(name, _)| name.clone())
            .collect()
    };
    if !direct_capable.iter().any(|p| p == &target.protocol) {
        return Err(if direct_capable.is_empty() {
            "target plugin is not connected or does not support direct messages; \
             no currently-connected plugins support direct messages"
                .to_string()
        } else {
            format!(
                "target plugin '{}' is not connected or does not support direct messages; \
                 currently direct-capable: {}",
                target.protocol,
                direct_capable.join(", ")
            )
        });
    }

    let code = identity_links::generate_code();
    let now = Utc::now();
    let expires = now + CDuration::minutes(15);
    let challenge_id = {
        let store = d.store.lock().unwrap();
        store
            .create_challenge(
                &code,
                &target.protocol,
                &target.endpoint,
                &requester.protocol,
                &requester.endpoint,
                display_name,
                now,
                expires,
            )
            .map_err(|e| e.to_string())?
    };

    // Masked per design §Lifecycle step 1's exact body wording: the target
    // sees who is asking to link, but never the requester's full ref.
    // RULING 2: protocol stays visible, only the ref is masked — "signal:****921A"
    // style, not `mask_ref` applied to the whole "proto:ref" string.
    let masked_requester = format!(
        "{}:{}",
        requester.protocol,
        identity_links::mask_ref(&requester.endpoint)
    );
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
    d: &Daemon,
    dest: Endpoint,
    body: String,
    now: DateTime<Utc>,
    expires: DateTime<Utc>,
) -> Result<(), String> {
    let (hop_limit, global_max) = d.cfg_snapshot(|c| (c.hop_limit, c.limits.global.queue_max));
    let env = Envelope::new(
        Endpoint {
            protocol: IDENTITY_ROUTE.trim_start_matches('@').to_string(),
            endpoint: "system".to_string(),
        },
        Sender {
            native_ref: IDENTITY_ROUTE.to_string(),
        },
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
    let over_global =
        global_max > 0 && store.pending_count(None).unwrap_or(0) >= i64::from(global_max);
    if over_global {
        metrics::inc(&metrics::QUEUE_REJECTED);
        let inserted =
            store.insert_dead_delivery(env.id, IDENTITY_ROUTE, &dest, now, expires, "QUEUE_FULL");
        if let Err(e) = &inserted {
            warn!(error = %e, "failed to record queue-full identity delivery");
        }
        warn!(destination = %format!("{}:{}", dest.protocol, identity_links::mask_ref(&dest.endpoint)),
              "queue full, identity delivery rejected");
        // Finding 1/3 (whole-branch review): emit only AFTER the store guard
        // drops (mirrors `handle_result`'s `drop(store)` pattern), and only
        // when the dead-letter row actually persisted -- an event reporting
        // a state that never made it to disk would be worse than none.
        drop(store);
        if inserted.is_ok() {
            emit_delivery(d, env.id, IDENTITY_ROUTE, "dead_letter");
        }
        return Err("queue full".to_string());
    }
    if let Err(e) = store.insert_delivery(
        env.id,
        IDENTITY_ROUTE,
        &dest,
        now,
        expires,
        relay_core::priority_rank(&env.priority),
    ) {
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
    let link_id = {
        let store = d.store.lock().unwrap();
        // Consume first: whatever happens below, this code must not be
        // usable a second time.
        if let Err(e) = store.delete_challenge(challenge.id) {
            warn!(error = %e, "failed to consume identity challenge");
        }

        // One-link-per-identity: delete any existing link(s) touching
        // either party before inserting the new one (replace, not stack).
        for (proto, r) in [
            (
                challenge.target_protocol.as_str(),
                challenge.target_ref.as_str(),
            ),
            (
                challenge.requester_protocol.as_str(),
                challenge.requester_ref.as_str(),
            ),
        ] {
            if let Ok(Some(existing)) = store.link_for_identity(proto, r) {
                if let Err(e) = store.delete_link(existing.id) {
                    warn!(error = %e, "failed to delete superseded identity link");
                }
            }
        }

        match store.insert_link(
            &challenge.target_protocol,
            &challenge.target_ref,
            &challenge.requester_protocol,
            &challenge.requester_ref,
            &challenge.display_name,
            now,
        ) {
            Ok(id) => id,
            Err(e) => {
                warn!(error = %e, "failed to persist identity link");
                return;
            }
        }
    };

    metrics::inc(&metrics::LINKS_VERIFIED);
    // RULING 2: unify on the same compound "protocol:masked_ref" convention
    // as the response/notice bodies below — protocol stays visible, only
    // the ref is masked. Codes still never appear in a log line.
    info!(target = %format!("{}:{}", challenge.target_protocol,
                             identity_links::mask_ref(&challenge.target_ref)),
          requester = %format!("{}:{}", challenge.requester_protocol,
                                identity_links::mask_ref(&challenge.requester_ref)),
          "identity link verified");
    // design §4: deliberately carries nothing but the opaque link id -- no
    // protocol, no ref (masked or otherwise), no display_name.
    d.emit_event(|| Event::LinkVerified { link_id, ts: now });

    let masked_requester = format!(
        "{}:{}",
        challenge.requester_protocol,
        identity_links::mask_ref(&challenge.requester_ref)
    );
    let masked_target = format!(
        "{}:{}",
        challenge.target_protocol,
        identity_links::mask_ref(&challenge.target_ref)
    );
    let expires = now + CDuration::seconds(d.cfg_snapshot(|c| c.ttl_default_secs) as i64);

    // Best-effort (design §Lifecycle step 2): a queue-full rejection here
    // (RULING 1) dead-letters the notice but must not undo the link that
    // was just confirmed, so the Result is deliberately discarded.
    let _ = enqueue_identity_send(
        d,
        Endpoint {
            protocol: challenge.target_protocol.clone(),
            endpoint: challenge.target_ref.clone(),
        },
        format!(
            "RelayFabric: identity link confirmed with {masked_requester} as \"{}\".",
            challenge.display_name
        ),
        now,
        expires,
    );
    let _ = enqueue_identity_send(
        d,
        Endpoint {
            protocol: challenge.requester_protocol.clone(),
            endpoint: challenge.requester_ref.clone(),
        },
        format!(
            "RelayFabric: {masked_target} confirmed the identity link as \"{}\".",
            challenge.display_name
        ),
        now,
        expires,
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
    // Fetched once, up front, and reused by both branches below: the
    // `delivered` branch already needed `route`/`message_id` (for the
    // metrics lookups just below) and the other branch already needed
    // `attempt_count` (to decide retry vs. dead-letter) -- a second,
    // redundant `deliveries_for_id` call used to run in that second branch;
    // design §4's `delivery` event needs `route`/`message_id` in EITHER
    // branch, which this single fetch now covers for both.
    let delivery = store.deliveries_for_id(corr);
    if delivered {
        metrics::inc(&metrics::EGRESS);
        // Route counter + delivery latency (design §3): looked up from the
        // delivery/message rows before the state flip below, though the
        // flip's own 'attempting'-only guard means these two are
        // best-effort like EGRESS just above (a late/duplicate delivered
        // ack that the guard silently ignores still bumps these, exactly
        // as it already bumps EGRESS) -- not worth a second query to
        // detect that rare, harmless double-count.
        if let Some(delivery) = &delivery {
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
        drop(store);
        emit_delivery_event(d, delivery.as_ref(), "delivered");
        return;
    }
    // look up attempt count to decide retry vs dead-letter
    let attempts = delivery
        .as_ref()
        .map(|del| del.attempt_count)
        .unwrap_or(queue::MAX_ATTEMPTS);
    let state = if attempts >= queue::MAX_ATTEMPTS {
        warn_if_mark_failed(
            corr,
            "dead_letter",
            store.mark_terminal(corr, "dead_letter", "RETRY_EXHAUSTED"),
        );
        warn!(
            delivery = corr,
            detail = detail.as_deref().unwrap_or(""),
            "dead-lettered"
        );
        "dead_letter"
    } else {
        let next = Utc::now()
            + CDuration::from_std(queue::backoff(attempts)).unwrap_or(CDuration::seconds(5));
        warn_if_mark_failed(corr, "pending", store.mark_retry(corr, next));
        info!(delivery = corr, attempts, "delivery failed, will retry");
        "retry"
    };
    drop(store);
    emit_delivery_event(d, delivery.as_ref(), state);
}

/// Shared by both branches of `handle_result` above (design §4's `delivery`
/// event): a no-op when `delivery` is `None` -- a delivery row that vanished
/// between the `deliveries_for_id` lookup and here has no `route`/
/// `message_id` to report, and that shouldn't happen anyway (`corr` only
/// ever comes from a plugin's `DeliveryResult` for a row this daemon itself
/// just sent). `state` is the design §4 semantic label (`delivered` |
/// `dead_letter` | `retry`), not necessarily the literal `deliveries.state`
/// column value the caller just wrote (a retry is stored as `pending`).
fn emit_delivery_event(d: &Daemon, delivery: Option<&storage::Delivery>, state: &str) {
    let Some(delivery) = delivery else { return };
    emit_delivery(d, delivery.message_id, delivery.route.clone(), state);
}

/// Finding 1 (whole-branch review): the direct-parameter counterpart to
/// `emit_delivery_event` above, for call sites (`process_due`,
/// `process_due_identity`, `handle_inbound`, `enqueue_identity_send`) that
/// already have `id`/`route` in hand from the write they just made and don't
/// need `emit_delivery_event`'s extra `deliveries_for_id`-shaped lookup.
/// `state` is the DB `deliveries.state` value as-is (design §4's `delivered
/// | failed | dead_letter | retry`, PLUS `expired` -- a real terminal
/// `deliveries.state` this daemon writes on TTL expiry that predates §4's
/// four-state list; there's no more meaningful synonym for it, so it's
/// surfaced verbatim rather than folded into `failed`).
///
/// Lock discipline: callers MUST hold no `store` (or other Daemon) guard
/// when this runs -- mirror `handle_result`'s `drop(store)` pattern above.
/// Emission itself never touches the store, but calling it while a guard is
/// still live would defeat the point of separating write from notify.
///
/// `pub(crate)` (not private): `fed::conn`'s Ack handler (design §5 egress:
/// `Fed::Ack{id}` => delivered) reuses this exact helper once it marks a
/// federation delivery row delivered, rather than re-implementing its own
/// copy of the `Event::Delivery` construction.
pub(crate) fn emit_delivery(d: &Daemon, id: uuid::Uuid, route: impl Into<String>, state: &str) {
    d.emit_event(|| Event::Delivery {
        id,
        route: route.into(),
        state: state.to_string(),
        ts: Utc::now(),
    });
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
            // RFDP peer advertisements (design §3, cycle G): same hourly
            // cadence as the retention/challenge purges above -- an
            // expired advert is already excluded from `list_peer_adverts`
            // (its own `expires > now` filter), so this is disk hygiene,
            // not a correctness gate.
            match d.store.lock().unwrap().purge_expired_adverts(now) {
                Ok(n) => {
                    if n > 0 {
                        info!(purged = n, "purged expired peer advertisements");
                    }
                }
                Err(e) => warn!(error = %e, "expired peer advert purge failed"),
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
            let result =
                d.store
                    .lock()
                    .unwrap()
                    .mark_terminal(del.id, "failed", "DESTINATION_UNKNOWN");
            warn_if_mark_failed(del.id, "failed", result);
            emit_delivery(d, del.message_id, del.route.clone(), "failed");
            return;
        }
    };
    if env.is_expired(now) {
        let result = d
            .store
            .lock()
            .unwrap()
            .mark_terminal(del.id, "expired", "TTL_EXPIRED");
        warn_if_mark_failed(del.id, "expired", result);
        emit_delivery(d, del.message_id, del.route.clone(), "expired");
        return;
    }
    if del.route == IDENTITY_ROUTE {
        process_due_identity(d, del, env, now).await;
        return;
    }
    if del.destination.protocol == FED_PROTOCOL {
        process_due_fed(d, del, env, now).await;
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
            let result =
                d.store
                    .lock()
                    .unwrap()
                    .mark_terminal(del.id, "dead_letter", "POLICY_DENIED");
            warn_if_mark_failed(del.id, "dead_letter", result);
            info!(delivery = del.id, policy, "policy denied");
            emit_delivery(d, del.message_id, del.route.clone(), "dead_letter");
        }
        policy::Decision::Allow {
            max_payload,
            attachments_allowed,
            max_attachment_bytes,
        } => {
            // capability + policy limits combine to the tighter one
            let (tx, cap_limit, dest_supports_attachments) = {
                let plugins = d.plugins.lock().unwrap();
                match plugins
                    .get(&del.destination.protocol)
                    .filter(|h| h.connected)
                {
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
                let result = d
                    .store
                    .lock()
                    .unwrap()
                    .mark_retry(del.id, now + CDuration::seconds(5));
                warn_if_mark_failed(del.id, "pending", result);
                return;
            };

            // Transport-class policy (design §3, spec §17/§113.4): the
            // destination plugin's TRANSPORT -- not just its protocol
            // `Capabilities` -- can impose a further payload ceiling and/or
            // forbid media (Meshtastic/LoRa, satellite, etc). Resolved live
            // per delivery, the same as `route_cfg`/render below, so a
            // `--check-config`-validated `transports:` edit takes effect on
            // the very next send, no restart. `del.destination.protocol` is
            // the plugin name, exactly what `Config::transport_policy` keys
            // on.
            //
            // SEALED EXEMPTION (§113.4, CRITICAL): this line -- and every
            // use of `tp` below it, in this function and in
            // `load_attachments` -- is reached ONLY for a non-fed,
            // non-identity LOCAL PLUGIN destination. `process_due`'s own
            // dispatch, above, already sent a `FED_PROTOCOL` delivery to
            // `process_due_fed`, which for a `sealed` route hands off to
            // `process_due_fed_sealed` (whose own doc comment: "NO TRANSFORM
            // -- out_env is sealed EXACTLY as the caller left it") before
            // this function is ever called. So the exemption holds
            // STRUCTURALLY, by dispatch order, not by an in-line guard here
            // -- there is no shared code path between sealed egress and the
            // transport-policy resolution/application below to guard in the
            // first place.
            let tp = d.cfg_snapshot(|c| c.transport_policy(&del.destination.protocol));

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
                let per_minute = d.cfg_snapshot(|c| {
                    c.transport_budgets
                        .get(&del.destination.protocol)
                        .map(|b| b.messages_per_minute)
                        .unwrap_or(0)
                });
                let allowed = d.budget_limiter.lock().unwrap().allow(
                    &del.destination.protocol,
                    per_minute,
                    Instant::now(),
                );
                if !allowed {
                    metrics::inc(&metrics::BUDGET_DEFERRED);
                    let result = d
                        .store
                        .lock()
                        .unwrap()
                        .mark_retry(del.id, now + CDuration::seconds(10));
                    warn_if_mark_failed(del.id, "pending", result);
                    return;
                }
            }

            // Effective payload cap (design §3): min(plugin
            // Capabilities.max_payload, transport_policy.max_payload_bytes)
            // -- the transport cap COMPOSES with, never replaces, the
            // plugin's own protocol cap. Folding the combined value into
            // `cap_limit` itself (rather than adding a second truncation
            // stage) means the pre-existing `max_payload`/`cap_limit`
            // min-merge just below, and the single `transform::render` call
            // it feeds, already produce the right answer -- no truncation
            // stacked. For the TerrestrialInternet default this is a no-op
            // in practice: its transport cap is >= `MAX_FRAME` (16 MiB), at
            // least as large as anything a plugin has ever been able to
            // advertise (`TERRESTRIAL_MAX_PAYLOAD_BYTES`'s doc comment in
            // `relay_core::transport`) -- the backward-compat anchor.
            let cap_limit = Some(
                cap_limit
                    .map(|v| v as u64)
                    .unwrap_or(u64::MAX)
                    .min(tp.max_payload_bytes) as usize,
            );
            let limit = match (max_payload, cap_limit) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let alias = d
                .aliaser
                .alias(&env.source.protocol, &env.sender.native_ref, &del.route);

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
            let linked_mode = route_cfg
                .as_ref()
                .map(|r| r.identity_mode == "linked")
                .unwrap_or(false);
            let tag = if linked_mode {
                let link = d
                    .store
                    .lock()
                    .unwrap()
                    .link_for_identity(&env.source.protocol, &env.sender.native_ref)
                    .unwrap_or(None);
                link.map(|l| l.display_name)
                    .unwrap_or_else(|| alias.clone())
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
                load_attachments(d, &env.attachments, max_attachment_bytes, frame_budget, tp)
            } else {
                // destination lacks the capability, or policy rejects
                // attachments outright: strip every attachment and note it
                // once per attachment, without naming any of them (a
                // blanket strip must not reveal which files existed).
                let dropped: Vec<(String, u64)> = env
                    .attachments
                    .iter()
                    .map(|a| (a.filename.clone(), a.size))
                    .collect();
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
            let body = transform::render(render_tag, &format!("{truncated_body}{notes}"), limit);
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
                let result = d
                    .store
                    .lock()
                    .unwrap()
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
    d: &Arc<Daemon>,
    del: storage::Delivery,
    env: Envelope,
    now: DateTime<Utc>,
) {
    enum Readiness {
        Ready(mpsc::Sender<DaemonToPlugin>),
        Disconnected,
        NotDirectCapable,
    }
    let readiness = {
        let plugins = d.plugins.lock().unwrap();
        match plugins.get(&del.destination.protocol) {
            Some(h) if h.connected && h.capabilities.direct_messages => {
                Readiness::Ready(h.tx.clone())
            }
            Some(h) if h.connected => Readiness::NotDirectCapable,
            _ => Readiness::Disconnected,
        }
    };
    let tx = match readiness {
        Readiness::Ready(tx) => tx,
        Readiness::NotDirectCapable => {
            let result =
                d.store
                    .lock()
                    .unwrap()
                    .mark_terminal(del.id, "dead_letter", "NOT_DIRECT_CAPABLE");
            warn_if_mark_failed(del.id, "dead_letter", result);
            warn!(delivery = del.id, plugin = %del.destination.protocol,
                  "identity delivery dead-lettered: plugin connected but not direct-capable");
            emit_delivery(d, del.message_id, del.route.clone(), "dead_letter");
            return;
        }
        Readiness::Disconnected => {
            let result = d
                .store
                .lock()
                .unwrap()
                .mark_retry(del.id, now + CDuration::seconds(5));
            warn_if_mark_failed(del.id, "pending", result);
            return;
        }
    };

    if del.priority > 0 {
        let per_minute = d.cfg_snapshot(|c| {
            c.transport_budgets
                .get(&del.destination.protocol)
                .map(|b| b.messages_per_minute)
                .unwrap_or(0)
        });
        let allowed = d.budget_limiter.lock().unwrap().allow(
            &del.destination.protocol,
            per_minute,
            Instant::now(),
        );
        if !allowed {
            metrics::inc(&metrics::BUDGET_DEFERRED);
            let result = d
                .store
                .lock()
                .unwrap()
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
        let result = d
            .store
            .lock()
            .unwrap()
            .mark_retry(del.id, now + CDuration::seconds(5));
        warn_if_mark_failed(del.id, "pending", result);
        warn!(delivery = del.id, plugin = %del.destination.protocol,
              reason = closed_or_full, "plugin channel unavailable, requeued");
    }
}

/// Federation egress (design §5, Task 5): delivers an envelope whose
/// destination is `fed:<peer_name>/<remote_route>` (`del.destination.
/// endpoint`, already validated at config-load time to have this shape --
/// see `config::validate_fed_destination`) over a live `fed::conn`
/// connection to that peer. Mirrors `process_due_identity`'s
/// dispatch-by-destination shape in `process_due` above: this function owns
/// the entire fed-specific send end to end.
///
/// CONNECTION LOOKUP FIRST (design §5's own ordering): `FedState.conns` is
/// keyed by peer NAME for a configured peer (`fed::conn::register_up`'s
/// convention, whichever side dialed) -- looked up before any of the
/// envelope work below runs, so a disconnected peer costs nothing more than
/// a `mark_retry` (existing retry/backoff/TTL posture, unchanged), exactly
/// like a disconnected plugin in `process_due`/`process_due_identity`
/// above.
///
/// PSEUDONYMIZATION ORDER (design §5, Task 5 -- documented here because
/// it's easy to get backwards and silently ship a signature that doesn't
/// cover what the peer actually sees): `env.origin.is_none()` is the signal
/// for "locally originated, never signed before". ONLY in that case does
/// this daemon (a) optionally replace `sender.native_ref` with a
/// route-scoped alias (`identity_exposure: pseudonymous`, the default) and
/// (b) sign the origin itself -- pseudonymization strictly BEFORE signing,
/// so the origin signature's canonical bytes (which include
/// `sender.native_ref`, see `fed::sign::canonical_bytes`) cover the alias
/// the peer will actually see, never the raw ref. An envelope that already
/// carries an origin signature (relayed federation traffic: this daemon
/// ingressed it from ANOTHER peer, via `fed_ingress`, and is now forwarding
/// it onward because the local route it landed on also has a `fed:`
/// destination) is NEVER pseudonymized or re-signed here -- the ref was
/// already fixed (or deliberately left raw, if THAT origin's own
/// `identity_exposure` was `full`) by whichever gateway actually signed it,
/// and mutating `sender.native_ref` on an already-signed envelope would
/// break that origin signature outright: any downstream peer's
/// `fed::sign::verify_chain` would then fail with `BAD_SIGNATURE`,
/// dead-lettering a perfectly legitimate relay. Appending this daemon's own
/// attestation and incrementing `hops` happen unconditionally, on BOTH
/// paths -- that's this hop's actual provenance record regardless of
/// whether it originated the message or is merely forwarding it.
async fn process_due_fed(
    d: &Arc<Daemon>,
    del: storage::Delivery,
    env: Envelope,
    now: DateTime<Utc>,
) {
    let Some((peer_name, remote_route)) = del.destination.endpoint.split_once('/') else {
        // Unreachable in practice: `config::validate_fed_destination`
        // enforces this shape at config-load time, so every `fed:` delivery
        // row's `dest_endpoint` already has the separator. Defensive only
        // (e.g. a hand-built row in a test) -- failed outright rather than
        // retried forever against a shape that can never become valid.
        let result = d
            .store
            .lock()
            .unwrap()
            .mark_terminal(del.id, "failed", "FED_DEST_MALFORMED");
        warn_if_mark_failed(del.id, "failed", result);
        emit_delivery(d, del.message_id, del.route.clone(), "failed");
        return;
    };

    let tx = d.fed.as_ref().and_then(|fed| {
        fed.conns
            .lock()
            .unwrap()
            .get(peer_name)
            .map(|c| c.tx.clone())
    });
    let Some(tx) = tx else {
        // No live connection to this peer (never connected, or currently
        // down between reconnect attempts) -- same posture as a
        // disconnected plugin: nudge next_attempt forward, stay pending.
        let result = d
            .store
            .lock()
            .unwrap()
            .mark_retry(del.id, now + CDuration::seconds(5));
        warn_if_mark_failed(del.id, "pending", result);
        return;
    };

    // Federation egress budget (design §5, carried from cycle F's review:
    // the many-distinct-senders flood gap -- a peer fed from many distinct
    // local native_refs never individually trips any per-sender limit, so
    // this caps the PEER'S LINK as a whole instead). Keyed "fed/<peer_name>"
    // in the SAME `BudgetLimiter` instance `process_due`'s transport-budget
    // check uses (above, non-fed branch) -- distinct key namespace
    // ("fed/" prefix) so a peer named the same as a plugin protocol can
    // never collide with that protocol's own transport budget. Checked
    // BEFORE any of the pseudonymization/signing work below, so a deferred
    // send never pays for work that's about to be thrown away.
    //
    // NO priority-based bypass here, UNLIKE the transport-budget check
    // above (which lets priority-0/emergency sends skip it entirely): the
    // cycle-F priority ruling is that federation egress has no emergency
    // lane at all -- an emergency envelope routed over a fed destination
    // still queues behind this peer's budget like every other send, full
    // stop. `messages_per_minute: 0` (absent/default, `PeerConfig`'s doc
    // comment) is unlimited and never touches `budget_limiter`'s map at
    // all (`BudgetLimiter::allow`'s own `per_minute == 0` fast path).
    //
    // Rebuild-on-apply: `Daemon::apply_config` resets `budget_limiter` to
    // a fresh `BudgetLimiter::new()` unconditionally on EVERY apply (not
    // conditioned on `federation` having changed) -- so a "fed/<peer_name>"
    // key clears exactly when every `transport_budgets` key does, with no
    // separate reset plumbing needed here (verified directly,
    // `fed_egress_budget_resets_on_apply_config` below).
    let per_minute = d.cfg_snapshot(|c| {
        c.federation
            .as_ref()
            .and_then(|f| f.peers.iter().find(|p| p.name == peer_name))
            .map(|p| p.messages_per_minute)
            .unwrap_or(0)
    });
    let allowed = d.budget_limiter.lock().unwrap().allow(
        &format!("fed/{peer_name}"),
        per_minute,
        Instant::now(),
    );
    if !allowed {
        metrics::inc(&metrics::BUDGET_DEFERRED);
        let result = d
            .store
            .lock()
            .unwrap()
            .mark_retry(del.id, now + CDuration::seconds(5));
        warn_if_mark_failed(del.id, "pending", result);
        return;
    }

    let identity_exposure = d
        .cfg_snapshot(|c| c.federation.as_ref().map(|f| f.identity_exposure.clone()))
        .unwrap_or_else(|| "pseudonymous".to_string());

    let mut out_env = env.clone();
    if out_env.origin.is_none() {
        // Locally originated: never signed before this hop (see this
        // function's doc comment for why this check gates BOTH the
        // pseudonymization and the signing below).
        if identity_exposure == "pseudonymous" {
            let scope = format!("fed:{peer_name}/{remote_route}");
            out_env.sender.native_ref =
                d.aliaser
                    .alias(&out_env.source.protocol, &out_env.sender.native_ref, &scope);
        }
        out_env.origin = Some(fed::sign::sign_origin(&out_env, &d.identity));
    }
    if let Err(e) = fed::sign::append_attestation(&mut out_env, &d.identity, Utc::now()) {
        // Only reachable if `out_env.origin` is somehow still `None` here,
        // which the branch above already ruled out -- defensive, not a
        // real runtime path. Retried rather than dropped: a transient bug
        // here shouldn't silently lose the message.
        warn!(delivery = del.id, error = %e, "failed to append federation attestation");
        let result = d
            .store
            .lock()
            .unwrap()
            .mark_retry(del.id, now + CDuration::seconds(5));
        warn_if_mark_failed(del.id, "pending", result);
        return;
    }
    out_env.hops += 1;

    // Design §3/§4, SPEC §113.1/§113.4, cycle H, Task 4, review fix round 1
    // (CRITICAL, cleartext-downgrade finding): the shared prefix above
    // (connection lookup, budget, pseudonymize/sign/attest/hops) is
    // IDENTICAL for `gateway` and `sealed` routes -- that machinery is
    // cycle-F identity exposure/provenance, not a §113.4 "transform"
    // (render/truncate/attachment-note; this function never applied any of
    // those to EITHER mode -- process_due's own render pipeline is only
    // ever reached for a non-fed destination, see `process_due`'s dispatch
    // order above). Only the FINAL wire-encoding step branches: a
    // `gateway` route sends `out_env` cleartext (`Fed::Envelope`, below,
    // unchanged from cycle F); a `sealed` route seals it first
    // (`process_due_fed_sealed`, design §4) and sends `Fed::Sealed`
    // instead -- never both, never a cleartext fallback if sealing can't
    // proceed (fail-closed: see that function's own doc comment).
    //
    // `del.route` NOT resolving to a CURRENT `RouteConfig` -- the route was
    // renamed/removed from config since this delivery was queued (a live
    // `PUT /v1/config` reload, or a restart against an edited config file:
    // deliveries persist across restarts) -- MUST fail closed, never
    // silently default to `"gateway"`. Defaulting to gateway would send a
    // delivery that was queued under a `sealed` route as a CLEARTEXT
    // `Fed::Envelope`, carrying the original unsealed body -- an unknown
    // security posture is never safe to treat as "least private". This
    // applies uniformly regardless of what the route USED to be: an
    // unresolvable route means the posture literally cannot be determined,
    // so this never guesses either way (a gateway-mode delivery whose
    // route vanished ALSO dead-letters here, not just a sealed one).
    let Some(route_cfg) = d.route_cfg(&del.route) else {
        let result =
            d.store
                .lock()
                .unwrap()
                .mark_terminal(del.id, "dead_letter", "ROUTE_CONFIG_MISSING");
        warn_if_mark_failed(del.id, "dead_letter", result);
        warn!(delivery = del.id, route = %del.route, peer = peer_name,
              "fed egress dead-lettered: route config not found (renamed/removed since this \
               delivery was queued) -- security posture cannot be determined, failing closed \
               rather than defaulting to gateway");
        emit_delivery(d, del.message_id, del.route.clone(), "dead_letter");
        return;
    };
    if route_cfg.security_mode == "sealed" {
        process_due_fed_sealed(d, &del, out_env, peer_name, remote_route, tx, now).await;
        return;
    }

    let result = d.store.lock().unwrap().mark_attempting(del.id);
    warn_if_mark_failed(del.id, "attempting", result);

    let frame = fed::wire::Fed::Envelope {
        env: Box::new(out_env),
        target_route: remote_route.to_string(),
    };
    // try_send, not send().await -- see process_due's identical rationale
    // above: this pump task must never block on one peer connection's
    // channel.
    match tx.try_send(frame) {
        Ok(()) => metrics::inc(&metrics::FED_EGRESS),
        Err(e) => {
            let closed_or_full = match e {
                mpsc::error::TrySendError::Full(_) => "full",
                mpsc::error::TrySendError::Closed(_) => "closed",
            };
            let result = d
                .store
                .lock()
                .unwrap()
                .mark_retry(del.id, now + CDuration::seconds(5));
            warn_if_mark_failed(del.id, "pending", result);
            warn!(
                delivery = del.id,
                peer = peer_name,
                reason = closed_or_full,
                "federation connection unavailable, requeued"
            );
        }
    }
}

/// Margin subtracted from `fed::noise::MAX_FRAME` to get `SEALED_MAX_BYTES`
/// (Task 4 review fix round 1, minor #2): the check below runs against the
/// PRE-seal canonical envelope bytes, but what actually has to fit under
/// `MAX_FRAME` on the wire is the POST-seal, POST-frame-wrap bytes -- the
/// `SealedEnvelope` adds a 32-byte ephemeral pubkey + 24-byte nonce +
/// 16-byte AEAD tag (72 bytes) over the plaintext, and ciborium CBOR-map
/// framing for both the `SealedEnvelope` struct itself and the wrapping
/// `Fed::Sealed { sealed, target_route }` frame adds a further (small,
/// bounded-by-field-count) handful of bytes. At exactly the old
/// (margin-less) ceiling, that overhead pushed the real wire frame just
/// PAST `MAX_FRAME` -- `FedChannel::send_frame` would then reject it
/// AFTER `mark_attempting` had already been recorded, silently stranding
/// the delivery in `attempting` with no dead-letter and no retry. 512
/// bytes is comfortably more than the ~100 bytes of actual overhead (any
/// realistic `target_route`/`id`/`alg` string length included), so
/// `SEALED_MAX_BYTES` guarantees headroom rather than tracking the exact
/// overhead byte-for-byte.
const SEALED_OVERHEAD_MARGIN: u64 = 512;

/// Hard ceiling on a sealed envelope's PRE-seal canonical CBOR size (design
/// §4, SPEC §113.4: "oversized sealed payloads for constrained transports
/// are rejected at origin, not shrunk in transit"). Phase-1 has no
/// per-peer ADVERTISED constrained-transport max to check against yet --
/// `fed::advert::ProtoCaps::max_payload` is always `None` this cycle (see
/// that field's doc comment: live-capability enrichment is future work) --
/// so this reuses `fed::noise::MAX_FRAME` (16 MiB), the actual Noise
/// transport frame ceiling ANY sealed frame would have to fit under to
/// cross the wire at all (`fed::noise::FedChannel::send_frame`/
/// `recv_frame`), minus `SEALED_OVERHEAD_MARGIN` (see that constant's doc
/// comment for why a margin is needed at all) rather than inventing a
/// second, narrower operator-visible number from scratch. Checked against
/// the PRE-seal canonical envelope bytes, not the post-seal
/// `SealedEnvelope`'s serialized size -- cheaper (no AEAD call wasted on
/// something already too big), and the margin above is what makes that
/// substitution safe.
const SEALED_MAX_BYTES: u64 = fed::noise::MAX_FRAME as u64 - SEALED_OVERHEAD_MARGIN;

/// Resolves the peer's sealed X25519 recipient key for sealed egress
/// (design §1/§4, SPEC §113.3): the config pin (`PeerConfig::sealed_key`)
/// wins when present, even over a DIFFERENT advert-learned key (logged as
/// a warn rather than silently overridden -- design §1: "if both present
/// and disagree -> config wins + a warn"); otherwise the peer's own
/// verified, stored `Fed::Advert::security.sealed_key`. The stored advert
/// row is re-decoded and re-`advert::verify`d here, and its embedded
/// `node_id` re-checked against the row key it's stored under -- the same
/// "never trust a stored row without re-verifying its own signature and
/// node_id binding on every use" posture `admin::discovery`'s peer listing
/// already takes (a DB-write-capable attacker with no victim private key
/// could otherwise insert a row keyed under a trusted peer's `node_id`
/// carrying attacker-chosen advert content, self-signed under the
/// attacker's OWN key -- `advert::verify` alone would pass it right
/// through). `None` when NEITHER source has a usable key (absent, or
/// present but not valid 64-hex-char/32-byte X25519 key material) -- the
/// caller's fail-closed contract (`NO_SEALED_KEY` dead-letter, never
/// unsealed egress) depends on this never silently defaulting to "somehow
/// proceed anyway".
fn resolve_sealed_key(d: &Daemon, peer_name: &str) -> Option<crypto_box::PublicKey> {
    let (config_pin, node_id) = d.cfg_snapshot(|c| {
        c.federation
            .as_ref()
            .and_then(|f| f.peers.iter().find(|p| p.name == peer_name))
            .map(|p| (p.sealed_key.clone(), p.node_id.clone()))
    })?;

    // Task 4 review fix round 1 (minor #3, doc-only): as of today,
    // `config::validate_sealed_route`'s "each `sealed` route's peer must
    // carry a CONFIG-PINNED `sealed_key`" rule means no config that passes
    // `--check-config` can ever reach this function with a config-pin-less
    // peer on a sealed route -- this advert-learned branch is currently
    // unreachable through any validated config, exercised only by tests
    // that build a `Daemon` directly (bypassing `validate`). It stays as
    // forward-compat defense-in-depth (design §1: advert-learned keys are
    // real API surface, e.g. once a future phase relaxes the config-pin
    // requirement), not dead code to delete.
    let advert_key = d
        .store
        .lock()
        .unwrap()
        .list_peer_adverts(Utc::now())
        .unwrap_or_default()
        .into_iter()
        .find(|(nid, _, _)| nid == &node_id)
        .and_then(|(nid, cbor, _)| {
            let decoded: fed::advert::Advert = ciborium::from_reader(cbor.as_slice()).ok()?;
            (fed::advert::verify(&decoded).is_ok() && decoded.node_id == nid)
                .then_some(decoded.security.sealed_key)
                .flatten()
        });

    let chosen_hex = match (&config_pin, &advert_key) {
        (Some(cfg), Some(adv)) => {
            if cfg != adv {
                warn!(
                    peer = peer_name,
                    "sealed_key config pin disagrees with advert-learned key; config wins"
                );
            }
            cfg.clone()
        }
        (Some(cfg), None) => cfg.clone(),
        (None, Some(adv)) => adv.clone(),
        (None, None) => return None,
    };

    let bytes = hex::decode(&chosen_hex).ok()?;
    crypto_box::PublicKey::from_slice(&bytes).ok()
}

/// Sealed fed egress (design §4, SPEC §113.4, cycle H, Task 4): the
/// `security_mode: sealed` counterpart to `process_due_fed`'s gateway-mode
/// tail. `out_env` has already been pseudonymized (if applicable)/
/// origin-signed/attested/hop-incremented by the shared prefix in the
/// caller -- see that call site's doc comment for why sealed mode reuses
/// that step unchanged rather than skipping it.
///
/// NO TRANSFORM (§113.4): `out_env` -- body, attachments, everything -- is
/// sealed EXACTLY as the caller left it. There is no render/truncate/
/// attachment-note call anywhere on this path.
///
/// Fail-closed key resolution: no sealed key for this peer (neither a
/// config pin nor a verified advert-learned one, `resolve_sealed_key`) ->
/// dead-letter `NO_SEALED_KEY`, NEVER falls back to sending `out_env`
/// unsealed.
///
/// Fail-closed size guard (SPEC §113.4: "oversized sealed payloads for
/// constrained transports are rejected at origin, not shrunk in
/// transit"): the pre-seal canonical envelope CBOR over `SEALED_MAX_BYTES`
/// -> dead-letter `SEALED_OVERSIZE`, never shrunk.
///
/// `seal::seal` (plain, ephemeral-per-call), never `seal::
/// seal_with_ephemeral` -- Task 2 review binding note: production egress
/// must always use a fresh ephemeral key, never a persisted/reused one.
///
/// Ack unchanged: `SealedEnvelope::id` (the cleartext header field, set
/// here to `out_env.id.to_string()`) is exactly what a peer's `Fed::
/// Ack{id}` reply will carry back -- `storage::Store::
/// deliveries_for_fed_ack`'s `(message_id, peer_key)` lookup matches it
/// the same way it already matches a gateway-mode `Fed::Envelope`'s id.
async fn process_due_fed_sealed(
    d: &Arc<Daemon>,
    del: &storage::Delivery,
    out_env: Envelope,
    peer_name: &str,
    remote_route: &str,
    tx: mpsc::Sender<fed::wire::Fed>,
    now: DateTime<Utc>,
) {
    let Some(recipient_pub) = resolve_sealed_key(d, peer_name) else {
        let result = d
            .store
            .lock()
            .unwrap()
            .mark_terminal(del.id, "dead_letter", "NO_SEALED_KEY");
        warn_if_mark_failed(del.id, "dead_letter", result);
        warn!(delivery = del.id, peer = peer_name,
              "sealed egress dead-lettered: no sealed key for this peer (config pin or verified advert)");
        emit_delivery(d, del.message_id, del.route.clone(), "dead_letter");
        return;
    };

    let mut canonical_env_cbor = Vec::new();
    ciborium::into_writer(&out_env, &mut canonical_env_cbor)
        .expect("Envelope always serializes to CBOR");
    if canonical_env_cbor.len() as u64 > SEALED_MAX_BYTES {
        let result =
            d.store
                .lock()
                .unwrap()
                .mark_terminal(del.id, "dead_letter", "SEALED_OVERSIZE");
        warn_if_mark_failed(del.id, "dead_letter", result);
        warn!(delivery = del.id, peer = peer_name, size = canonical_env_cbor.len(),
              "sealed egress dead-lettered: envelope exceeds the sealed size ceiling, rejected at origin");
        emit_delivery(d, del.message_id, del.route.clone(), "dead_letter");
        return;
    }

    let max_ttl_secs = d
        .cfg_snapshot(|c| c.federation.as_ref().map(|f| f.max_ttl_secs))
        .unwrap_or(86_400);
    let expires_at = (out_env.created_at + CDuration::seconds(max_ttl_secs as i64)).timestamp();
    let sealed = fed::seal::seal(
        &canonical_env_cbor,
        &out_env.id.to_string(),
        expires_at,
        &recipient_pub,
    );

    let result = d.store.lock().unwrap().mark_attempting(del.id);
    warn_if_mark_failed(del.id, "attempting", result);

    let frame = fed::wire::Fed::Sealed {
        sealed,
        target_route: remote_route.to_string(),
    };
    // try_send, not send().await -- same rationale as the gateway path.
    match tx.try_send(frame) {
        Ok(()) => metrics::inc(&metrics::SEALED_EGRESS),
        Err(e) => {
            let closed_or_full = match e {
                mpsc::error::TrySendError::Full(_) => "full",
                mpsc::error::TrySendError::Closed(_) => "closed",
            };
            let result = d
                .store
                .lock()
                .unwrap()
                .mark_retry(del.id, now + CDuration::seconds(5));
            warn_if_mark_failed(del.id, "pending", result);
            warn!(
                delivery = del.id,
                peer = peer_name,
                reason = closed_or_full,
                "federation connection unavailable, requeued (sealed)"
            );
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
/// 0. the destination transport's media policy (design §3, spec §113.4):
///    `!tp.allow_images`/`!tp.allow_video` demotes an `image/*`/`video/*`
///    attachment to a note, REUSING this same "strip from `attachments`,
///    note it instead" shape the two byte-cap checks below already use --
///    just a different reason wording, so the recipient can tell a
///    transport-policy demotion apart from an oversize drop. Checked first
///    since it's a cheap string-prefix test, no different in spirit from
///    checking `meta.size` before touching the CAS. Non-media attachments,
///    and media the transport allows, fall through to the existing checks
///    unchanged.
/// 1. the per-attachment policy byte cap (`max_attachment_bytes`), then
/// 2. the cumulative `frame_budget` guard, so the whole Send frame stays
///    under `MAX_FRAME` even when several in-cap attachments are combined.
///
/// Anything that fails any of these, plus anything whose blob has gone
/// missing from the CAS, is dropped from the attachment list and noted in
/// the returned string instead — never logged, since attachment
/// filenames/content are message content (see `handle_inbound`'s
/// module-level note on the same point).
fn load_attachments(
    d: &Daemon,
    metas: &[AttachmentMeta],
    max_attachment_bytes: Option<u64>,
    frame_budget: u64,
    tp: relay_core::TransportPolicy,
) -> (Vec<IpcAttachment>, String) {
    let mut attachments = Vec::new();
    let mut notes = String::new();
    let mut cumulative: u64 = 0;
    for meta in metas {
        let demote = if meta.mime.starts_with("image/") && !tp.allow_images {
            Some("image")
        } else if meta.mime.starts_with("video/") && !tp.allow_video {
            Some("video")
        } else {
            None
        };
        if let Some(kind) = demote {
            notes.push_str(&format!(
                "\n[{kind} '{}' omitted — constrained transport]",
                meta.filename
            ));
            metrics::inc(&metrics::TRANSPORT_DEMOTED);
            continue;
        }
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
        Budget, Config, FederationConfig, Limits, NodeConfig, PluginConfig, PublicService,
        RenderConfig, RouteConfig,
    };
    use std::collections::BTreeMap;

    pub fn test_daemon(dir: &std::path::Path) -> Daemon {
        test_daemon_full(dir, Limits::default(), BTreeMap::new(), false, vec![], None)
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
        test_daemon_full(dir, limits, BTreeMap::new(), false, vec![], None)
    }

    /// Like `test_daemon`, but with caller-supplied `transport_budgets`.
    /// `BudgetLimiter` is re-read live from `d.cfg.transport_budgets` on
    /// every pump tick (unlike `sender_limiter`/`cas`, which cache their
    /// config at construction) — this only exists so budget tests don't have
    /// to spell out the full `Config` literal.
    pub fn test_daemon_with_budgets(
        dir: &std::path::Path,
        transport_budgets: BTreeMap<String, Budget>,
    ) -> Daemon {
        test_daemon_full(
            dir,
            Limits::default(),
            transport_budgets,
            false,
            vec![],
            None,
        )
    }

    /// Like `test_daemon`, but with caller-supplied `node.public` and
    /// `public_services` — for admin `/v1/public` tests. `config::validate`
    /// is not run here (these build the `Config` literal directly, the way
    /// every other `test_daemon_*` helper does), so unlike a config loaded
    /// from disk, `public: true` with services that don't actually cover
    /// the fixture's `general` route is accepted at construction time.
    pub fn test_daemon_with_public(
        dir: &std::path::Path,
        public: bool,
        services: Vec<PublicService>,
    ) -> Daemon {
        test_daemon_full(
            dir,
            Limits::default(),
            BTreeMap::new(),
            public,
            services,
            None,
        )
    }

    /// Like `test_daemon`, but with a caller-supplied `federation` block --
    /// the `general` fixture route (sources/destinations `mocka:chan`/
    /// `mockb:chan`) is otherwise unchanged, so a `federation.ingress_routes:
    /// ["general"]` config gives `fed_ingress` tests a real route with two
    /// local fan-out destinations to assert deliveries against, without
    /// needing a bespoke route just for federation. Also seeds the trust
    /// store from `federation` (`Store::seed_federation_trust`), the same
    /// as `fed::conn::spawn_federation` does at real boot -- `Daemon::new`
    /// itself does NOT do this (only `spawn_federation` owns that call
    /// site in production), so a test driving `fed_ingress` directly
    /// (bypassing `spawn_federation` entirely) needs it done here instead.
    pub fn test_daemon_with_federation(
        dir: &std::path::Path,
        federation: FederationConfig,
    ) -> Daemon {
        let d = test_daemon_full(
            dir,
            Limits::default(),
            BTreeMap::new(),
            false,
            vec![],
            Some(federation.clone()),
        );
        d.store
            .lock()
            .unwrap()
            .seed_federation_trust(&federation, Utc::now())
            .unwrap();
        d
    }

    /// Like `test_daemon_with_federation`, but also with a caller-supplied
    /// `Limits` (needed for the per-sender rate-limit test, same rationale
    /// as `test_daemon_with_limits`: `sender_limiter` bakes in its numbers
    /// at construction).
    pub fn test_daemon_with_federation_and_limits(
        dir: &std::path::Path,
        federation: FederationConfig,
        limits: Limits,
    ) -> Daemon {
        let d = test_daemon_full(
            dir,
            limits,
            BTreeMap::new(),
            false,
            vec![],
            Some(federation.clone()),
        );
        d.store
            .lock()
            .unwrap()
            .seed_federation_trust(&federation, Utc::now())
            .unwrap();
        d
    }

    fn test_daemon_full(
        dir: &std::path::Path,
        limits: Limits,
        transport_budgets: BTreeMap<String, Budget>,
        public: bool,
        public_services: Vec<PublicService>,
        federation: Option<FederationConfig>,
    ) -> Daemon {
        let mut plugins = BTreeMap::new();
        for name in ["mocka", "mockb"] {
            plugins.insert(
                name.to_string(),
                PluginConfig {
                    enabled: true,
                    command: None,
                    config: serde_yaml::Value::Null,
                    peer_uid: None,
                },
            );
        }
        let cfg = Config {
            node: NodeConfig {
                name: "t".into(),
                data_dir: dir.to_path_buf(),
                public,
            },
            plugins,
            raw_plugin_configs: BTreeMap::new(),
            raw_yaml: String::new(),
            routes: vec![RouteConfig {
                name: "general".into(),
                sources: vec!["mocka:chan".parse().unwrap(), "mockb:chan".parse().unwrap()],
                destinations: vec!["mocka:chan".parse().unwrap(), "mockb:chan".parse().unwrap()],
                identity_mode: "pseudonymous".into(),
                render: RenderConfig::default(),
                security_mode: "gateway".into(),
                allow_gateway_decryption: None,
            }],
            policies: vec![],
            ttl_default_secs: 3600,
            dedup_ttl_secs: 3600,
            hop_limit: 8,
            max_attachment_bytes: 8 * 1024 * 1024,
            public_services,
            limits,
            transport_budgets,
            federation,
            discovery: crate::config::DiscoveryConfig::default(),
            privacy: crate::config::PrivacyConfig::default(),
            transports: BTreeMap::new(),
        };
        Daemon::new(cfg, dir).unwrap()
    }

    /// A federated peer's Ed25519 identity for tests -- distinct from the
    /// daemon's own `d.identity` (which speaks for the LOCAL node), this
    /// is the identity of a simulated REMOTE origin gateway: whatever
    /// `fed::sign::sign_origin`/`append_attestation` produce with it is
    /// what `engine::fed_ingress`'s signature-chain gate verifies, and its
    /// `node_id()` is what a test seeds into the trust store / passes as
    /// `fed_ingress`'s `peer_node_id` param.
    pub fn test_peer_identity(dir: &std::path::Path, name: &str) -> NodeIdentity {
        NodeIdentity::load_or_create(&dir.join(name)).unwrap()
    }

    /// A signed, federation-ready envelope: origin-signed by `identity`
    /// (a simulated remote gateway's own identity, e.g.
    /// `test_peer_identity`), `hops` and `body` are the two knobs
    /// `fed_ingress` tests actually vary; everything else is fixed
    /// (arbitrary but valid) test data.
    pub fn signed_test_envelope(identity: &NodeIdentity, body: &str, hops: u32) -> Envelope {
        let now = Utc::now();
        let mut env = Envelope::new(
            Endpoint {
                protocol: "mock".into(),
                endpoint: "origin-chan".into(),
            },
            Sender {
                native_ref: "!origin-sender".into(),
            },
            "text".into(),
            body.to_string(),
            now,
            now + CDuration::hours(1),
            8,
        );
        env.hops = hops;
        env.origin = Some(crate::fed::sign::sign_origin(&env, identity));
        env
    }

    /// Registers a connected mock plugin with (optionally) the `attachments`
    /// capability — shared by engine's own tests and admin.rs's Tower-oneshot
    /// tests (identity-link admin endpoints need a way to stand up a
    /// non-direct-capable plugin for the 409 rejection path).
    pub fn register_plugin(
        d: &Daemon,
        name: &str,
        attachments: bool,
    ) -> mpsc::Receiver<DaemonToPlugin> {
        let (tx, rx) = mpsc::channel(8);
        d.plugins.lock().unwrap().insert(
            name.to_string(),
            PluginHandle {
                tx,
                capabilities: Capabilities {
                    attachments,
                    ..Capabilities::default()
                },
                connected: true,
            },
        );
        rx
    }

    /// Registers a connected mock plugin that advertises
    /// `capabilities.direct_messages` — shared by engine's own tests and
    /// admin.rs's Tower-oneshot tests for `POST /v1/identities/link`.
    pub fn register_direct_plugin(d: &Daemon, name: &str) -> mpsc::Receiver<DaemonToPlugin> {
        let (tx, rx) = mpsc::channel(8);
        d.plugins.lock().unwrap().insert(
            name.to_string(),
            PluginHandle {
                tx,
                capabilities: Capabilities {
                    direct_messages: true,
                    ..Capabilities::default()
                },
                connected: true,
            },
        );
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tests_support::{
        register_direct_plugin, register_plugin, signed_test_envelope, test_daemon,
        test_daemon_with_budgets, test_daemon_with_federation,
        test_daemon_with_federation_and_limits, test_daemon_with_limits, test_peer_identity,
    };

    #[test]
    fn inbound_routes_to_other_endpoint_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
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
        // one delivery row, to mockb, none echoed to mocka
        let store = d.store.lock().unwrap();
        let counts = store.queue_counts().unwrap();
        assert_eq!(counts, vec![("pending".to_string(), 1)]);
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(due[0].destination.protocol, "mockb");
        drop(store);
        // duplicate is dropped
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
        assert_eq!(
            d.store.lock().unwrap().queue_counts().unwrap(),
            vec![("pending".to_string(), 1)]
        );
        // unrouted endpoint is dropped (deny by default)
        handle_inbound(
            &d,
            "mocka",
            "elsewhere".into(),
            "!a".into(),
            "text".into(),
            "hi".into(),
            None,
            vec![],
            None,
        );
        assert_eq!(
            d.store.lock().unwrap().queue_counts().unwrap(),
            vec![("pending".to_string(), 1)]
        );
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
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "no priority sent".into(),
            None,
            vec![],
            None,
        );
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "typo'd priority".into(),
            None,
            vec![],
            Some("urgent".into()),
        );

        let store = d.store.lock().unwrap();
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(due.len(), 2);
        assert!(
            due.iter().all(|d| d.priority == 2),
            "both a missing and an unrecognized priority must schedule at the normal rank"
        );

        let envs: Vec<_> = due
            .iter()
            .map(|d| store.get_message(d.message_id).unwrap().unwrap())
            .collect();
        assert!(
            envs.iter().any(|e| e.priority == "normal"),
            "a missing priority must default the stored class to \"normal\""
        );
        assert!(
            envs.iter().any(|e| e.priority == "urgent"),
            "an unrecognized class name must be stored verbatim, not silently rewritten"
        );
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
            )
            .unwrap();
        }
        let delivery_id = {
            let store = d.store.lock().unwrap();
            store
                .insert_delivery(
                    ghost_id,
                    "general",
                    &dest,
                    now,
                    now + CDuration::hours(1),
                    2,
                )
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

        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
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
        assert_eq!(
            mode, 0o700,
            "pre-existing loose-permission data dir must be tightened"
        );
    }

    #[tokio::test]
    async fn process_due_requeues_instead_of_blocking_when_plugin_channel_is_full() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));

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
        d.plugins.lock().unwrap().insert(
            "mockb".to_string(),
            PluginHandle {
                tx,
                capabilities: Capabilities::default(),
                connected: true,
            },
        );

        let del = {
            let store = d.store.lock().unwrap();
            store.deliveries_for_id(delivery_id).unwrap()
        };

        // Regression guard: process_due used to `.await` a send on this
        // channel, which would hang forever with the slot held. It must
        // return promptly and leave the delivery pending for the next tick.
        tokio::time::timeout(std::time::Duration::from_secs(2), process_due(&d, del, now))
            .await
            .expect("process_due hung on a full plugin channel");

        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
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

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            None,
            vec![small, big],
            None,
        );

        let store = d.store.lock().unwrap();
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(due.len(), 1);
        let env = store.get_message(due[0].message_id).unwrap().unwrap();

        assert_eq!(
            env.attachments.len(),
            1,
            "only the in-cap attachment gets a meta"
        );
        assert_eq!(env.attachments[0].sha256, expected_sha);
        assert_eq!(env.attachments[0].filename, "small.txt");
        assert_eq!(env.attachments[0].size, 4);

        assert!(
            env.body.contains("[dropped big.bin: 64 B over 16 B limit]"),
            "body did not carry the drop note: {}",
            env.body
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
        handle_inbound(
            &d,
            "mocka",
            "elsewhere".into(),
            "!a".into(),
            "text".into(),
            "hi".into(),
            None,
            vec![att],
            None,
        );

        assert!(
            d.cas.get(&sha).is_err(),
            "unrouted message must not write attachment bytes to the CAS"
        );
        let entries: Vec<_> = std::fs::read_dir(dir.path().join("attachments"))
            .unwrap()
            .collect();
        assert!(
            entries.is_empty(),
            "CAS dir must contain no files for a dropped/unrouted message"
        );
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
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "first".into(),
            None,
            vec![shared.clone()],
            None,
        );
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "second".into(),
            None,
            vec![shared],
            None,
        );
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
        let (purged1, orphans1) = d
            .store
            .lock()
            .unwrap()
            .purge_terminal(now + CDuration::hours(1))
            .unwrap();
        assert_eq!(purged1, 1);
        assert!(
            orphans1.is_empty(),
            "sha still referenced by the second (pending) message must survive: {orphans1:?}"
        );
        for s in &orphans1 {
            d.cas.remove(s).unwrap();
        }
        assert_eq!(
            d.cas.get(&sha).unwrap(),
            b"shared bytes",
            "CAS blob must survive: a live message still references it"
        );

        // now finish off the second message too and purge again: nothing
        // references the sha anymore, so it must come back as orphaned and
        // be removable.
        {
            let store = d.store.lock().unwrap();
            store.mark_attempting(id2).unwrap();
            store.mark_delivered(id2).unwrap();
        }
        let (purged2, orphans2) = d
            .store
            .lock()
            .unwrap()
            .purge_terminal(now + CDuration::hours(1))
            .unwrap();
        assert_eq!(purged2, 1);
        assert_eq!(orphans2, vec![sha.clone()]);
        for s in &orphans2 {
            d.cas.remove(s).unwrap();
        }
        assert!(
            d.cas.get(&sha).is_err(),
            "now-truly-orphaned blob must be removable"
        );
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
            filename: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            data: b"just some bytes".to_vec(),
        };
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "look at this".into(),
            None,
            vec![att.clone()],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send {
            body, attachments, ..
        } = recv_send(&mut rx).await
        else {
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
            filename: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            data: b"bytes".to_vec(),
        };
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "look at this".into(),
            None,
            vec![att],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send {
            body, attachments, ..
        } = recv_send(&mut rx).await
        else {
            panic!("expected Send");
        };
        assert!(attachments.is_empty());
        assert!(body.contains("[attachment omitted]"), "body was: {body}");
        assert!(
            !body.contains("photo.jpg"),
            "a blanket capability strip must not name the dropped file: {body}"
        );
    }

    #[tokio::test]
    async fn process_due_strips_attachments_when_policy_rejects_them_even_if_capability_allows() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().policies = vec![crate::config::Policy {
            name: "no-attachments-for-b".into(),
            r#match: crate::config::PolicyMatch {
                destination_protocol: vec!["mockb".into()],
            },
            rules: crate::config::PolicyRules {
                attachments: Some("reject".into()),
                ..Default::default()
            },
        }];
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", true); // capability says yes...

        let att = IpcAttachment {
            filename: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            data: b"bytes".to_vec(),
        };
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "look at this".into(),
            None,
            vec![att],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send {
            body, attachments, ..
        } = recv_send(&mut rx).await
        else {
            panic!("expected Send");
        };
        assert!(
            attachments.is_empty(),
            "...but policy says no, and policy wins"
        );
        assert!(body.contains("[attachment omitted]"), "body was: {body}");
    }

    #[tokio::test]
    async fn process_due_drops_attachment_over_the_policy_byte_cap_and_notes_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().policies = vec![crate::config::Policy {
            name: "small-attachments-for-b".into(),
            r#match: crate::config::PolicyMatch {
                destination_protocol: vec!["mockb".into()],
            },
            rules: crate::config::PolicyRules {
                max_attachment_bytes: Some(10),
                ..Default::default()
            },
        }];
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", true);

        let att = IpcAttachment {
            filename: "toobig.bin".into(),
            mime: "application/octet-stream".into(),
            data: vec![0u8; 20], // over the 10 B policy cap, under the ingress cap
        };
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "look at this".into(),
            None,
            vec![att],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send {
            body, attachments, ..
        } = recv_send(&mut rx).await
        else {
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
            filename: "gone.bin".into(),
            mime: "application/octet-stream".into(),
            data: b"will vanish".to_vec(),
        };
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "look at this".into(),
            None,
            vec![att],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        let env = d
            .store
            .lock()
            .unwrap()
            .get_message(del.message_id)
            .unwrap()
            .unwrap();
        let sha = env.attachments[0].sha256.clone();
        d.cas.remove(&sha).unwrap(); // simulate the blob having gone missing

        process_due(&d, del, now).await;

        let DaemonToPlugin::Send {
            body, attachments, ..
        } = recv_send(&mut rx).await
        else {
            panic!("expected Send");
        };
        assert!(attachments.is_empty());
        assert!(
            body.contains("[attachment gone.bin unavailable]"),
            "body was: {body}"
        );
    }

    // ---- transport-class policy (design §3, spec §17/§113.4): egress -----

    /// Constrained-transport route (Meshtastic/LoRa class, `max_payload_bytes:
    /// 237`, `allow_images: false`): an image attachment is demoted to a
    /// note -- reusing the same "strip from attachments, note it" shape as
    /// the capability/oversize drop paths -- and `TRANSPORT_DEMOTED` bumps.
    #[tokio::test]
    async fn process_due_constrained_transport_demotes_image_to_a_note_and_bumps_the_metric() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().transports.insert(
            "mockb".to_string(),
            crate::config::TransportEntry {
                class: relay_core::TransportClass::Meshtastic,
                max_payload_bytes: None,
                allow_images: None,
                allow_video: None,
                compress: None,
                batch_telemetry: None,
            },
        );
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", true);
        let before = metrics::TRANSPORT_DEMOTED.load(std::sync::atomic::Ordering::Relaxed);

        let att = IpcAttachment {
            filename: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            data: vec![7u8; 32],
        };
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hi".into(),
            None,
            vec![att],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send {
            body, attachments, ..
        } = recv_send(&mut rx).await
        else {
            panic!("expected Send");
        };
        assert!(
            attachments.is_empty(),
            "an image must never reach a transport that forbids images"
        );
        assert!(
            body.contains("[image 'photo.jpg' omitted — constrained transport]"),
            "body was: {body}"
        );
        let after = metrics::TRANSPORT_DEMOTED.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            after > before,
            "TRANSPORT_DEMOTED must increment on a media demotion"
        );
    }

    /// `allow_images`/`allow_video` are independent knobs (design §1): a
    /// route that only forbids video must demote JUST the video attachment
    /// and pass a co-attached, non-media file through untouched -- proving
    /// the demotion is selective, not a blanket strip.
    #[tokio::test]
    async fn process_due_transport_policy_demotes_video_but_keeps_a_non_media_attachment() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().transports.insert(
            "mockb".to_string(),
            crate::config::TransportEntry {
                class: relay_core::TransportClass::TerrestrialInternet,
                max_payload_bytes: None,
                allow_images: None,       // stays true (internet default)
                allow_video: Some(false), // explicitly forbidden for this route
                compress: None,
                batch_telemetry: None,
            },
        );
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", true);
        let before = metrics::TRANSPORT_DEMOTED.load(std::sync::atomic::Ordering::Relaxed);

        let clip = IpcAttachment {
            filename: "clip.mp4".into(),
            mime: "video/mp4".into(),
            data: vec![1u8; 32],
        };
        let doc = IpcAttachment {
            filename: "notes.pdf".into(),
            mime: "application/pdf".into(),
            data: vec![2u8; 32],
        };
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hi".into(),
            None,
            vec![clip, doc],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send {
            body, attachments, ..
        } = recv_send(&mut rx).await
        else {
            panic!("expected Send");
        };
        assert_eq!(
            attachments.len(),
            1,
            "only the video should be demoted, the PDF must pass through"
        );
        assert_eq!(attachments[0].filename, "notes.pdf");
        assert!(
            body.contains("[video 'clip.mp4' omitted — constrained transport]"),
            "body was: {body}"
        );
        let after = metrics::TRANSPORT_DEMOTED.load(std::sync::atomic::Ordering::Relaxed);
        assert!(after > before);
    }

    /// Effective payload cap = min(plugin cap, transport cap) (design §3):
    /// here the TRANSPORT cap (Meshtastic, 237 B) is the tighter of the two,
    /// so it must win over a much looser plugin-advertised cap.
    #[tokio::test]
    async fn process_due_constrained_transport_caps_payload_to_the_tighter_transport_limit() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().transports.insert(
            "mockb".to_string(),
            crate::config::TransportEntry {
                class: relay_core::TransportClass::Meshtastic, // 237 B cap
                max_payload_bytes: None,
                allow_images: None,
                allow_video: None,
                compress: None,
                batch_telemetry: None,
            },
        );
        let d = Arc::new(d);
        let (tx, mut rx) = mpsc::channel(8);
        d.plugins.lock().unwrap().insert(
            "mockb".to_string(),
            PluginHandle {
                tx,
                capabilities: Capabilities {
                    max_payload: Some(5000),
                    ..Capabilities::default()
                },
                connected: true,
            },
        );

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "x".repeat(1000),
            None,
            vec![],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(body.len() <= 237,
            "body must be capped to the tighter TRANSPORT limit, not the looser plugin one: {} bytes", body.len());
    }

    /// Same min() composition, opposite direction: the destination's
    /// TerrestrialInternet default is non-constraining (>= MAX_FRAME), so a
    /// tighter PLUGIN cap must still be the one that wins -- introducing
    /// transport policy must never loosen what a plugin's own Capabilities
    /// already enforced.
    #[tokio::test]
    async fn process_due_internet_transport_still_honors_a_tighter_plugin_cap() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path())); // no transports: block configured
        let (tx, mut rx) = mpsc::channel(8);
        d.plugins.lock().unwrap().insert(
            "mockb".to_string(),
            PluginHandle {
                tx,
                capabilities: Capabilities {
                    max_payload: Some(20),
                    ..Capabilities::default()
                },
                connected: true,
            },
        );

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "this body is much longer than twenty bytes".into(),
            None,
            vec![],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(body.len() <= 20,
            "the non-constraining internet transport cap must never override a tighter plugin cap: {} bytes", body.len());
    }

    /// Backward-compat regression guard (design §3, "Security/compat
    /// invariants"): a destination with NO `transports:` entry resolves to
    /// the TerrestrialInternet default (>= MAX_FRAME, media allowed), which
    /// must never newly constrain an existing route -- an image and an
    /// ordinary body must arrive exactly as they did before this feature.
    #[tokio::test]
    async fn process_due_internet_route_regression_image_and_body_pass_through_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let mut rx = register_plugin(&d, "mockb", true);

        let att = IpcAttachment {
            filename: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            data: vec![9u8; 64],
        };
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "ordinary message".into(),
            None,
            vec![att],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send {
            body, attachments, ..
        } = recv_send(&mut rx).await
        else {
            panic!("expected Send");
        };
        assert_eq!(
            attachments.len(),
            1,
            "the internet-default transport must never demote media: backward compat"
        );
        assert_eq!(attachments[0].filename, "photo.jpg");
        assert!(
            body.ends_with("ordinary message"),
            "body must be delivered untruncated: {body}"
        );
        assert!(
            !body.contains("omitted"),
            "no demotion note may appear on the non-constraining default: {body}"
        );
    }

    /// SEALED EXEMPTION (design §3, SPEC §113.4, CRITICAL): sealed egress
    /// (`process_due_fed_sealed`) never resolves `transport_policy` at all
    /// -- `process_due` dispatches `FED_PROTOCOL` deliveries to
    /// `process_due_fed`/`process_due_fed_sealed` BEFORE reaching the
    /// transport-policy code in the `Allow` arm, so the exemption holds
    /// structurally, not via an in-line guard. Proven here even under an
    /// ADVERSARIAL config -- a `transports:` entry deliberately keyed on
    /// `FED_PROTOCOL` ("fed") with a tiny cap and both media flags off --
    /// to show that entry is simply never consulted on a sealed route: the
    /// unsealed body/attachments at the far end are the ORIGINAL, untouched
    /// ones. (`TRANSPORT_DEMOTED` is a process-global shared with every
    /// other test in this binary's parallel run, so it is NOT asserted
    /// here — an exact before/after equality on it would be a false
    /// negative any time a concurrent demotion test in this same run
    /// legitimately bumps it; the body/attachments equality checks below
    /// are the load-bearing proof of the exemption.)
    #[tokio::test]
    async fn process_due_fed_sealed_egress_ignores_transport_policy_even_when_misconfigured_for_fed(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let recipient_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let recipient_pub = recipient_secret.public_key();
        let node_id = format!("rf:{}", "48".repeat(32));
        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.sealed_key = Some(hex::encode(recipient_pub.to_bytes()));
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        {
            let mut cfg = d.cfg.read().unwrap().clone();
            let route = cfg.routes.iter_mut().find(|r| r.name == "general").unwrap();
            route.security_mode = "sealed".to_string();
            cfg.transports.insert(
                FED_PROTOCOL.to_string(),
                crate::config::TransportEntry {
                    class: relay_core::TransportClass::Meshtastic,
                    max_payload_bytes: Some(64),
                    allow_images: Some(false),
                    allow_video: Some(false),
                    compress: None,
                    batch_telemetry: None,
                },
            );
            d.apply_config(cfg);
        }
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let long_body = "this body is deliberately much longer than the 64-byte transport cap \
                          configured above and must survive sealing completely whole";
        assert!(long_body.len() > 64, "fixture sanity check");
        let mut env = local_env("!ref", long_body);
        env.attachments = vec![AttachmentMeta {
            filename: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            size: 32,
            sha256: "deadbeef".repeat(8),
        }];
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        let (sealed, _) = unwrap_sealed_frame(rx.try_recv().unwrap());
        let opened = fed::seal::unseal(&sealed, &recipient_secret).unwrap();
        let decoded: Envelope = ciborium::from_reader(opened.as_slice()).unwrap();
        assert_eq!(
            decoded.body, long_body,
            "sealed egress must never truncate to a transport cap"
        );
        assert_eq!(
            decoded.attachments.len(),
            1,
            "sealed egress must never demote media to a note"
        );
        assert_eq!(decoded.attachments[0].filename, "photo.jpg");
    }

    #[test]
    fn load_attachments_drops_whatever_would_exceed_the_cumulative_frame_budget() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());

        let sha_a = d.cas.put(&[1u8; 10]).unwrap();
        let sha_b = d.cas.put(&[2u8; 10]).unwrap();
        let metas = vec![
            AttachmentMeta {
                filename: "a.bin".into(),
                mime: "application/octet-stream".into(),
                size: 10,
                sha256: sha_a,
            },
            AttachmentMeta {
                filename: "b.bin".into(),
                mime: "application/octet-stream".into(),
                size: 10,
                sha256: sha_b,
            },
        ];

        // budget only has room for the first attachment's 10 bytes.
        let tp =
            relay_core::TransportPolicy::for_class(relay_core::TransportClass::TerrestrialInternet);
        let (attachments, notes) = load_attachments(&d, &metas, None, 15, tp);

        assert_eq!(
            attachments.len(),
            1,
            "only the first fits under the frame budget"
        );
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
            filename: "a.bin".into(),
            mime: "application/octet-stream".into(),
            data: vec![0u8; 64], // oversize -> dropped
        };
        let b = IpcAttachment {
            filename: "b.bin".into(),
            mime: "application/octet-stream".into(),
            data: vec![1u8; 64], // different bytes, also oversize -> dropped
        };
        let same_created_at = Utc::now();

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            Some(same_created_at),
            vec![a],
            None,
        );
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            Some(same_created_at),
            vec![b],
            None,
        );

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert_eq!(
            counts,
            vec![("pending".to_string(), 2)],
            "differing dropped attachments must not dedup-collide: {counts:?}"
        );
    }

    #[test]
    fn inbound_over_per_route_queue_max_dead_letters_with_queue_full_reason() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relayfabric.db");
        let d = test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                per_route: crate::config::PerRoute { queue_max: 1 },
                ..Default::default()
            },
        );
        let before = metrics::QUEUE_REJECTED.load(std::sync::atomic::Ordering::Relaxed);

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "first".into(),
            None,
            vec![],
            None,
        );
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "second".into(),
            None,
            vec![],
            None,
        );

        let after = metrics::QUEUE_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        // QUEUE_REJECTED is a process-global counter shared by every test in
        // this binary's parallel run, so only a monotonic ">" check is safe
        // here (an exact +1 delta flakes when another test bumps the same
        // counter concurrently) -- the real, race-free proof that exactly
        // this test's rejection happened is the dead_letter row + QUEUE_FULL
        // reason asserted below, which only this test's own over-quota
        // delivery could have produced.
        assert!(
            after > before,
            "the second delivery must bump QUEUE_REJECTED"
        );

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert!(
            counts.contains(&("pending".to_string(), 1)),
            "counts was {counts:?}"
        );
        assert!(counts.contains(&("dead_letter".to_string(), 1)),
            "over-quota delivery must land dead_letter and stay visible in queue_counts: {counts:?}");

        // the dead-lettered row must carry QUEUE_FULL specifically, not just
        // any dead_letter reason.
        let raw = rusqlite::Connection::open(&db_path).unwrap();
        let reason: String = raw
            .query_row(
                "SELECT reason FROM deliveries WHERE state = 'dead_letter'",
                [],
                |r| r.get(0),
            )
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
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            Some(created_at),
            vec![],
            None,
        );

        let due = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(Utc::now(), 10).unwrap()
        };
        assert_eq!(due.len(), 1);
        let delivery_id = due[0].id;
        assert_eq!(due[0].route, "general");
        d.store
            .lock()
            .unwrap()
            .mark_attempting(delivery_id)
            .unwrap();

        let route_before = metrics::ROUTE_MESSAGES
            .lock()
            .unwrap()
            .get("general")
            .copied()
            .unwrap_or(0);
        let latency_count_before =
            metrics::DELIVERY_LATENCY_COUNT.load(std::sync::atomic::Ordering::Relaxed);
        let latency_sum_before =
            metrics::DELIVERY_LATENCY_MICROS_SUM.load(std::sync::atomic::Ordering::Relaxed);

        handle_result(&d, delivery_id, true, None);

        let route_after = metrics::ROUTE_MESSAGES
            .lock()
            .unwrap()
            .get("general")
            .copied()
            .unwrap_or(0);
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
        assert!(
            route_after > route_before,
            "a delivered message must bump its route's counter"
        );
        assert!(latency_count_after > latency_count_before);
        assert!(
            latency_sum_after < latency_sum_before + 60_000_000,
            "recorded latency must track received_at, not the lied-about \
             created_at: before={latency_sum_before} after={latency_sum_after}"
        );

        let state = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap()
            .state;
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
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            Some(epoch_zero),
            vec![],
            None,
        );

        let due = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(Utc::now(), 10).unwrap()
        };
        assert_eq!(due.len(), 1);
        let delivery_id = due[0].id;
        d.store
            .lock()
            .unwrap()
            .mark_attempting(delivery_id)
            .unwrap();

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
        assert!(
            latency_sum_after < latency_sum_before + ONE_HOUR_MICROS,
            "an epoch-0 created_at must not poison the latency metric: \
             before={latency_sum_before} after={latency_sum_after}"
        );
    }

    #[test]
    fn inbound_over_sender_per_minute_limit_drops_second_message_and_bumps_metric() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                per_sender: crate::config::PerSender {
                    messages_per_minute: 1,
                    bytes_per_hour: 0,
                },
                ..Default::default()
            },
        );
        let before = metrics::RATELIMITED.load(std::sync::atomic::Ordering::Relaxed);

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "first".into(),
            None,
            vec![],
            None,
        );
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "second".into(),
            None,
            vec![],
            None,
        );

        let after = metrics::RATELIMITED.load(std::sync::atomic::Ordering::Relaxed);
        // ">" not an exact +1 delta: RATELIMITED is a process-global counter
        // that other tests in this binary's parallel run (e.g. the identity-
        // link confirm/rate-limit ordering test) also legitimately bump —
        // a real increment from this test's own action still guarantees
        // after > before regardless of what else the counter is doing
        // concurrently, so this stays a precise, non-flaky assertion.
        assert!(
            after > before,
            "the second message from the same sender must bump RATELIMITED"
        );

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert_eq!(
            counts,
            vec![("pending".to_string(), 1)],
            "a rate-limited message must vanish entirely, not enqueue or dead-letter: {counts:?}"
        );
    }

    /// A different sender on the same plugin must not share the rate-limited
    /// sender's budget: the limiter key is (plugin, native_ref), not just
    /// plugin.
    #[test]
    fn sender_rate_limit_does_not_bleed_across_senders() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                per_sender: crate::config::PerSender {
                    messages_per_minute: 1,
                    bytes_per_hour: 0,
                },
                ..Default::default()
            },
        );

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "from a".into(),
            None,
            vec![],
            None,
        );
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!b".into(),
            "text".into(),
            "from b".into(),
            None,
            vec![],
            None,
        );

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert_eq!(
            counts,
            vec![("pending".to_string(), 2)],
            "a different sender must get its own budget: {counts:?}"
        );
    }

    #[test]
    fn inbound_drops_attachment_over_cas_budget_and_notes_it_but_message_still_flows() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                global: crate::config::GlobalLimits {
                    queue_max: 0,
                    cas_max_bytes: 5,
                },
                ..Default::default()
            },
        );

        let att = IpcAttachment {
            filename: "over-budget.bin".into(),
            mime: "application/octet-stream".into(),
            data: vec![0u8; 20], // over the 5-byte CAS budget, under the ingress size cap
        };
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            None,
            vec![att],
            None,
        );

        let store = d.store.lock().unwrap();
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(
            due.len(),
            1,
            "message must still flow despite the dropped attachment"
        );
        let env = store.get_message(due[0].message_id).unwrap().unwrap();
        assert!(
            env.attachments.is_empty(),
            "the over-budget attachment must not get a meta"
        );
        assert!(
            env.body
                .contains("[dropped over-budget.bin: cas budget exceeded]"),
            "body was: {}",
            env.body
        );
    }

    #[tokio::test]
    async fn transport_budget_defers_the_send_over_it_and_emergency_bypasses() {
        let dir = tempfile::tempdir().unwrap();
        let mut budgets = std::collections::BTreeMap::new();
        budgets.insert(
            "mockb".to_string(),
            crate::config::Budget {
                messages_per_minute: 2,
            },
        );
        let d = Arc::new(test_daemon_with_budgets(dir.path(), budgets));
        let mut rx = register_plugin(&d, "mockb", false);

        // three normal-priority messages queued for mockb, a 2/minute budget.
        for body in ["one", "two", "three"] {
            handle_inbound(
                &d,
                "mocka",
                "chan".into(),
                "!a".into(),
                "text".into(),
                body.into(),
                None,
                vec![],
                None,
            );
        }
        let now = Utc::now();
        let dues = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(now, 10).unwrap()
        };
        assert_eq!(dues.len(), 3);
        assert!(
            dues.iter().all(|d| d.priority == 2),
            "these are all normal priority"
        );
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
        assert!(
            after > before,
            "only the third send within the minute must be deferred"
        );

        // the first two budget slots went out as real Sends...
        recv_send(&mut rx).await;
        recv_send(&mut rx).await;
        // ...and nothing else: the third never called try_send at all.
        assert!(
            matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "the budget-deferred delivery must not have produced a Send"
        );

        // the deferred delivery (whichever of the three it was) must still be
        // 'pending' with its next_attempt pushed ~10s out, not immediately
        // due again and not dead-lettered.
        let deferred_id = ids[2];
        {
            let store = d.store.lock().unwrap();
            assert!(
                store
                    .due_deliveries(now + CDuration::seconds(9), 10)
                    .unwrap()
                    .iter()
                    .all(|d| d.id != deferred_id),
                "must not be due again before the ~10s budget backoff elapses"
            );
            assert!(
                store
                    .due_deliveries(now + CDuration::seconds(11), 10)
                    .unwrap()
                    .iter()
                    .any(|d| d.id == deferred_id),
                "must be due again once the ~10s budget backoff has elapsed"
            );
        }

        // an emergency send for the same over-budget destination must
        // bypass the check entirely and go out immediately.
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "urgent".into(),
            None,
            vec![],
            Some("emergency".into()),
        );
        let now2 = Utc::now();
        let emergency_del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now2, 10)
                .unwrap()
                .into_iter()
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

        assert!(
            err.contains("mocka"),
            "err must name the direct-capable plugin: {err}"
        );
        assert!(
            !err.contains("!target-secret"),
            "err must never leak the target ref: {err}"
        );
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
        assert!(
            err.contains("mocka"),
            "err must still name the direct-capable plugins that ARE connected: {err}"
        );
    }

    #[test]
    fn initiate_link_error_path_creates_no_challenge_or_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let requester: Endpoint = "mocka:!req".parse().unwrap();
        let target: Endpoint = "mockb:!target".parse().unwrap();
        assert!(initiate_link(&d, requester, target, "Jascha").is_err());

        let due = d
            .store
            .lock()
            .unwrap()
            .due_deliveries(Utc::now(), 10)
            .unwrap();
        assert!(
            due.iter().all(|de| de.route != IDENTITY_ROUTE),
            "a rejected initiate_link must not enqueue an @identity delivery"
        );
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
            store
                .due_deliveries(now, 10)
                .unwrap()
                .into_iter()
                .find(|de| de.route == IDENTITY_ROUTE)
                .expect("challenge delivery must be queued on the @identity route")
        };
        assert_eq!(del.destination.protocol, "mockb");
        assert_eq!(
            del.destination.endpoint, "+15559876543",
            "the target's native_ref must be stored in dest_endpoint"
        );

        process_due(&d, del, now).await;
        let DaemonToPlugin::SendDirect {
            native_ref, body, ..
        } = recv_send(&mut rx).await
        else {
            panic!("expected SendDirect");
        };
        assert_eq!(native_ref, "+15559876543");
        assert!(
            body.contains("RelayFabric verification code:"),
            "body was: {body}"
        );
        assert!(
            !body.contains("+15551234567"),
            "the requester's full ref must never appear in the challenge body: {body}"
        );

        let code = body
            .split("code: ")
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        let found = d
            .store
            .lock()
            .unwrap()
            .find_active_challenge("mockb", "+15559876543", code, now)
            .unwrap();
        assert!(
            found.is_some(),
            "the code in the SendDirect body must match the stored challenge"
        );
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
        let d = test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                global: crate::config::GlobalLimits {
                    queue_max: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let _rx = register_direct_plugin(&d, "mockb");

        // fill the global queue to its cap of 1 with an ordinary routed message
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
        assert_eq!(
            d.store.lock().unwrap().queue_counts().unwrap(),
            vec![("pending".to_string(), 1)]
        );

        let requester: Endpoint = "mocka:!req".parse().unwrap();
        let target: Endpoint = "mockb:!target".parse().unwrap();
        let err = initiate_link(&d, requester, target, "Jascha").unwrap_err();
        assert_eq!(err, "queue full");

        // the @identity delivery landed dead_letter with QUEUE_FULL, not
        // silently dropped (same visibility contract as the per-route case).
        let raw = rusqlite::Connection::open(&db_path).unwrap();
        let reason: String = raw
            .query_row(
                "SELECT reason FROM deliveries WHERE route = '@identity' AND state = 'dead_letter'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reason, "QUEUE_FULL");
    }

    /// The same cap applies to `confirm_link`'s best-effort notices, but a
    /// queue-full rejection there must not unwind the link that was just
    /// verified — the link itself has nothing to do with delivery capacity.
    #[test]
    fn confirm_link_over_global_queue_cap_dead_letters_notices_but_still_confirms_link() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                global: crate::config::GlobalLimits {
                    queue_max: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let now = Utc::now();
        seed_challenge(
            &d,
            ("mockb", "!target"),
            ("mocka", "!req"),
            "424242",
            "Jascha",
            now,
            15,
        );

        // fill the global queue to its cap of 1
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

        handle_inbound(
            &d,
            "mockb",
            "chan".into(),
            "!target".into(),
            "text".into(),
            "424242".into(),
            None,
            vec![],
            None,
        );

        let link = d
            .store
            .lock()
            .unwrap()
            .link_for_identity("mockb", "!target")
            .unwrap();
        assert!(
            link.is_some(),
            "the link must still be confirmed even when both notices are queue-capped"
        );

        let counts = d.store.lock().unwrap().queue_counts().unwrap();
        assert!(
            counts.contains(&("dead_letter".to_string(), 2)),
            "both best-effort confirmation notices must dead-letter with QUEUE_FULL: {counts:?}"
        );
    }

    // ---- identity linking: confirm interception ----------------------------

    fn seed_challenge(
        d: &Daemon,
        target: (&str, &str),
        requester: (&str, &str),
        code: &str,
        display_name: &str,
        now: DateTime<Utc>,
        ttl_minutes: i64,
    ) -> i64 {
        d.store
            .lock()
            .unwrap()
            .create_challenge(
                code,
                target.0,
                target.1,
                requester.0,
                requester.1,
                display_name,
                now,
                now + CDuration::minutes(ttl_minutes),
            )
            .unwrap()
    }

    #[test]
    fn confirm_right_sender_and_code_creates_link_and_does_not_route() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();
        seed_challenge(
            &d,
            ("mockb", "!target"),
            ("mocka", "!req"),
            "424242",
            "Jascha",
            now,
            15,
        );

        // LINKS_VERIFIED is a process-global counter shared by every test in
        // this binary's parallel run, so only a monotonic ">" check is safe
        // here (an exact +1 delta would be racy against any other test
        // touching the same counter concurrently) — the real, race-free
        // proof that exactly one confirmation happened is the due_deliveries
        // count assertion below (confirm_link enqueues a fresh, non-dedup'd
        // row per call, so a double-fire would show up as 4 rows, not 2).
        let before = metrics::LINKS_VERIFIED.load(std::sync::atomic::Ordering::Relaxed);
        handle_inbound(
            &d,
            "mockb",
            "chan".into(),
            "!target".into(),
            "text".into(),
            "424242".into(),
            None,
            vec![],
            None,
        );
        let after = metrics::LINKS_VERIFIED.load(std::sync::atomic::Ordering::Relaxed);
        assert!(after > before, "LINKS_VERIFIED must bump");

        let link = d
            .store
            .lock()
            .unwrap()
            .link_for_identity("mockb", "!target")
            .unwrap();
        assert_eq!(link.unwrap().display_name, "Jascha");

        // Not routed: the "general" route (mockb:chan -> mocka:chan) would
        // otherwise have produced a delivery for this exact inbound. Only
        // the two best-effort @identity confirmation notices are queued.
        let due = d
            .store
            .lock()
            .unwrap()
            .due_deliveries(Utc::now(), 10)
            .unwrap();
        assert!(
            due.iter().all(|de| de.route == IDENTITY_ROUTE),
            "the confirming message itself must never be routed: {due:?}"
        );
        assert_eq!(due.len(), 2, "one confirmation notice per party: {due:?}");
    }

    #[test]
    fn confirm_wrong_sender_does_not_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();
        seed_challenge(
            &d,
            ("mockb", "!target"),
            ("mocka", "!req"),
            "424242",
            "Jascha",
            now,
            15,
        );

        // same protocol, same code, but a DIFFERENT native ref replying.
        handle_inbound(
            &d,
            "mockb",
            "chan".into(),
            "!someone-else".into(),
            "text".into(),
            "424242".into(),
            None,
            vec![],
            None,
        );

        assert!(
            d.store
                .lock()
                .unwrap()
                .link_for_identity("mockb", "!target")
                .unwrap()
                .is_none(),
            "a third party sending the code must not confirm the link"
        );
        assert!(
            d.store
                .lock()
                .unwrap()
                .find_active_challenge("mockb", "!target", "424242", Utc::now())
                .unwrap()
                .is_some(),
            "the real target's challenge must remain active"
        );
    }

    #[test]
    fn confirm_wrong_code_does_not_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();
        seed_challenge(
            &d,
            ("mockb", "!target"),
            ("mocka", "!req"),
            "424242",
            "Jascha",
            now,
            15,
        );

        handle_inbound(
            &d,
            "mockb",
            "chan".into(),
            "!target".into(),
            "text".into(),
            "999999".into(),
            None,
            vec![],
            None,
        );

        assert!(d
            .store
            .lock()
            .unwrap()
            .link_for_identity("mockb", "!target")
            .unwrap()
            .is_none());
        assert!(
            d.store
                .lock()
                .unwrap()
                .find_active_challenge("mockb", "!target", "424242", Utc::now())
                .unwrap()
                .is_some(),
            "the real code must remain valid after a wrong-code attempt"
        );
    }

    #[test]
    fn confirm_expired_challenge_does_not_confirm() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let past = Utc::now() - CDuration::minutes(30);
        // expires_at = past + 15min, still in the past relative to "now" below.
        seed_challenge(
            &d,
            ("mockb", "!target"),
            ("mocka", "!req"),
            "424242",
            "Jascha",
            past,
            15,
        );

        handle_inbound(
            &d,
            "mockb",
            "chan".into(),
            "!target".into(),
            "text".into(),
            "424242".into(),
            None,
            vec![],
            None,
        );

        assert!(
            d.store
                .lock()
                .unwrap()
                .link_for_identity("mockb", "!target")
                .unwrap()
                .is_none(),
            "an expired challenge must not confirm"
        );
    }

    #[test]
    fn confirm_non_matching_six_digit_body_routes_normally() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        // no active challenge at all for this sender.
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "123456".into(),
            None,
            vec![],
            None,
        );

        let due = d
            .store
            .lock()
            .unwrap()
            .due_deliveries(Utc::now(), 10)
            .unwrap();
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
        seed_challenge(
            &d,
            ("mocka", "!a"),
            ("mockb", "!req"),
            "424242",
            "Jascha",
            now,
            15,
        );

        for body in ["42424", "4242422", "42424a", "abcdef", " 424242a"] {
            handle_inbound(
                &d,
                "mocka",
                "chan".into(),
                "!a".into(),
                "text".into(),
                body.into(),
                None,
                vec![],
                None,
            );
            assert!(
                d.store
                    .lock()
                    .unwrap()
                    .find_active_challenge("mocka", "!a", "424242", Utc::now())
                    .unwrap()
                    .is_some(),
                "body {body:?} must never consume the active challenge"
            );
        }
        assert!(d
            .store
            .lock()
            .unwrap()
            .link_for_identity("mocka", "!a")
            .unwrap()
            .is_none());
    }

    #[test]
    fn confirm_interception_is_gated_by_the_sender_rate_limit() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                per_sender: crate::config::PerSender {
                    messages_per_minute: 1,
                    bytes_per_hour: 0,
                },
                ..Default::default()
            },
        );
        let now = Utc::now();
        seed_challenge(
            &d,
            ("mocka", "!a"),
            ("mockb", "!req"),
            "424242",
            "Jascha",
            now,
            15,
        );

        // first message from "!a" consumes the 1/minute budget.
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

        // the confirming code, from the SAME sender, right after: must be
        // rate-limited before it ever reaches the confirm check. RATELIMITED
        // is a process-global counter also touched by other tests running
        // concurrently in this binary, so the real, race-free proof here is
        // the challenge-still-active assertion below: if the confirm check
        // had run for this second message (i.e. the rate limiter did NOT
        // gate it first), the challenge would have been consumed.
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "424242".into(),
            None,
            vec![],
            None,
        );

        assert!(
            d.store
                .lock()
                .unwrap()
                .find_active_challenge("mocka", "!a", "424242", Utc::now())
                .unwrap()
                .is_some(),
            "a rate-limited confirm attempt must not consume the challenge"
        );
    }

    #[test]
    fn confirm_interception_is_gated_by_dedup_a_replayed_confirm_only_confirms_once() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();
        seed_challenge(
            &d,
            ("mocka", "!a"),
            ("mockb", "!req"),
            "424242",
            "Jascha",
            now,
            15,
        );

        for _ in 0..2 {
            // identical args each call -> identical dedup key.
            handle_inbound(
                &d,
                "mocka",
                "chan".into(),
                "!a".into(),
                "text".into(),
                "424242".into(),
                None,
                vec![],
                None,
            );
        }

        // confirm_link's insert_delivery calls are NOT dedup'd/idempotent
        // (unlike insert_link's ON CONFLICT replace) — a second real
        // confirm_link run would double the confirmation notices to 4. This
        // is a race-free, per-test-isolated proxy for "confirmed exactly
        // once" (LINKS_VERIFIED is a process-global counter shared with
        // other concurrently-running tests, so it isn't a safe signal here).
        let due = d
            .store
            .lock()
            .unwrap()
            .due_deliveries(Utc::now(), 10)
            .unwrap();
        assert_eq!(due.iter().filter(|de| de.route == IDENTITY_ROUTE).count(), 2,
            "an exact-duplicate replay of the confirming message must be swallowed by dedup, not re-confirmed");
    }

    #[test]
    fn one_link_per_identity_replace_covers_both_the_target_and_requester_sides() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let now = Utc::now();

        // target already linked to some old partner...
        d.store
            .lock()
            .unwrap()
            .insert_link("mocka", "!a", "mockc", "!old-a", "Old A", now)
            .unwrap();
        // ...and the requester ALSO already linked to some other old partner.
        d.store
            .lock()
            .unwrap()
            .insert_link("mockb", "!req", "mockd", "!old-req", "Old Req", now)
            .unwrap();

        seed_challenge(
            &d,
            ("mocka", "!a"),
            ("mockb", "!req"),
            "111222",
            "Fresh",
            now,
            15,
        );
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "111222".into(),
            None,
            vec![],
            None,
        );

        let store = d.store.lock().unwrap();
        assert!(
            store
                .link_for_identity("mockc", "!old-a")
                .unwrap()
                .is_none(),
            "the target's old partner must be unlinked (replace, not stack)"
        );
        assert!(
            store
                .link_for_identity("mockd", "!old-req")
                .unwrap()
                .is_none(),
            "the requester's old partner must be unlinked (replace, not stack)"
        );
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
    async fn process_due_identity_dead_letters_promptly_when_plugin_connected_but_not_direct_capable(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let _rx = register_plugin(&d, "mockb", false); // connected, but NOT direct-capable

        let target: Endpoint = "mockb:!target".parse().unwrap();
        let now = Utc::now();
        let env = Envelope::new(
            "identity:system".parse().unwrap(),
            Sender {
                native_ref: "@identity".into(),
            },
            "notice".into(),
            "code".into(),
            now,
            now + CDuration::minutes(15),
            8,
        );
        d.store.lock().unwrap().insert_message(&env).unwrap();
        let del_id = d
            .store
            .lock()
            .unwrap()
            .insert_delivery(env.id, IDENTITY_ROUTE, &target, now, env.expires_at, 2)
            .unwrap();
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
            "identity:system".parse().unwrap(),
            Sender {
                native_ref: "@identity".into(),
            },
            "notice".into(),
            "code".into(),
            now,
            now + CDuration::minutes(15),
            8,
        );
        d.store.lock().unwrap().insert_message(&env).unwrap();
        let del_id = d
            .store
            .lock()
            .unwrap()
            .insert_delivery(env.id, IDENTITY_ROUTE, &target, now, env.expires_at, 2)
            .unwrap();
        let del = d.store.lock().unwrap().deliveries_for_id(del_id).unwrap();

        process_due(&d, del, now).await;

        let after = d.store.lock().unwrap().deliveries_for_id(del_id).unwrap();
        assert_eq!(after.state, "pending",
            "a disconnected plugin may still reconnect, so this must keep retrying, not dead-letter");
        assert!(
            after.next_attempt > now,
            "retry must be scheduled in the future"
        );
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
    async fn confirm_link_dead_letters_requester_notice_when_requester_plugin_lacks_direct_messages(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let mut target_rx = register_direct_plugin(&d, "mockb"); // target: direct-capable
        let _requester_rx = register_plugin(&d, "mocka", false); // requester: connected, NOT direct-capable

        let now = Utc::now();
        seed_challenge(
            &d,
            ("mockb", "!target"),
            ("mocka", "!req"),
            "424242",
            "Jascha",
            now,
            15,
        );

        handle_inbound(
            &d,
            "mockb",
            "chan".into(),
            "!target".into(),
            "text".into(),
            "424242".into(),
            None,
            vec![],
            None,
        );

        // link exists regardless of either notice's fate
        assert!(
            d.store
                .lock()
                .unwrap()
                .link_for_identity("mockb", "!target")
                .unwrap()
                .is_some(),
            "the link must be confirmed even though the requester's plugin can't take the notice"
        );

        let due = d
            .store
            .lock()
            .unwrap()
            .due_deliveries(Utc::now(), 10)
            .unwrap();
        assert_eq!(due.len(), 2, "one confirmation notice per party: {due:?}");
        let target_del = due
            .iter()
            .find(|de| de.destination.protocol == "mockb")
            .unwrap()
            .clone();
        let requester_del = due
            .iter()
            .find(|de| de.destination.protocol == "mocka")
            .unwrap()
            .clone();

        process_due(&d, requester_del.clone(), now).await;
        let after_requester = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(requester_del.id)
            .unwrap();
        assert_eq!(
            after_requester.state, "dead_letter",
            "the requester-side notice must dead-letter promptly, not retry for 24h"
        );
        assert_eq!(
            after_requester.reason.as_deref(),
            Some("NOT_DIRECT_CAPABLE")
        );

        process_due(&d, target_del, now).await;
        let DaemonToPlugin::SendDirect { native_ref, .. } = recv_send(&mut target_rx).await else {
            panic!("expected SendDirect");
        };
        assert_eq!(
            native_ref, "!target",
            "the target-side notice must still be attempted"
        );
    }

    // ---- identity linking: rendering ---------------------------------------

    #[tokio::test]
    async fn process_due_renders_display_name_when_route_is_linked_and_a_verified_link_exists() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().routes[0].identity_mode = "linked".to_string();
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false);

        d.store
            .lock()
            .unwrap()
            .insert_link("mocka", "!a", "signal", "+1", "Jascha", Utc::now())
            .unwrap();

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
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(body.starts_with("[Jascha]\n"), "body was: {body}");
    }

    #[tokio::test]
    async fn process_due_never_renders_display_name_on_a_route_that_has_not_opted_into_linked_mode()
    {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path())); // default identity_mode: "pseudonymous"
        let mut rx = register_plugin(&d, "mockb", false);

        d.store
            .lock()
            .unwrap()
            .insert_link("mocka", "!a", "signal", "+1", "Jascha", Utc::now())
            .unwrap();

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
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
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
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(
            !body.contains("Jascha"),
            "with no verified link, linked mode must fall back to the alias: {body}"
        );
    }

    #[tokio::test]
    async fn unlink_reverts_rendering_to_pseudonym_on_the_next_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().routes[0].identity_mode = "linked".to_string();
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false);

        let link_id = d
            .store
            .lock()
            .unwrap()
            .insert_link("mocka", "!a", "signal", "+1", "Jascha", Utc::now())
            .unwrap();

        // first message: linked, renders display_name.
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "first".into(),
            None,
            vec![],
            None,
        );
        let now = Utc::now();
        let del1 = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
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
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "second".into(),
            None,
            vec![],
            None,
        );
        let now2 = Utc::now();
        let del2 = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now2, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del2, now2).await;
        let DaemonToPlugin::Send { body: body2, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(
            !body2.contains("Jascha"),
            "after unlink, rendering must revert to the pseudonym: {body2}"
        );
    }

    // ---- design §4: route render knobs (tag: none, max_chars) -------------

    #[tokio::test]
    async fn render_tag_none_suppresses_the_alias_prefix_on_a_pseudonymous_route() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path()); // default identity_mode: "pseudonymous"
        d.cfg.write().unwrap().routes[0].render.tag = "none".to_string();
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false);

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
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert_eq!(
            body, "hello",
            "tag: none must omit the [alias]\\n prefix entirely: {body}"
        );
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

        d.store
            .lock()
            .unwrap()
            .insert_link("mocka", "!a", "signal", "+1", "Jascha", Utc::now())
            .unwrap();

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
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert_eq!(
            body, "hello",
            "tag: none must suppress the linked display_name too, not just the pseudonym: {body}"
        );
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

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "this body is much longer than twenty characters".into(),
            None,
            vec![],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(
            body.starts_with('['),
            "tag prefix must still be present: {body}"
        );
        let after_tag = body
            .split_once('\n')
            .expect("tag prefix followed by a newline")
            .1;
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

        d.store
            .lock()
            .unwrap()
            .insert_link(
                "mocka",
                "!a",
                "signal",
                "+1",
                "AVeryLongDisplayNameIndeed",
                Utc::now(),
            )
            .unwrap();

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "this body is much longer than sixteen characters".into(),
            None,
            vec![],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(
            body.starts_with("[AVeryLongDisplayNameIndeed]\n"),
            "a long linked display_name must never be truncated by render.max_chars: {body}"
        );
        assert!(
            body.contains('…'),
            "the body must still be truncated: {body}"
        );
    }

    /// design decision (fix round 1, point 4): attachment-strip notes are
    /// appended AFTER `max_chars` truncates the body, so notes are NOT
    /// counted toward the `max_chars` budget -- a note explaining a dropped
    /// attachment must reliably reach the recipient even when the body
    /// itself is truncated to make room.
    #[tokio::test]
    async fn render_max_chars_truncates_body_before_notes_are_appended_notes_not_counted_toward_max_chars(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().routes[0].render.max_chars = 16;
        let d = Arc::new(d);
        let mut rx = register_plugin(&d, "mockb", false); // no attachments capability

        let att = IpcAttachment {
            filename: "photo.jpg".into(),
            mime: "image/jpeg".into(),
            data: b"bytes".to_vec(),
        };
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "this body is much longer than sixteen characters".into(),
            None,
            vec![att],
            None,
        );
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };
        process_due(&d, del, now).await;

        let DaemonToPlugin::Send { body, .. } = recv_send(&mut rx).await else {
            panic!("expected Send");
        };
        assert!(
            body.contains("[attachment omitted]"),
            "the note must survive even though the body was truncated to make room: {body}"
        );
        // The truncated-body portion (everything after the tag, up through
        // the truncation ellipsis) is exactly 16 chars -- the note text
        // itself is not counted toward that budget.
        let note_start = body.find("\n[attachment omitted]").expect("note present");
        let body_only = &body[body.find('\n').unwrap() + 1..note_start];
        assert_eq!(
            body_only.chars().count(),
            16,
            "max_chars must bound the body alone, not the body+note total: {body}"
        );
    }

    // ---- apply_config (design §1: hot-reloadable config behind RwLock) ----

    #[test]
    fn apply_config_unchanged_config_has_no_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let new_cfg = d.cfg.read().unwrap().clone();
        let outcome = d.apply_config(new_cfg);
        assert!(
            outcome.restart_required.is_empty(),
            "outcome was: {outcome:?}"
        );
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
        new_cfg.plugins.insert(
            "mockc".to_string(),
            crate::config::PluginConfig {
                enabled: true,
                command: None,
                config: serde_yaml::Value::Null,
                peer_uid: None,
            },
        );
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

    fn test_federation_config() -> crate::config::FederationConfig {
        crate::config::FederationConfig {
            listen: None,
            accept_from: "verified".into(),
            max_hops: 4,
            max_ttl_secs: 86_400,
            identity_exposure: "pseudonymous".into(),
            ingress_routes: vec![],
            peers: vec![],
            trusted: vec![],
            blocked: vec![],
        }
    }

    /// Design §3/§4, cycle F: `test_daemon` starts with `federation: None`
    /// (no block at all) -- adding one is exactly as restart-required as any
    /// other federation-block change, under the same `"daemon"` pseudo-entry
    /// `node.*` changes use.
    #[test]
    fn apply_config_federation_block_added_is_restart_required_under_daemon_pseudo_entry() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.federation = Some(test_federation_config());
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required, vec!["daemon".to_string()]);
    }

    /// A field-level edit inside an already-present federation block (not
    /// just adding/removing the block itself) must also trip the `"daemon"`
    /// restart entry -- design §3/§4's "ANY change to the federation block"
    /// this cycle (live fed reconfig deferred).
    #[test]
    fn apply_config_federation_field_change_is_restart_required_under_daemon_pseudo_entry() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().federation = Some(test_federation_config());

        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.federation.as_mut().unwrap().max_hops = 6;
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required, vec!["daemon".to_string()]);
    }

    /// Re-applying an UNCHANGED federation block must not report a restart
    /// -- the diff is a real equality check, not "federation present at
    /// all ⇒ always restart".
    #[test]
    fn apply_config_federation_block_unchanged_has_no_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().federation = Some(test_federation_config());

        let new_cfg = d.cfg.read().unwrap().clone();
        let outcome = d.apply_config(new_cfg);
        assert!(
            outcome.restart_required.is_empty(),
            "outcome was: {outcome:?}"
        );
    }

    /// Design §1/§4, cycle G: `discovery` gets the same `"daemon"`
    /// restart-required treatment as `federation` -- `test_daemon` starts
    /// with `discovery: DiscoveryConfig::default()` (`mode: "disabled"`),
    /// so turning it on is a real diff.
    #[test]
    fn apply_config_discovery_mode_change_is_restart_required_under_daemon_pseudo_entry() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.discovery.mode = "federation".to_string();
        let outcome = d.apply_config(new_cfg);
        assert_eq!(outcome.restart_required, vec!["daemon".to_string()]);
    }

    /// Re-applying an UNCHANGED discovery block must not report a restart.
    #[test]
    fn apply_config_discovery_unchanged_has_no_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().discovery.mode = "federation".to_string();

        let new_cfg = d.cfg.read().unwrap().clone();
        let outcome = d.apply_config(new_cfg);
        assert!(
            outcome.restart_required.is_empty(),
            "outcome was: {outcome:?}"
        );
    }

    /// Design §3, SPEC §113.1/§113.2, cycle H: a route's `security_mode`
    /// takes effect live -- same posture as `identity_mode`/`render` above
    /// it (`apply_config`'s restart-required diff never inspects `routes`
    /// at all; every per-message read goes through `cfg.read()`/
    /// `route_cfg`, so the next attempt already sees the new value).
    #[test]
    fn apply_config_security_mode_change_is_live_no_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path()); // default security_mode: "gateway"
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.routes[0].security_mode = "sealed".to_string();
        let outcome = d.apply_config(new_cfg);
        assert!(
            outcome.restart_required.is_empty(),
            "outcome was: {outcome:?}"
        );
    }

    /// Design §2 (transport-class cycle, task 2): a `transports:`-only
    /// config change is live -- same posture as `security_mode`/`render`/
    /// `identity_mode`/the `privacy` floor above (`apply_config`'s
    /// restart-required diff never inspects `transports` at all, so the
    /// swap alone makes it live). Asserts BOTH halves: no `"daemon"` entry
    /// in `restart_required`, AND `Config::transport_policy` reflects the
    /// new config immediately after `apply_config` returns -- not just
    /// "no restart reported" but "actually took effect".
    #[test]
    fn apply_config_transports_change_is_live_no_restart_required_and_takes_effect() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path()); // "mocka" plugin, default: no transports entry
        let before = d.cfg_snapshot(|c| c.transport_policy("mocka"));
        assert_eq!(
            before,
            relay_core::TransportPolicy::for_class(relay_core::TransportClass::TerrestrialInternet),
            "default (no transports entry) should be the non-constraining internet anchor"
        );

        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.transports.insert(
            "mocka".to_string(),
            crate::config::TransportEntry {
                class: relay_core::TransportClass::SatelliteInternet,
                max_payload_bytes: Some(32768),
                allow_images: Some(false),
                allow_video: None,
                compress: None,
                batch_telemetry: None,
            },
        );
        let outcome = d.apply_config(new_cfg);
        assert!(
            outcome.restart_required.is_empty(),
            "outcome was: {outcome:?}"
        );

        let after = d.cfg_snapshot(|c| c.transport_policy("mocka"));
        assert_eq!(after.max_payload_bytes, 32768);
        assert!(!after.allow_images);
    }

    /// Design §3, SPEC §113.2, cycle H: unlike `federation`/`discovery`
    /// (both `"daemon"` restart-required on ANY change), the node-level
    /// `privacy` floor is deliberately NOT part of the restart diff at all
    /// (see `Config::privacy`'s doc comment) -- a floor edit takes effect
    /// live, the same as `routes`/`render`/`identity_mode`.
    #[test]
    fn apply_config_privacy_floor_change_is_live_no_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path()); // default privacy: no floor
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.privacy.minimum_security = "sealed".to_string();
        new_cfg.privacy.allow_gateway_decryption = false;
        new_cfg.privacy.allow_protocol_downgrade = false;
        let outcome = d.apply_config(new_cfg);
        assert!(
            outcome.restart_required.is_empty(),
            "outcome was: {outcome:?}"
        );
    }

    #[test]
    fn apply_config_multiple_changes_are_all_reported_sorted_and_deduped() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.node.public = !new_cfg.node.public;
        new_cfg.plugins.get_mut("mockb").unwrap().enabled = false;
        new_cfg.plugins.insert(
            "aaa-new".to_string(),
            crate::config::PluginConfig {
                enabled: true,
                command: None,
                config: serde_yaml::Value::Null,
                peer_uid: None,
            },
        );
        let outcome = d.apply_config(new_cfg);
        assert_eq!(
            outcome.restart_required,
            vec![
                "aaa-new".to_string(),
                "daemon".to_string(),
                "mockb".to_string()
            ]
        );
    }

    /// Live-effect half of the matrix: a route added via `apply_config` must
    /// route the very next inbound message with no restart in between.
    #[test]
    fn apply_config_route_added_is_live_for_the_next_message_no_restart() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());

        // "newchan" isn't wired into any route in the base config: dropped.
        handle_inbound(
            &d,
            "mocka",
            "newchan".into(),
            "!a".into(),
            "text".into(),
            "before".into(),
            None,
            vec![],
            None,
        );
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(), vec![]);

        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.routes.push(crate::config::RouteConfig {
            name: "extra".into(),
            sources: vec!["mocka:newchan".parse().unwrap()],
            destinations: vec!["mockb:chan".parse().unwrap()],
            identity_mode: "pseudonymous".into(),
            render: crate::config::RenderConfig::default(),
            security_mode: "gateway".into(),
            allow_gateway_decryption: None,
        });
        let outcome = d.apply_config(new_cfg);
        assert!(
            outcome.restart_required.is_empty(),
            "a route addition alone must never require a restart: {outcome:?}"
        );

        handle_inbound(
            &d,
            "mocka",
            "newchan".into(),
            "!a".into(),
            "text".into(),
            "after".into(),
            None,
            vec![],
            None,
        );
        assert_eq!(
            d.store.lock().unwrap().queue_counts().unwrap(),
            vec![("pending".to_string(), 1)],
            "the new route must be live without a restart"
        );
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

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "one".into(),
            None,
            vec![],
            None,
        );
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "two".into(),
            None,
            vec![],
            None,
        );

        assert_eq!(
            d.store.lock().unwrap().queue_counts().unwrap(),
            vec![("pending".to_string(), 1)],
            "the second message from the same sender must be rate-limited \
             immediately after tightening, no restart involved"
        );
    }

    /// `apply_config` must store the incoming config's `raw_yaml` (Task 3's
    /// PUT will have set it via `config::load_from_str` before calling this)
    /// so a subsequent `GET /v1/config` (Task 2) serves the newly-applied
    /// text, not the config the daemon booted with.
    #[test]
    fn apply_config_stores_the_new_configs_raw_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        assert_eq!(
            d.cfg.read().unwrap().raw_yaml,
            "",
            "test_daemon's Config has no raw_yaml"
        );

        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.raw_yaml = "node:\n  name: applied\n".to_string();
        d.apply_config(new_cfg);

        assert_eq!(d.cfg.read().unwrap().raw_yaml, "node:\n  name: applied\n");
    }

    /// Carried fix (Task 1 review, Minor -> Task 3): the restart-required
    /// diff compares `cfg.plugins[_].config` (always resolved) against
    /// `new.plugins[_].config`, so `new` MUST come from `config::load_from_str`
    /// (which resolves secrets before returning) rather than a bare parse --
    /// otherwise a plugin config block with a `${env:...}` reference would
    /// always look "changed" (resolved value vs. still-a-reference-string),
    /// even when the env var resolves to the exact same value both times.
    /// Both the daemon's initial config and `new` here go through
    /// `load_from_str`, exactly as the real PUT/rollback handlers do (per
    /// `apply_config`'s doc comment).
    #[test]
    fn apply_config_reapplying_the_same_resolved_secret_reports_no_restart_required() {
        std::env::set_var("RF_ENGINE_TEST_APPLY_SECRET", "sentinel-apply-secret-7f3a");
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
      token: "${{env:RF_ENGINE_TEST_APPLY_SECRET}}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            data_dir.display()
        );

        let cfg1 = crate::config::load_from_str(&yaml).unwrap();
        let d = Daemon::new(cfg1, &data_dir).unwrap();
        let cfg2 = crate::config::load_from_str(&yaml).unwrap();
        let outcome = d.apply_config(cfg2);
        std::env::remove_var("RF_ENGINE_TEST_APPLY_SECRET");

        assert!(
            outcome.restart_required.is_empty(),
            "re-applying an unchanged config (secret resolved via the same \
             env var both times) must not report a false-positive restart: \
             {outcome:?}"
        );
    }

    /// Carried fix (Task 1 review, Important -> Task 3): `apply_config` must
    /// serialize end-to-end so two overlapping callers (PUT and rollback
    /// racing, or two PUTs racing) never leave `cfg` holding one config's
    /// values while `sender_limiter` holds the OTHER config's numbers. This
    /// can't assert "config A always wins" (thread scheduling decides which
    /// of the two finishes last, and that's legitimately nondeterministic)
    /// -- what must hold, every run, is that whichever config `cfg` ends up
    /// with is the SAME config the limiter's live behavior reflects.
    #[test]
    fn apply_config_concurrent_calls_serialize_so_cfg_and_limiter_never_disagree() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path())); // Limits::default(): unlimited

        let mut cfg_tight = d.cfg.read().unwrap().clone();
        cfg_tight.limits.per_sender.messages_per_minute = 1;
        let mut cfg_loose = d.cfg.read().unwrap().clone();
        cfg_loose.limits.per_sender.messages_per_minute = 1000;

        let (d1, d2) = (d.clone(), d.clone());
        let t1 = std::thread::spawn(move || d1.apply_config(cfg_tight));
        let t2 = std::thread::spawn(move || d2.apply_config(cfg_loose));
        t1.join().unwrap();
        t2.join().unwrap();

        let final_limit = d.cfg_snapshot(|c| c.limits.per_sender.messages_per_minute);
        assert!(
            final_limit == 1 || final_limit == 1000,
            "unexpected limit: {final_limit}"
        );

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "one".into(),
            None,
            vec![],
            None,
        );
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "two".into(),
            None,
            vec![],
            None,
        );
        let pending = d
            .store
            .lock()
            .unwrap()
            .queue_counts()
            .unwrap()
            .into_iter()
            .find(|(state, _)| state == "pending")
            .map(|(_, n)| n)
            .unwrap_or(0);

        if final_limit == 1 {
            assert_eq!(
                pending, 1,
                "cfg ended up with the tight limit but the limiter let both messages through"
            );
        } else {
            assert_eq!(
                pending, 2,
                "cfg ended up with the loose limit but the limiter rate-limited the second message"
            );
        }
    }

    // ---- events (design §4: SSE live event feed) --------------------------

    /// design §4's "must cost ~nothing" with zero subscribers, from the
    /// behavioral side: `broadcast::Sender::send` never buffers anything for
    /// a receiver that didn't exist at send time, so a subscriber that joins
    /// AFTER the action ran sees nothing from it. This is also why every
    /// other test below subscribes BEFORE driving the action under test.
    #[test]
    fn emit_event_with_no_subscribers_at_send_time_reaches_a_later_subscriber_never() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
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
        let mut rx = d.events.subscribe();
        assert!(
            rx.try_recv().is_err(),
            "a late subscriber must not see a pre-subscription event"
        );
    }

    #[test]
    fn handle_inbound_emits_ingress_with_masked_sender_and_the_fan_out_route_list() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut rx = d.events.subscribe();

        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "+15551234567".into(),
            "text".into(),
            "hello".into(),
            None,
            vec![],
            None,
        );

        let ev = rx
            .try_recv()
            .expect("handle_inbound must emit an Ingress event on accept");
        match ev {
            Event::Ingress {
                protocol,
                sender_masked,
                routes,
                ..
            } => {
                assert_eq!(protocol, "mocka");
                assert_eq!(
                    sender_masked, "mocka:+1****4567",
                    "sender must appear only in the masked \"protocol:masked_ref\" compound form"
                );
                assert_eq!(routes, vec!["general".to_string()]);
            }
            other => panic!("expected Ingress, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "exactly one Ingress event per accepted message"
        );
    }

    #[test]
    fn handle_inbound_emits_no_ingress_event_for_a_dropped_unrouted_message() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut rx = d.events.subscribe();
        handle_inbound(
            &d,
            "mocka",
            "elsewhere".into(),
            "!a".into(),
            "text".into(),
            "hi".into(),
            None,
            vec![],
            None,
        );
        assert!(rx.try_recv().is_err(),
            "an unrouted (deny-by-default) message must not emit Ingress -- design §4 says \"post-accept\"");
    }

    fn deliver_one_message(d: &Daemon) -> (i64, uuid::Uuid) {
        handle_inbound(
            d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "hello".into(),
            None,
            vec![],
            None,
        );
        let store = d.store.lock().unwrap();
        let due = store.due_deliveries(Utc::now(), 10).unwrap();
        store.mark_attempting(due[0].id).unwrap();
        let message_id = store.deliveries_for_id(due[0].id).unwrap().message_id;
        (due[0].id, message_id)
    }

    #[test]
    fn handle_result_emits_delivery_event_state_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let (delivery_id, message_id) = deliver_one_message(&d);

        let mut rx = d.events.subscribe();
        handle_result(&d, delivery_id, true, None);

        let ev = rx
            .try_recv()
            .expect("handle_result(delivered) must emit a Delivery event");
        let Event::Delivery {
            id, route, state, ..
        } = ev
        else {
            panic!("expected Delivery, got {ev:?}");
        };
        assert_eq!(
            id, message_id,
            "id must be the message UUID, correlating with its Ingress event"
        );
        assert_eq!(route, "general");
        assert_eq!(state, "delivered");
    }

    #[test]
    fn handle_result_emits_delivery_event_state_retry_before_max_attempts() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let (delivery_id, _message_id) = deliver_one_message(&d); // attempt_count -> 1

        let mut rx = d.events.subscribe();
        handle_result(&d, delivery_id, false, Some("boom".into()));

        let ev = rx
            .try_recv()
            .expect("handle_result(retry) must emit a Delivery event");
        let Event::Delivery { route, state, .. } = ev else {
            panic!("expected Delivery, got {ev:?}");
        };
        assert_eq!(route, "general");
        assert_eq!(
            state, "retry",
            "an in-budget failure must report the semantic \"retry\" label, \
             not the raw \"pending\" deliveries.state column value"
        );
    }

    #[test]
    fn handle_result_emits_delivery_event_state_dead_letter_once_attempts_are_exhausted() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
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
        let delivery_id = {
            let store = d.store.lock().unwrap();
            let due = store.due_deliveries(Utc::now(), 10).unwrap();
            for _ in 0..queue::MAX_ATTEMPTS {
                store.mark_attempting(due[0].id).unwrap();
            }
            due[0].id
        };

        let mut rx = d.events.subscribe();
        handle_result(&d, delivery_id, false, Some("boom".into()));

        let ev = rx
            .try_recv()
            .expect("handle_result(dead_letter) must emit a Delivery event");
        let Event::Delivery { route, state, .. } = ev else {
            panic!("expected Delivery, got {ev:?}");
        };
        assert_eq!(route, "general");
        assert_eq!(state, "dead_letter");
    }

    #[test]
    fn confirm_link_emits_link_verified_with_only_the_opaque_link_id() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        seed_challenge(
            &d,
            ("mockb", "!target"),
            ("mocka", "!req"),
            "424242",
            "Jascha",
            Utc::now(),
            15,
        );

        let mut rx = d.events.subscribe();
        handle_inbound(
            &d,
            "mockb",
            "chan".into(),
            "!target".into(),
            "text".into(),
            "424242".into(),
            None,
            vec![],
            None,
        );

        let ev = rx
            .try_recv()
            .expect("a matched confirm must emit a LinkVerified event");
        let Event::LinkVerified { link_id, .. } = ev else {
            panic!("expected LinkVerified, got {ev:?}");
        };
        let link = d
            .store
            .lock()
            .unwrap()
            .link_for_identity("mockb", "!target")
            .unwrap()
            .unwrap();
        assert_eq!(link_id, link.id);
        assert!(
            rx.try_recv().is_err(),
            "the confirming message itself must not also emit an Ingress event (it's never routed)"
        );
    }

    #[test]
    fn apply_config_emits_config_applied_with_the_outcomes_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut new_cfg = d.cfg.read().unwrap().clone();
        new_cfg.plugins.get_mut("mockb").unwrap().command = Some("new-command".into());

        let mut rx = d.events.subscribe();
        let outcome = d.apply_config(new_cfg);

        let ev = rx
            .try_recv()
            .expect("apply_config must emit a ConfigApplied event");
        let Event::ConfigApplied {
            restart_required, ..
        } = ev
        else {
            panic!("expected ConfigApplied, got {ev:?}");
        };
        assert_eq!(restart_required, outcome.restart_required);
        assert_eq!(restart_required, vec!["mockb".to_string()]);
    }

    /// Design §Security invariants: a full realistic sequence (an inbound
    /// message carrying a sentinel body/native-ref, its delivery result, and
    /// an identity-link confirmation carrying a sentinel code/display_name)
    /// must never leak ANY of those sentinels into ANY captured event's JSON
    /// serialization -- across the whole stream, not just the one event
    /// that "should" logically carry that data.
    #[test]
    fn sse_privacy_full_sequence_never_leaks_body_ref_code_or_display_name() {
        const SENTINEL_BODY: &str = "the quick brown fox jumps SECRET-BODY-CONTENT";
        const SENTINEL_REF: &str = "+15551234999";
        const SENTINEL_CODE: &str = "993377";
        const SENTINEL_NAME: &str = "Sentinel Display Name Zyx";

        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let mut rx = d.events.subscribe();

        // leg 1+2: ingress + a delivered delivery
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            SENTINEL_REF.into(),
            "text".into(),
            SENTINEL_BODY.into(),
            None,
            vec![],
            None,
        );
        let delivery_id = {
            let store = d.store.lock().unwrap();
            let due = store.due_deliveries(Utc::now(), 10).unwrap();
            store.mark_attempting(due[0].id).unwrap();
            due[0].id
        };
        handle_result(&d, delivery_id, true, None);

        // leg 3: identity-link confirm
        seed_challenge(
            &d,
            ("mockb", "!privacy-target"),
            ("mocka", "!privacy-req"),
            SENTINEL_CODE,
            SENTINEL_NAME,
            Utc::now(),
            15,
        );
        handle_inbound(
            &d,
            "mockb",
            "chan".into(),
            "!privacy-target".into(),
            "text".into(),
            SENTINEL_CODE.into(),
            None,
            vec![],
            None,
        );

        let mut captured = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            captured.push(ev);
        }
        assert_eq!(
            captured.len(),
            3,
            "expected exactly ingress+delivery+link_verified: {captured:?}"
        );

        let corpus: String = captured
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            !corpus.contains(SENTINEL_BODY),
            "message body leaked: {corpus}"
        );
        assert!(
            !corpus.contains(SENTINEL_REF),
            "full native ref leaked: {corpus}"
        );
        assert!(
            !corpus.contains(SENTINEL_CODE),
            "challenge code leaked: {corpus}"
        );
        assert!(
            !corpus.contains(SENTINEL_NAME),
            "display_name leaked: {corpus}"
        );

        // Positive control: proves the sentinel ref really was present to
        // leak (in its masked form) -- so the negative assertions above are
        // meaningful, not vacuously true because nothing matched anything.
        assert!(
            corpus.contains("mocka:+1****4999"),
            "expected the masked sender to appear in the ingress event: {corpus}"
        );
    }

    // ---- Finding 1 (whole-branch review): the five previously-silent
    // terminal-transition sites must each emit a Delivery event. -----------

    #[tokio::test]
    async fn process_due_emits_delivery_event_state_failed_on_destination_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("relayfabric.db");
        let d = Arc::new(test_daemon(dir.path()));
        let now = Utc::now();
        let dest: Endpoint = "mockb:chan".parse().unwrap();

        // same technique as `process_due_marks_failed_when_message_missing_
        // without_deadlocking`: a delivery row whose message envelope JSON
        // is unreadable, simulating the realistic "missing message" case.
        let ghost_id = uuid::Uuid::now_v7();
        {
            let raw = rusqlite::Connection::open(&db_path).unwrap();
            raw.execute(
                "INSERT INTO messages (id, envelope, created_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![ghost_id.to_string(), "not valid json", now.to_rfc3339()],
            )
            .unwrap();
        }
        let del = {
            let store = d.store.lock().unwrap();
            let delivery_id = store
                .insert_delivery(
                    ghost_id,
                    "general",
                    &dest,
                    now,
                    now + CDuration::hours(1),
                    2,
                )
                .unwrap();
            store.deliveries_for_id(delivery_id).unwrap()
        };

        let mut rx = d.events.subscribe();
        process_due(&d, del, now).await;

        let ev = rx
            .try_recv()
            .expect("process_due must emit a Delivery event on DESTINATION_UNKNOWN");
        let Event::Delivery { route, state, .. } = ev else {
            panic!("expected Delivery, got {ev:?}");
        };
        assert_eq!(route, "general");
        assert_eq!(state, "failed");
    }

    #[tokio::test]
    async fn process_due_emits_delivery_event_state_expired_on_ttl_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let now = Utc::now();
        let env = Envelope::new(
            "mocka:chan".parse().unwrap(),
            Sender {
                native_ref: "!a".into(),
            },
            "text".into(),
            "hello".into(),
            now - CDuration::hours(2),
            now - CDuration::hours(1),
            8,
        );
        let dest: Endpoint = "mockb:chan".parse().unwrap();
        let del = {
            let store = d.store.lock().unwrap();
            store.insert_message(&env).unwrap();
            let delivery_id = store
                .insert_delivery(env.id, "general", &dest, now, env.expires_at, 2)
                .unwrap();
            store.deliveries_for_id(delivery_id).unwrap()
        };

        let mut rx = d.events.subscribe();
        process_due(&d, del, now).await;

        let ev = rx
            .try_recv()
            .expect("process_due must emit a Delivery event on TTL_EXPIRED");
        let Event::Delivery { route, state, .. } = ev else {
            panic!("expected Delivery, got {ev:?}");
        };
        assert_eq!(route, "general");
        assert_eq!(
            state, "expired",
            "the DB state ('expired') must be emitted as-is, not folded into 'failed'"
        );
    }

    #[tokio::test]
    async fn process_due_emits_delivery_event_state_dead_letter_on_policy_denial() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        d.cfg.write().unwrap().policies = vec![crate::config::Policy {
            name: "deny-b".into(),
            r#match: crate::config::PolicyMatch {
                destination_protocol: vec!["mockb".into()],
            },
            rules: crate::config::PolicyRules {
                deny: true,
                ..Default::default()
            },
        }];
        let d = Arc::new(d);
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
        let now = Utc::now();
        let del = {
            let store = d.store.lock().unwrap();
            store
                .due_deliveries(now, 1)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
        };

        let mut rx = d.events.subscribe();
        process_due(&d, del, now).await;

        let ev = rx
            .try_recv()
            .expect("process_due must emit a Delivery event on POLICY_DENIED");
        let Event::Delivery { route, state, .. } = ev else {
            panic!("expected Delivery, got {ev:?}");
        };
        assert_eq!(route, "general");
        assert_eq!(state, "dead_letter");
    }

    #[tokio::test]
    async fn process_due_identity_emits_delivery_event_state_dead_letter_on_not_direct_capable() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let _rx_plugin = register_plugin(&d, "mockb", false); // connected, NOT direct-capable

        let target: Endpoint = "mockb:!target".parse().unwrap();
        let now = Utc::now();
        let env = Envelope::new(
            "identity:system".parse().unwrap(),
            Sender {
                native_ref: "@identity".into(),
            },
            "notice".into(),
            "code".into(),
            now,
            now + CDuration::minutes(15),
            8,
        );
        d.store.lock().unwrap().insert_message(&env).unwrap();
        let del = {
            let store = d.store.lock().unwrap();
            let delivery_id = store
                .insert_delivery(env.id, IDENTITY_ROUTE, &target, now, env.expires_at, 2)
                .unwrap();
            store.deliveries_for_id(delivery_id).unwrap()
        };

        let mut rx = d.events.subscribe();
        process_due(&d, del, now).await;

        let ev = rx
            .try_recv()
            .expect("process_due_identity must emit a Delivery event on NOT_DIRECT_CAPABLE");
        let Event::Delivery { route, state, .. } = ev else {
            panic!("expected Delivery, got {ev:?}");
        };
        assert_eq!(route, IDENTITY_ROUTE);
        assert_eq!(state, "dead_letter");
    }

    #[test]
    fn handle_inbound_emits_delivery_event_state_dead_letter_on_queue_full() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                per_route: crate::config::PerRoute { queue_max: 1 },
                ..Default::default()
            },
        );
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "first".into(),
            None,
            vec![],
            None,
        );

        let mut rx = d.events.subscribe();
        handle_inbound(
            &d,
            "mocka",
            "chan".into(),
            "!a".into(),
            "text".into(),
            "second".into(),
            None,
            vec![],
            None,
        );

        let mut saw_dead_letter = false;
        while let Ok(ev) = rx.try_recv() {
            if let Event::Delivery { route, state, .. } = &ev {
                assert_eq!(route, "general");
                assert_eq!(state, "dead_letter");
                saw_dead_letter = true;
            }
        }
        assert!(
            saw_dead_letter,
            "queue-full must emit a Delivery(dead_letter) event"
        );
    }

    #[test]
    fn initiate_link_emits_delivery_event_state_dead_letter_on_global_queue_full() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_limits(
            dir.path(),
            crate::config::Limits {
                global: crate::config::GlobalLimits {
                    queue_max: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let _rx_plugin = register_direct_plugin(&d, "mockb");
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

        let requester: Endpoint = "mocka:!req".parse().unwrap();
        let target: Endpoint = "mockb:!target".parse().unwrap();

        let mut rx = d.events.subscribe();
        let err = initiate_link(&d, requester, target, "Jascha").unwrap_err();
        assert_eq!(err, "queue full");

        let ev = rx
            .try_recv()
            .expect("enqueue_identity_send must emit a Delivery event on QUEUE_FULL");
        let Event::Delivery { route, state, .. } = ev else {
            panic!("expected Delivery, got {ev:?}");
        };
        assert_eq!(route, IDENTITY_ROUTE);
        assert_eq!(state, "dead_letter");
    }

    // ==== fed_ingress (design §5, Task 4) =================================

    fn fed_peer_cfg(name: &str, node_id: &str, trust: &str) -> crate::config::PeerConfig {
        crate::config::PeerConfig {
            name: name.into(),
            node_id: node_id.into(),
            addr: "10.0.0.2:47000".into(),
            trust: trust.into(),
            messages_per_minute: 0,
            sealed_key: None,
        }
    }

    /// `federation.ingress_routes: ["general"]`, `accept_from` and
    /// `max_hops`/`max_ttl_secs` caller-supplied — the fixture's `general`
    /// route (from `test_daemon_full`) has two destinations
    /// (`mocka:chan`/`mockb:chan`), so a happy-path accept always produces
    /// two delivery rows.
    fn fed_config(
        accept_from: &str,
        max_hops: u32,
        max_ttl_secs: u64,
    ) -> crate::config::FederationConfig {
        crate::config::FederationConfig {
            listen: None,
            accept_from: accept_from.into(),
            max_hops,
            max_ttl_secs,
            identity_exposure: "pseudonymous".into(),
            ingress_routes: vec!["general".into()],
            peers: vec![],
            trusted: vec![],
            blocked: vec![],
        }
    }

    #[test]
    fn fed_ingress_happy_path_accepts_fans_out_and_increments_fed_ingress() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let fed = fed_config("verified", 4, 86_400);
        let mut cfg = fed.clone();
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        let before = metrics::FED_INGRESS.load(std::sync::atomic::Ordering::Relaxed);
        let env = signed_test_envelope(&identity, "hello federation", 0);
        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert!(
            matches!(outcome, FedIngressOutcome::Accepted(_)),
            "expected Accepted, got {outcome:?}"
        );
        let after = metrics::FED_INGRESS.load(std::sync::atomic::Ordering::Relaxed);
        assert!(after > before, "FED_INGRESS must increment on accept");

        let store = d.store.lock().unwrap();
        let counts = store.queue_counts().unwrap();
        assert_eq!(
            counts,
            vec![("pending".to_string(), 2)],
            "both of general's destinations must get a delivery row"
        );
    }

    /// Fix round 1 (DoS hardening): BAD_SIGNATURE/TRUST_DENIED are
    /// `Persistence::NoPersist` -- reachable by ANY peer with zero trust
    /// established, so they must never write to `messages`/`deliveries`.
    #[test]
    fn fed_ingress_bad_signature_is_not_persisted_but_still_bumps_fed_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        // No origin signature at all -- verify_chain must reject before
        // anything else runs.
        let env = {
            let now = Utc::now();
            Envelope::new(
                Endpoint {
                    protocol: "mock".into(),
                    endpoint: "origin-chan".into(),
                },
                Sender {
                    native_ref: "!origin-sender".into(),
                },
                "text".into(),
                "unsigned".into(),
                now,
                now + CDuration::hours(1),
                8,
            )
        };
        let env_id = env.id;

        let before = metrics::FED_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("BAD_SIGNATURE"));
        let after = metrics::FED_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            after > before,
            "FED_REJECTED must increment on rejection even though nothing persists"
        );

        let store = d.store.lock().unwrap();
        assert!(
            store.queue_counts().unwrap().is_empty(),
            "BAD_SIGNATURE must never create a delivery row (pre-trust, DoS-hardening)"
        );
        assert!(
            store.get_message(env_id).unwrap().is_none(),
            "BAD_SIGNATURE must never persist the message either"
        );
    }

    /// A flood of DISTINCT bad-signature envelopes (an untrusted peer's
    /// realistic attack shape) must leave storage completely untouched no
    /// matter how many are sent -- the core DoS-hardening property, not
    /// just "one rejection doesn't persist".
    #[test]
    fn fed_ingress_bad_signature_flood_writes_zero_rows_regardless_of_volume() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let d = test_daemon_with_federation(dir.path(), fed_config("verified", 4, 86_400));

        for i in 0..5 {
            let now = Utc::now();
            let env = Envelope::new(
                Endpoint {
                    protocol: "mock".into(),
                    endpoint: "origin-chan".into(),
                },
                Sender {
                    native_ref: "!origin-sender".into(),
                },
                "text".into(),
                format!("garbage {i}"),
                now,
                now + CDuration::hours(1),
                8,
            );
            let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
            assert_eq!(outcome, FedIngressOutcome::Rejected("BAD_SIGNATURE"));
        }

        let store = d.store.lock().unwrap();
        assert!(
            store.queue_counts().unwrap().is_empty(),
            "a flood of unsigned envelopes must create zero delivery rows"
        );
    }

    #[test]
    fn fed_ingress_trust_denied_is_not_persisted_but_still_bumps_fed_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        // Peer is a configured peer at "verified", but accept_from requires
        // "trusted" -- design's security invariant: "accept_from=trusted
        // rejects verified".
        let mut cfg = fed_config("trusted", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        let env = signed_test_envelope(&identity, "hello", 0);
        let env_id = env.id;
        let before = metrics::FED_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("TRUST_DENIED"));
        assert!(metrics::FED_REJECTED.load(std::sync::atomic::Ordering::Relaxed) > before);

        let store = d.store.lock().unwrap();
        assert!(
            store.queue_counts().unwrap().is_empty(),
            "TRUST_DENIED must never create a delivery row (pre-trust, DoS-hardening)"
        );
        assert!(store.get_message(env_id).unwrap().is_none());
    }

    #[test]
    fn fed_ingress_trust_denied_for_an_unconfigured_unseen_peer() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        // Peer never seeded/seen at all (no peers[]/trusted entry, no
        // handshake ever recorded `seen`) -- trust_level() is None, which
        // must gate the same as "unknown", failing the default
        // accept_from="verified".
        let d = test_daemon_with_federation(dir.path(), fed_config("verified", 4, 86_400));

        let env = signed_test_envelope(&identity, "hello", 0);
        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("TRUST_DENIED"));
    }

    /// A flood of DISTINCT, VALIDLY-SIGNED-but-untrusted envelopes (the
    /// realistic attack shape for a peer that discovered/guessed a
    /// legitimate origin's canonical bytes are irrelevant -- signature
    /// validity alone never earns trust) must also leave storage
    /// completely untouched.
    #[test]
    fn fed_ingress_trust_denied_flood_writes_zero_rows_regardless_of_volume() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let d = test_daemon_with_federation(dir.path(), fed_config("verified", 4, 86_400));

        let before = metrics::FED_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        for i in 0..5 {
            let env = signed_test_envelope(&identity, &format!("flood {i}"), 0);
            let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
            assert_eq!(outcome, FedIngressOutcome::Rejected("TRUST_DENIED"));
        }
        let after = metrics::FED_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            after >= before + 5,
            "FED_REJECTED must bump once per rejected envelope: {before} -> {after}"
        );

        let store = d.store.lock().unwrap();
        assert!(
            store.queue_counts().unwrap().is_empty(),
            "a pre-trust flood of 5 distinct envelopes must create zero delivery rows"
        );
    }

    #[test]
    fn fed_ingress_hop_limit_rejects_at_exactly_max_hops_and_still_dead_letters() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        // exactly max_hops (4): design §4 "at or over this are dead_lettered".
        let env = signed_test_envelope(&identity, "looped", 4);
        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("HOP_LIMIT"));

        // HOP_LIMIT only fires once the sender already cleared the trust
        // gate -- Persistence::Persist, so it still lands in dead_letter
        // (operator-actionable), unlike the pre-trust NoPersist reasons.
        let store = d.store.lock().unwrap();
        assert_eq!(
            store.queue_counts().unwrap(),
            vec![("dead_letter".to_string(), 1)]
        );
        drop(store);

        // one under the limit: must be accepted.
        let env_ok = signed_test_envelope(&identity, "not looped", 3);
        let outcome_ok = fed_ingress(&d, &node_id, env_ok, "general".to_string());
        assert!(matches!(outcome_ok, FedIngressOutcome::Accepted(_)));
    }

    #[test]
    fn fed_ingress_route_not_federated_when_target_route_not_in_ingress_routes_and_still_dead_letters(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        // ingress_routes deliberately does NOT include "general".
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.ingress_routes = vec![];
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        let env = signed_test_envelope(&identity, "hello", 0);
        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("ROUTE_NOT_FEDERATED"));

        // ROUTE_NOT_FEDERATED also only fires post-trust-gate -- Persist.
        let store = d.store.lock().unwrap();
        assert_eq!(
            store.queue_counts().unwrap(),
            vec![("dead_letter".to_string(), 1)]
        );
    }

    /// Fix round 1 Minor: the two defensive "should be unreachable"
    /// branches (federation config absent; `ingress_routes` names a route
    /// that doesn't actually exist in `cfg.routes`) get their own reason
    /// `FED_CONFIG_MISSING`, distinct from `ROUTE_NOT_FEDERATED` -- a
    /// config-invariant violation the daemon's own operator caused, not a
    /// policy rejection, and still persisted (an untrusted peer can't
    /// reach either branch: the first runs before any peer input matters,
    /// the second only after the peer already cleared the trust gate).
    #[test]
    fn fed_ingress_missing_federation_config_uses_its_own_reason_and_still_persists() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        // No federation block at all -- fed_ingress is never normally
        // called this way in production (nothing wires it without
        // federation configured), but the defensive branch must behave
        // correctly if it ever is.
        let d = test_daemon(dir.path());

        let env = signed_test_envelope(&identity, "hello", 0);
        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("FED_CONFIG_MISSING"));

        let store = d.store.lock().unwrap();
        assert_eq!(
            store.queue_counts().unwrap(),
            vec![("dead_letter".to_string(), 1)]
        );
    }

    #[test]
    fn fed_ingress_ingress_route_naming_a_nonexistent_route_uses_fed_config_missing() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        // ingress_routes names a route that isn't in cfg.routes at all --
        // config::validate_federation would normally reject this
        // combination at load time; constructing it directly (bypassing
        // validation, as every test_daemon_* helper does) exercises the
        // defensive fallback on its own.
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.ingress_routes = vec!["ghost-route".into()];
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        let env = signed_test_envelope(&identity, "hello", 0);
        let outcome = fed_ingress(&d, &node_id, env, "ghost-route".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("FED_CONFIG_MISSING"));
    }

    #[test]
    fn fed_ingress_ttl_is_clamped_down_to_max_ttl_secs_never_extended() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 3600); // 1 hour cap
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        // signed_test_envelope's own TTL is 1 hour already (< the cap), so
        // build one with a much longer remote-claimed TTL by hand.
        let now = Utc::now();
        let mut env = Envelope::new(
            Endpoint {
                protocol: "mock".into(),
                endpoint: "origin-chan".into(),
            },
            Sender {
                native_ref: "!origin-sender".into(),
            },
            "text".into(),
            "long ttl".into(),
            now,
            now + CDuration::days(100),
            8,
        );
        env.origin = Some(fed::sign::sign_origin(&env, &identity));

        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        let FedIngressOutcome::Accepted(id) = outcome else {
            panic!("expected Accepted")
        };

        let store = d.store.lock().unwrap();
        let stored = store.get_message(id).unwrap().unwrap();
        let delta = (stored.expires_at - Utc::now()).num_seconds();
        assert!(
            delta <= 3600 && delta > 3500,
            "expires_at must be clamped to ~max_ttl_secs from now, got delta={delta}s"
        );
    }

    #[test]
    fn fed_ingress_strips_remote_priority_to_default_rank_even_when_emergency_claimed() {
        // CONTROLLER RULING (Task 2 review, binding on Task 4): a remote
        // peer setting priority: "emergency" on a federated envelope must
        // never reach the local emergency transport-budget bypass --
        // priority is unsigned, so this can't be caught by verify_chain;
        // fed_ingress must unconditionally re-stamp it before persisting.
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        // Build (and sign) an envelope, THEN tamper priority afterward --
        // priority is deliberately unsigned, so this must still verify.
        let mut env = signed_test_envelope(&identity, "urgent!!", 0);
        env.priority = "emergency".to_string();
        assert_eq!(
            fed::sign::verify_chain(&env),
            Ok(()),
            "priority is unsigned by design -- tampering it must not break the signature"
        );

        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert!(matches!(outcome, FedIngressOutcome::Accepted(_)));

        let store = d.store.lock().unwrap();
        let due = store.due_deliveries(Utc::now(), 10).unwrap();
        assert_eq!(due.len(), 2);
        assert!(
            due.iter()
                .all(|d| d.priority == relay_core::priority_rank("normal")),
            "every delivery row must be at the DEFAULT rank, never emergency's rank 0: {due:?}"
        );
        let stored = store.get_message(due[0].message_id).unwrap().unwrap();
        assert_eq!(
            stored.priority, "normal",
            "the stored envelope's priority class itself must be re-stamped to \"normal\""
        );
    }

    #[test]
    fn fed_ingress_dedup_replay_is_inert_no_new_delivery_rows_or_fed_ingress_bump() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        let env = signed_test_envelope(&identity, "replay me", 0);
        let env_replay = env.clone();
        let first = fed_ingress(&d, &node_id, env, "general".to_string());
        assert!(matches!(first, FedIngressOutcome::Accepted(_)));

        // FED_INGRESS/DUPLICATES are process-globals shared with every other
        // test in this binary's parallel run (`metrics.rs`'s own tests
        // document the same constraint) -- only a monotonic ">" check on
        // DUPLICATES is safe here; the authoritative "the replay did not
        // re-accept/re-fan-out" proof is the delivery ROW COUNT below,
        // which is per-Daemon (this test's own tempdir-backed store) and
        // immune to cross-test interference.
        let before_dup = metrics::DUPLICATES.load(std::sync::atomic::Ordering::Relaxed);
        let second = fed_ingress(&d, &node_id, env_replay, "general".to_string());
        assert_eq!(second, FedIngressOutcome::Rejected("DUPLICATE"));
        assert!(metrics::DUPLICATES.load(std::sync::atomic::Ordering::Relaxed) > before_dup);

        let store = d.store.lock().unwrap();
        assert_eq!(
            store.queue_counts().unwrap(),
            vec![("pending".to_string(), 2)],
            "the replay must not create any additional delivery rows"
        );
    }

    // ==== replay window (final-review I-1) =================================

    /// A signed envelope with caller-chosen `created_at`/`expires_at` --
    /// `created_at` IS covered by the origin signature (canonical bytes),
    /// `expires_at` deliberately is NOT (any on-path relay can rewrite it),
    /// which is exactly the asymmetry these tests exercise.
    fn signed_envelope_with_times(
        identity: &crate::node_identity::NodeIdentity,
        body: &str,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Envelope {
        let mut env = Envelope::new(
            Endpoint {
                protocol: "mock".into(),
                endpoint: "origin-chan".into(),
            },
            Sender {
                native_ref: "!origin-sender".into(),
            },
            "text".into(),
            body.to_string(),
            created_at,
            expires_at,
            8,
        );
        env.origin = Some(fed::sign::sign_origin(&env, identity));
        env
    }

    /// The replay-window bound itself: a captured envelope whose SIGNED
    /// `created_at` is older than the accept side's `max_ttl_secs` must be
    /// rejected `EXPIRED` even though its (unsigned, attacker-rewritten)
    /// `expires_at` claims it's still fresh -- and even though the dedup
    /// cache has no entry for it (this daemon is fresh, exactly the
    /// post-restart replay scenario). Post-trust, so it persists as a
    /// dead_letter row.
    #[test]
    fn fed_ingress_created_at_older_than_max_ttl_is_dead_lettered_expired_despite_fresh_expires_at()
    {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 3600); // 1 hour replay window
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        let now = Utc::now();
        let env = signed_envelope_with_times(
            &identity,
            "stale replay",
            now - CDuration::hours(2),
            now + CDuration::days(100),
        );
        assert_eq!(
            fed::sign::verify_chain(&env),
            Ok(()),
            "the replayed envelope's signature is genuine -- only its age gives it away"
        );

        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("EXPIRED"));

        let store = d.store.lock().unwrap();
        assert_eq!(
            store.queue_counts().unwrap(),
            vec![("dead_letter".to_string(), 1)],
            "EXPIRED is post-trust: it must dead_letter, never silently vanish or deliver"
        );
    }

    /// Just inside the window: `created_at` within `max_ttl_secs` of now is
    /// still accepted (the bound must not reject legitimate traffic).
    #[test]
    fn fed_ingress_created_at_just_inside_max_ttl_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 3600);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        let now = Utc::now();
        let env = signed_envelope_with_times(
            &identity,
            "nearly stale",
            now - CDuration::seconds(3500),
            now + CDuration::hours(1),
        );
        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert!(
            matches!(outcome, FedIngressOutcome::Accepted(_)),
            "an envelope inside the replay window must still be delivered, got {outcome:?}"
        );
    }

    /// Far-future `created_at` (clock-skew abuse): a peer stamping
    /// `created_at` ahead of real time would otherwise mint an envelope
    /// whose replay window only STARTS in the future -- capped at a small
    /// skew allowance, beyond which it's rejected `EXPIRED` too.
    #[test]
    fn fed_ingress_far_future_created_at_is_rejected_expired() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 3600);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        let now = Utc::now();
        let env = signed_envelope_with_times(
            &identity,
            "from the future",
            now + CDuration::seconds(3600),
            now + CDuration::hours(2),
        );
        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("EXPIRED"));

        let store = d.store.lock().unwrap();
        assert_eq!(
            store.queue_counts().unwrap(),
            vec![("dead_letter".to_string(), 1)]
        );
    }

    /// Ordinary clock skew between honest peers (seconds, not hours) must
    /// pass: `created_at` slightly ahead of now, within the allowance.
    #[test]
    fn fed_ingress_created_at_within_clock_skew_allowance_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 3600);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);

        let now = Utc::now();
        let env = signed_envelope_with_times(
            &identity,
            "slightly ahead",
            now + CDuration::seconds(200),
            now + CDuration::hours(1),
        );
        let outcome = fed_ingress(&d, &node_id, env, "general".to_string());
        assert!(
            matches!(outcome, FedIngressOutcome::Accepted(_)),
            "a few seconds of clock skew must not reject honest traffic, got {outcome:?}"
        );
    }

    #[test]
    fn fed_ingress_per_sender_limit_denies_second_message_without_dead_lettering() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let limits = crate::config::Limits {
            per_sender: crate::config::PerSender {
                messages_per_minute: 1,
                bytes_per_hour: 0,
            },
            ..Default::default()
        };
        let d = test_daemon_with_federation_and_limits(dir.path(), cfg, limits);

        let first = signed_test_envelope(&identity, "first", 0);
        assert!(matches!(
            fed_ingress(&d, &node_id, first, "general".to_string()),
            FedIngressOutcome::Accepted(_)
        ));

        let before = metrics::RATELIMITED.load(std::sync::atomic::Ordering::Relaxed);
        let second = signed_test_envelope(&identity, "second, distinct body", 0);
        let outcome = fed_ingress(&d, &node_id, second, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("RATE_LIMITED"));
        assert!(metrics::RATELIMITED.load(std::sync::atomic::Ordering::Relaxed) > before);

        let store = d.store.lock().unwrap();
        // Only the first message's two deliveries -- the rate-limited
        // second message gets no dead_letter row at all (silent drop,
        // mirroring handle_inbound's own rate-limit gate).
        assert_eq!(
            store.queue_counts().unwrap(),
            vec![("pending".to_string(), 2)]
        );
    }

    // ==== fed_sealed_ingress (design §5, SPEC §113.2/§113.5, cycle H,
    // Task 5) ================================================================

    /// Seals `env` for `recipient_pub`, header `expires_at` set to `env`'s
    /// own `expires_at` -- the common case every test below uses except the
    /// header-expiry test, which needs an independently-chosen header
    /// value (see `seal_env_for_with_expiry`).
    fn seal_env_for(
        env: &Envelope,
        recipient_pub: &crypto_box::PublicKey,
    ) -> fed::seal::SealedEnvelope {
        seal_env_for_with_expiry(env, recipient_pub, env.expires_at.timestamp())
    }

    /// `seal_env_for`, but with an independently-chosen sealed-header
    /// `expires_at` -- lets a test set the CLEARTEXT header's expiry
    /// without touching the envelope's own (separately-checked, post-
    /// decrypt) `created_at`/`expires_at`.
    fn seal_env_for_with_expiry(
        env: &Envelope,
        recipient_pub: &crypto_box::PublicKey,
        header_expires_at: i64,
    ) -> fed::seal::SealedEnvelope {
        let mut cbor = Vec::new();
        ciborium::into_writer(env, &mut cbor).unwrap();
        fed::seal::seal(&cbor, &env.id.to_string(), header_expires_at, recipient_pub)
    }

    /// Sets `route_name`'s `allow_gateway_decryption` override via
    /// `apply_config` (live, no restart) -- the downgrade-refusal test
    /// fixture setup, mirroring `set_route_security_mode`'s own pattern.
    fn set_route_allow_gateway_decryption(d: &Daemon, route_name: &str, value: Option<bool>) {
        let mut cfg = d.cfg.read().unwrap().clone();
        let route = cfg
            .routes
            .iter_mut()
            .find(|r| r.name == route_name)
            .unwrap_or_else(|| panic!("route '{route_name}' not found in test fixture config"));
        route.allow_gateway_decryption = value;
        d.apply_config(cfg);
    }

    #[tokio::test]
    async fn fed_sealed_ingress_happy_path_decrypts_delivers_to_mock_plugin_and_increments_sealed_ingress(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = Arc::new(test_daemon_with_federation(dir.path(), cfg));
        let mut rx_a = register_plugin(&d, "mocka", true);
        let mut rx_b = register_plugin(&d, "mockb", true);

        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());
        let body = "hello sealed ingress";
        let env = signed_test_envelope(&identity, body, 0);
        let env_id = env.id;
        let sealed = seal_env_for(&env, &recipient_pub);

        let before = metrics::SEALED_INGRESS.load(std::sync::atomic::Ordering::Relaxed);
        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Accepted(env_id));
        assert!(
            metrics::SEALED_INGRESS.load(std::sync::atomic::Ordering::Relaxed) > before,
            "SEALED_INGRESS must increment on accept"
        );

        let now = Utc::now();
        let dels = {
            let store = d.store.lock().unwrap();
            store.due_deliveries(now, 10).unwrap()
        };
        assert_eq!(
            dels.len(),
            2,
            "both of general's destinations must get a delivery row"
        );
        for del in dels {
            process_due(&d, del, now).await;
        }

        let DaemonToPlugin::Send { body: got_a, .. } = recv_send(&mut rx_a).await else {
            panic!("expected Send to mocka");
        };
        let DaemonToPlugin::Send { body: got_b, .. } = recv_send(&mut rx_b).await else {
            panic!("expected Send to mockb");
        };
        assert!(
            got_a.contains(body),
            "decrypted body must reach mocka verbatim: {got_a}"
        );
        assert!(
            got_b.contains(body),
            "decrypted body must reach mockb verbatim: {got_b}"
        );
    }

    #[test]
    fn fed_sealed_ingress_unsupported_alg_is_rejected_before_any_crypto() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        let env = signed_test_envelope(&identity, "hello", 0);
        let mut sealed = seal_env_for(&env, &recipient_pub);
        sealed.alg = "some-future-pq-hybrid-v2".to_string();

        let before = metrics::SEALED_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("UNSUPPORTED_SEAL_ALG"));
        assert!(metrics::SEALED_REJECTED.load(std::sync::atomic::Ordering::Relaxed) > before);
        assert!(
            d.store.lock().unwrap().queue_counts().unwrap().is_empty(),
            "no sealed rejection ever persists a delivery row"
        );
    }

    #[test]
    fn fed_sealed_ingress_expired_header_is_rejected_before_unseal() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        let env = signed_test_envelope(&identity, "hello", 0);
        let past = (Utc::now() - CDuration::hours(1)).timestamp();
        let sealed = seal_env_for_with_expiry(&env, &recipient_pub, past);

        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("EXPIRED"));
        assert!(d.store.lock().unwrap().queue_counts().unwrap().is_empty());
    }

    #[test]
    fn fed_sealed_ingress_tampered_ciphertext_fails_bad_seal() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        let env = signed_test_envelope(&identity, "hello", 0);
        let mut sealed = seal_env_for(&env, &recipient_pub);
        sealed.ct[0] ^= 0xFF;

        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("BAD_SEAL"));
        assert!(d.store.lock().unwrap().queue_counts().unwrap().is_empty());
    }

    #[test]
    fn fed_sealed_ingress_tampered_header_id_fails_bad_binding() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        let env = signed_test_envelope(&identity, "hello", 0);
        let mut sealed = seal_env_for(&env, &recipient_pub);
        // AEAD still opens fine (id isn't part of ct's AAD -- there is
        // none); only the post-decrypt binding check catches this.
        sealed.id = "a-completely-different-id".to_string();

        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("BAD_BINDING"));
        assert!(d.store.lock().unwrap().queue_counts().unwrap().is_empty());
    }

    #[test]
    fn fed_sealed_ingress_malformed_inner_cbor_fails_bad_seal_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        // Seal bytes that are NOT a valid Envelope CBOR at all -- `unseal`
        // itself only assumes a `(bytes, string, i64)` tuple shape, so
        // decrypt+binding both succeed; the failure must surface at
        // `fed_sealed_ingress`'s own decode step, via `Result`, never a
        // panic.
        let garbage = b"not a valid envelope cbor, just some sentinel bytes".to_vec();
        let expires = (Utc::now() + CDuration::hours(1)).timestamp();
        let sealed = fed::seal::seal(&garbage, "msg-malformed-inner", expires, &recipient_pub);

        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("BAD_SEAL"));
        assert!(d.store.lock().unwrap().queue_counts().unwrap().is_empty());
    }

    #[test]
    fn fed_sealed_ingress_bad_signature_unsigned_envelope_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        // No origin signature at all -- decrypts and decodes fine, but
        // verify_chain must reject before trust/downgrade/delivery.
        let now = Utc::now();
        let env = Envelope::new(
            Endpoint {
                protocol: "mock".into(),
                endpoint: "origin-chan".into(),
            },
            Sender {
                native_ref: "!origin-sender".into(),
            },
            "text".into(),
            "unsigned".into(),
            now,
            now + CDuration::hours(1),
            8,
        );
        let sealed = seal_env_for(&env, &recipient_pub);

        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("BAD_SIGNATURE"));
        assert!(d.store.lock().unwrap().queue_counts().unwrap().is_empty());
    }

    /// DoS hardening (public-node review, 2026-08-20): the trust gate runs
    /// BEFORE `unseal`, so an untrusted peer can never make this node do
    /// X25519+AEAD work. Proven by the rejection reason: a tampered seal
    /// from an untrusted peer must fail TRUST_DENIED (pre-crypto), never
    /// BAD_SEAL (which would mean unseal ran).
    #[test]
    fn fed_sealed_ingress_untrusted_peer_is_denied_before_unseal() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("trusted", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        let env = signed_test_envelope(&identity, "hello", 0);
        let mut sealed = seal_env_for(&env, &recipient_pub);
        sealed.ct[0] ^= 0xFF; // would be BAD_SEAL if unseal were reached

        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("TRUST_DENIED"));
        assert!(d.store.lock().unwrap().queue_counts().unwrap().is_empty());
    }

    #[test]
    fn fed_sealed_ingress_trust_denied_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        // Peer is configured at "verified", but accept_from requires
        // "trusted" -- mirrors `fed_ingress`'s own trust-denial fixture.
        let mut cfg = fed_config("trusted", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        let env = signed_test_envelope(&identity, "hello", 0);
        let sealed = seal_env_for(&env, &recipient_pub);

        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("TRUST_DENIED"));
        assert!(d.store.lock().unwrap().queue_counts().unwrap().is_empty());
    }

    #[test]
    fn fed_sealed_ingress_route_not_federated_when_target_not_in_ingress_routes() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.ingress_routes = vec![]; // "general" deliberately not federated
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        let env = signed_test_envelope(&identity, "hello", 0);
        let sealed = seal_env_for(&env, &recipient_pub);

        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("ROUTE_NOT_FEDERATED"));
        // Unlike `fed_ingress`'s own ROUTE_NOT_FEDERATED (Persist, since it
        // only fires post-trust), `fed_sealed_ingress` never persists ANY
        // rejection -- see `sealed_reject`'s doc comment for why.
        assert!(d.store.lock().unwrap().queue_counts().unwrap().is_empty());
    }

    /// The reason this whole task exists (design §113.2): a route that has
    /// declared it will not be a sealed->plaintext termination point must
    /// dead-letter, and -- critically -- the decrypted content must reach
    /// NEITHER a plugin NOR local storage.
    #[test]
    fn fed_sealed_ingress_downgrade_refused_route_never_delivers_content() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        set_route_allow_gateway_decryption(&d, "general", Some(false));
        let mut rx_a = register_plugin(&d, "mocka", true);
        let mut rx_b = register_plugin(&d, "mockb", true);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        let sentinel = "SENTINEL-DOWNGRADE-REFUSED-BODY-MUST-NEVER-BE-DELIVERED";
        let env = signed_test_envelope(&identity, sentinel, 0);
        let env_id = env.id;
        let sealed = seal_env_for(&env, &recipient_pub);

        let before = metrics::SEALED_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert_eq!(
            outcome,
            FedIngressOutcome::Rejected("SECURITY_DOWNGRADE_REFUSED")
        );
        assert!(metrics::SEALED_REJECTED.load(std::sync::atomic::Ordering::Relaxed) > before);

        let store = d.store.lock().unwrap();
        assert!(
            store.queue_counts().unwrap().is_empty(),
            "downgrade refusal must never create a delivery row -- content stays undelivered"
        );
        assert!(
            store.get_message(env_id).unwrap().is_none(),
            "downgrade refusal must never persist the decrypted envelope either"
        );
        drop(store);

        assert!(
            rx_a.try_recv().is_err(),
            "mocka plugin must receive nothing on downgrade refusal"
        );
        assert!(
            rx_b.try_recv().is_err(),
            "mockb plugin must receive nothing on downgrade refusal"
        );
    }

    #[test]
    fn fed_sealed_ingress_dedup_replay_is_inert_no_new_delivery_rows_or_sealed_ingress_bump() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        let env = signed_test_envelope(&identity, "replay me", 0);
        let sealed = seal_env_for(&env, &recipient_pub);
        let sealed_replay = sealed.clone();

        let first = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert!(matches!(first, FedIngressOutcome::Accepted(_)));

        let before_dup = metrics::DUPLICATES.load(std::sync::atomic::Ordering::Relaxed);
        let second = fed_sealed_ingress(&d, &node_id, sealed_replay, "general".to_string());
        assert_eq!(second, FedIngressOutcome::Rejected("DUPLICATE"));
        assert!(metrics::DUPLICATES.load(std::sync::atomic::Ordering::Relaxed) > before_dup);

        let store = d.store.lock().unwrap();
        assert_eq!(
            store.queue_counts().unwrap(),
            vec![("pending".to_string(), 2)],
            "the replay must not create any additional delivery rows"
        );
    }

    #[test]
    fn fed_sealed_ingress_strips_remote_priority_to_default_rank_even_when_emergency_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = test_daemon_with_federation(dir.path(), cfg);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        // priority is unsigned by design -- tampering it after signing must
        // not break verify_chain (same fixture shape as fed_ingress's own
        // priority-strip test).
        let mut env = signed_test_envelope(&identity, "urgent!!", 0);
        env.priority = "emergency".to_string();
        assert_eq!(fed::sign::verify_chain(&env), Ok(()));
        let sealed = seal_env_for(&env, &recipient_pub);

        let outcome = fed_sealed_ingress(&d, &node_id, sealed, "general".to_string());
        assert!(matches!(outcome, FedIngressOutcome::Accepted(_)));

        let store = d.store.lock().unwrap();
        let due = store.due_deliveries(Utc::now(), 10).unwrap();
        assert_eq!(due.len(), 2);
        assert!(
            due.iter()
                .all(|d| d.priority == relay_core::priority_rank("normal")),
            "every delivery row must be at the DEFAULT rank, never emergency's rank 0: {due:?}"
        );
        let stored = store.get_message(due[0].message_id).unwrap().unwrap();
        assert_eq!(
            stored.priority, "normal",
            "the stored envelope's priority class itself must be re-stamped to \"normal\""
        );
    }

    #[test]
    fn fed_sealed_ingress_per_peer_quota_denies_second_message_without_persisting() {
        let dir = tempfile::tempdir().unwrap();
        let identity = test_peer_identity(dir.path(), "peer");
        let node_id = identity.node_id();
        let mut cfg = fed_config("verified", 4, 86_400);
        cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let limits = crate::config::Limits {
            per_sender: crate::config::PerSender {
                messages_per_minute: 1,
                bytes_per_hour: 0,
            },
            ..Default::default()
        };
        let d = test_daemon_with_federation_and_limits(dir.path(), cfg, limits);
        let recipient_pub = crypto_box::PublicKey::from(d.sealed_key.public());

        let first_env = signed_test_envelope(&identity, "first", 0);
        let first_sealed = seal_env_for(&first_env, &recipient_pub);
        assert!(matches!(
            fed_sealed_ingress(&d, &node_id, first_sealed, "general".to_string()),
            FedIngressOutcome::Accepted(_)
        ));

        let before = metrics::RATELIMITED.load(std::sync::atomic::Ordering::Relaxed);
        let second_env = signed_test_envelope(&identity, "second, distinct body", 0);
        let second_sealed = seal_env_for(&second_env, &recipient_pub);
        let outcome = fed_sealed_ingress(&d, &node_id, second_sealed, "general".to_string());
        assert_eq!(outcome, FedIngressOutcome::Rejected("RATE_LIMITED"));
        assert!(metrics::RATELIMITED.load(std::sync::atomic::Ordering::Relaxed) > before);

        let store = d.store.lock().unwrap();
        // Only the first message's two deliveries -- the rate-limited
        // second message (per-peer quota, sealed sender is opaque) gets no
        // dead_letter row at all, mirroring fed_ingress's own category.
        assert_eq!(
            store.queue_counts().unwrap(),
            vec![("pending".to_string(), 2)]
        );
    }

    // ==== process_due_fed (design §5 egress, Task 5) =======================

    /// Registers a live federation connection under `peer_name` directly on
    /// `d.fed.conns` -- the same map `process_due_fed`'s connection lookup
    /// reads, and the same shape `fed::conn::register_up` (Task 4) would
    /// populate from a real handshake -- without needing an actual Noise
    /// connection or a `federation.peers[]` config entry for it (config's
    /// peer list is never consulted by `process_due_fed`'s connection
    /// lookup itself, only its `identity_exposure` field is).
    fn register_fed_conn(
        d: &Daemon,
        peer_name: &str,
        node_id: &str,
    ) -> mpsc::Receiver<fed::wire::Fed> {
        let (tx, rx) = mpsc::channel(8);
        d.fed.as_ref().unwrap().conns.lock().unwrap().insert(
            peer_name.to_string(),
            crate::fed::conn::PeerConn::new(tx, node_id.to_string(), Utc::now()),
        );
        rx
    }

    /// A locally-originated (never signed, `origin: None`) envelope from a
    /// `mocka:chan` source -- `process_due_fed`'s "sign it here" branch.
    fn local_env(native_ref: &str, body: &str) -> Envelope {
        let now = Utc::now();
        Envelope::new(
            Endpoint {
                protocol: "mocka".into(),
                endpoint: "chan".into(),
            },
            Sender {
                native_ref: native_ref.into(),
            },
            "text".into(),
            body.into(),
            now,
            now + CDuration::hours(1),
            8,
        )
    }

    /// Persists `env` and queues one `pending` delivery row under `route`,
    /// addressed to `fed:<dest_endpoint>` -- bypassing `fan_out_deliveries`
    /// entirely, so these tests can drive `process_due_fed` directly
    /// against a hand-picked `dest_endpoint` shape. Returns the delivery
    /// row's own id.
    ///
    /// `route` matters as of Task 4 (design §4, cycle H): `process_due_fed`
    /// resolves `security_mode` via `Daemon::route_cfg(&del.route)`, and
    /// (Task 4 review fix round 1, CRITICAL finding) a `route` that does
    /// NOT resolve to a current `RouteConfig` now fails closed
    /// (`ROUTE_CONFIG_MISSING` dead-letter, nothing sent) rather than
    /// defaulting to gateway -- so every test driving `process_due_fed`
    /// via this helper needs `route` to actually name a `RouteConfig` in
    /// the fixture. `queue_fed_delivery` below uses `"general"`, the
    /// fixture's one real route (`tests_support::test_daemon_full`,
    /// `security_mode: "gateway"` by default) -- pre-Task-4 tests used a
    /// deliberately-nonexistent `"outbound"` sentinel here (relying on the
    /// old "unknown route defaults to gateway" behavior the CRITICAL fix
    /// removed); `"general"` reproduces the same gateway-mode behavior
    /// through a route that genuinely exists instead.
    fn queue_fed_delivery_on_route(
        d: &Daemon,
        env: &Envelope,
        dest_endpoint: &str,
        route: &str,
    ) -> i64 {
        let now = Utc::now();
        let dest = Endpoint {
            protocol: FED_PROTOCOL.to_string(),
            endpoint: dest_endpoint.to_string(),
        };
        let store = d.store.lock().unwrap();
        store.insert_message(env).unwrap();
        store
            .insert_delivery(env.id, route, &dest, now, env.expires_at, 2)
            .unwrap()
    }

    fn queue_fed_delivery(d: &Daemon, env: &Envelope, dest_endpoint: &str) -> i64 {
        queue_fed_delivery_on_route(d, env, dest_endpoint, "general")
    }

    /// Sets `route_name`'s `security_mode` to `mode` via `apply_config`
    /// (design §3: live, no restart) -- the sealed-egress test fixture
    /// setup shared by every `process_due_fed_sealed` test below. Panics if
    /// `route_name` isn't in the fixture config, since that would silently
    /// test nothing (the tests using this always pair it with
    /// `queue_fed_delivery_on_route(.., route_name)`, see that function's
    /// doc comment for why the two must name the same route).
    fn set_route_security_mode(d: &Daemon, route_name: &str, mode: &str) {
        let mut cfg = d.cfg.read().unwrap().clone();
        let route = cfg
            .routes
            .iter_mut()
            .find(|r| r.name == route_name)
            .unwrap_or_else(|| panic!("route '{route_name}' not found in test fixture config"));
        route.security_mode = mode.to_string();
        d.apply_config(cfg);
    }

    fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn unwrap_envelope_frame(frame: fed::wire::Fed) -> (Envelope, String) {
        match frame {
            fed::wire::Fed::Envelope { env, target_route } => (*env, target_route),
            other => panic!("expected Fed::Envelope, got {other:?}"),
        }
    }

    fn unwrap_sealed_frame(frame: fed::wire::Fed) -> (fed::seal::SealedEnvelope, String) {
        match frame {
            fed::wire::Fed::Sealed {
                sealed,
                target_route,
            } => (sealed, target_route),
            other => panic!("expected Fed::Sealed, got {other:?}"),
        }
    }

    /// Builds and signs an `Advert` claiming `sealed_key_hex` as `node_id`'s
    /// sealed-routing key, ready to `upsert_peer_advert` -- the shared
    /// fixture for the sealed-egress "advert-learned key" test pair below.
    /// Minimal on everything else (`services`/`protocols` empty): only
    /// `security.sealed_key` matters to `resolve_sealed_key`.
    fn signed_sealed_key_advert(
        identity: &NodeIdentity,
        node_id: &str,
        sealed_key_hex: &str,
    ) -> fed::advert::Advert {
        fed::advert::sign(
            fed::advert::Advert {
                rf_version: 1,
                node_id: node_id.to_string(),
                name: "phoenix".into(),
                services: std::collections::BTreeMap::from([("federation".to_string(), true)]),
                protocols: std::collections::BTreeMap::new(),
                security: fed::advert::SecurityCaps {
                    translate: true,
                    signed: true,
                    sealed: true,
                    sealed_key: Some(sealed_key_hex.to_string()),
                },
                expires: (Utc::now() + CDuration::hours(1)).timestamp(),
                sig: Vec::new(),
            },
            identity,
        )
    }

    #[tokio::test]
    async fn process_due_fed_pseudonymous_default_wire_bytes_contain_alias_not_raw_ref() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_config("verified", 4, 86_400),
        ));
        let mut rx = register_fed_conn(&d, "phoenix", &format!("rf:{}", "11".repeat(32)));

        let env = local_env("!secret-ref", "hello federation");
        let raw_ref = env.sender.native_ref.clone();
        let expected_alias = d
            .aliaser
            .alias("mocka", &raw_ref, "fed:phoenix/regional-chat");

        let delivery_id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        let now = Utc::now();
        let before = metrics::FED_EGRESS.load(std::sync::atomic::Ordering::Relaxed);
        process_due(&d, del, now).await;

        let (sent_env, target_route) = unwrap_envelope_frame(
            rx.try_recv()
                .expect("process_due_fed must send a Fed::Envelope frame"),
        );
        assert_eq!(target_route, "regional-chat");
        assert_eq!(sent_env.sender.native_ref, expected_alias);
        assert_ne!(sent_env.sender.native_ref, raw_ref);

        // Sentinel (design §5, brief): the raw ref must not appear ANYWHERE
        // in the serialized wire bytes, not merely in the struct field this
        // test already checked above.
        let mut buf = Vec::new();
        ciborium::into_writer(&sent_env, &mut buf).unwrap();
        assert!(
            !bytes_contain(&buf, raw_ref.as_bytes()),
            "raw native ref must never reach the wire under identity_exposure: pseudonymous"
        );
        assert!(
            bytes_contain(&buf, expected_alias.as_bytes()),
            "the alias must actually be present in the wire bytes"
        );

        assert_eq!(
            sent_env.hops, 1,
            "hops must increment from the fixture's default of 0"
        );
        assert!(
            sent_env.origin.is_some(),
            "a locally-originated envelope must be origin-signed before it egresses"
        );
        assert_eq!(fed::sign::verify_chain(&sent_env), Ok(()),
            "the signature must verify against what was ACTUALLY sent (signed after pseudonymization)");

        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after.state, "attempting");
        assert!(
            metrics::FED_EGRESS.load(std::sync::atomic::Ordering::Relaxed) > before,
            "FED_EGRESS must increment on a successful send"
        );
    }

    #[tokio::test]
    async fn process_due_fed_full_mode_sends_the_raw_native_ref_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut fed_cfg = fed_config("verified", 4, 86_400);
        fed_cfg.identity_exposure = "full".into();
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        let mut rx = register_fed_conn(&d, "phoenix", &format!("rf:{}", "22".repeat(32)));

        let env = local_env("!raw-ref-stays-raw", "hi");
        let delivery_id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        let (sent_env, _) = unwrap_envelope_frame(rx.try_recv().unwrap());
        assert_eq!(
            sent_env.sender.native_ref, "!raw-ref-stays-raw",
            "identity_exposure: full is explicit opt-in to sending the raw ref"
        );
        assert!(sent_env.origin.is_some());
        assert_eq!(fed::sign::verify_chain(&sent_env), Ok(()));
    }

    /// The relay path (design §5, Task 5 binding logic): an envelope that
    /// arrives at `process_due_fed` ALREADY origin-signed (this daemon
    /// ingressed it from one peer and is forwarding it to another) must
    /// never be pseudonymized or re-signed here, even under the default
    /// `identity_exposure: pseudonymous` -- only a NEW attestation and the
    /// hop increment are this hop's to add.
    #[tokio::test]
    async fn process_due_fed_relayed_envelope_with_existing_origin_is_never_pseudonymized_or_resigned(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_config("verified", 4, 86_400),
        ));
        let mut rx = register_fed_conn(&d, "seattle", &format!("rf:{}", "33".repeat(32)));

        let origin_identity = test_peer_identity(dir.path(), "origin-gateway");
        let mut env = local_env("!never-touched", "relay me onward");
        env.origin = Some(fed::sign::sign_origin(&env, &origin_identity));
        fed::sign::append_attestation(&mut env, &origin_identity, Utc::now()).unwrap();
        env.hops = 1;
        assert_eq!(
            fed::sign::verify_chain(&env),
            Ok(()),
            "fixture sanity check"
        );
        let original_origin = env.origin.clone().unwrap();
        let original_attestation_count = env.attestations.len();

        let delivery_id = queue_fed_delivery(&d, &env, "seattle/regional-chat");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        let (sent_env, _) = unwrap_envelope_frame(rx.try_recv().unwrap());
        assert_eq!(sent_env.sender.native_ref, "!never-touched",
            "an already origin-signed envelope's ref must never be mutated, or its origin sig breaks");
        assert_eq!(sent_env.origin.as_ref().unwrap().node_id, original_origin.node_id,
            "origin must stay the ORIGIN gateway's identity, never overwritten by this daemon's own");
        assert_eq!(
            sent_env.origin.as_ref().unwrap().sig,
            original_origin.sig,
            "origin signature bytes must be byte-identical -- proof it was not recomputed"
        );
        assert_eq!(
            sent_env.attestations.len(),
            original_attestation_count + 1,
            "this hop appends exactly one new attestation on top of whatever was already there"
        );
        assert_eq!(
            sent_env.hops, 2,
            "hops increments by exactly one on top of the relayed value"
        );
        assert_eq!(fed::sign::verify_chain(&sent_env), Ok(()),
            "the full chain -- untouched origin + all attestations including this new one -- must verify");
    }

    // ==== process_due_fed sealed egress (design §4, SPEC §113.4, cycle H,
    // Task 4) ================================================================

    #[tokio::test]
    async fn process_due_fed_sealed_mode_produces_fed_sealed_frame_that_unseals_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let recipient_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let recipient_pub = recipient_secret.public_key();
        let node_id = format!("rf:{}", "44".repeat(32));

        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.sealed_key = Some(hex::encode(recipient_pub.to_bytes()));
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        set_route_security_mode(&d, "general", "sealed");
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let raw_ref = "!secret-ref";
        let raw_body = "SENTINEL-PLAINTEXT-BODY-must-never-appear-in-the-clear";
        let env = local_env(raw_ref, raw_body);
        let env_id = env.id;
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();

        let before = metrics::SEALED_EGRESS.load(std::sync::atomic::Ordering::Relaxed);
        process_due(&d, del, Utc::now()).await;

        let frame = rx
            .try_recv()
            .expect("process_due_fed must send a Fed::Sealed frame");
        let (sealed, target_route) = unwrap_sealed_frame(frame);
        assert_eq!(target_route, "regional-chat");
        assert_eq!(sealed.id, env_id.to_string());

        // Sentinel (design §113.4/§2): the raw body/ref must not appear
        // ANYWHERE in the serialized Fed::Sealed wire bytes -- sealing must
        // actually hide the sentinel/alias behind AEAD ciphertext, not just
        // leave it reachable via some other field.
        let mut buf = Vec::new();
        ciborium::into_writer(
            &fed::wire::Fed::Sealed {
                sealed: sealed.clone(),
                target_route: target_route.clone(),
            },
            &mut buf,
        )
        .unwrap();
        assert!(
            !bytes_contain(&buf, raw_body.as_bytes()),
            "the plaintext body must never reach the wire unsealed"
        );
        assert!(
            !bytes_contain(&buf, raw_ref.as_bytes()),
            "the raw native ref must never reach the wire under identity_exposure: pseudonymous"
        );

        // Round-trip: unseal with the recipient's own key, decode as an
        // Envelope, and the ENTIRE cycle-F signature chain must verify --
        // proof the sealed plaintext really is the full canonical envelope
        // (origin sig + attestations included), not merely the narrower
        // signing tuple.
        let opened = fed::seal::unseal(&sealed, &recipient_secret)
            .expect("must decrypt with the intended recipient's own sealed key");
        let decoded: Envelope = ciborium::from_reader(opened.as_slice())
            .expect("sealed plaintext must CBOR-decode as a full Envelope");
        assert_eq!(decoded.id, env_id);
        assert_eq!(
            decoded.body, raw_body,
            "no-transform: the unsealed body is the ORIGINAL, untruncated"
        );
        assert!(decoded.origin.is_some());
        assert_eq!(fed::sign::verify_chain(&decoded), Ok(()));

        assert!(
            metrics::SEALED_EGRESS.load(std::sync::atomic::Ordering::Relaxed) > before,
            "SEALED_EGRESS must increment on a successful sealed send"
        );
        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after.state, "attempting");
    }

    /// No-transform (design §4, SPEC §113.4): a route with BOTH
    /// `render.max_chars` and `render.tag` set is a `gateway`-mode config
    /// habit that must have zero effect once the route is `sealed` --
    /// `process_due_fed_sealed` never calls `transform::render`/
    /// `truncate_body`/`attachment_notes` at all, so the unsealed body must
    /// come back exactly as long as the original, never cut down to
    /// `max_chars`.
    #[tokio::test]
    async fn process_due_fed_sealed_mode_ignores_route_render_max_chars_body_is_untruncated() {
        let dir = tempfile::tempdir().unwrap();
        let recipient_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let recipient_pub = recipient_secret.public_key();
        let node_id = format!("rf:{}", "45".repeat(32));

        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.sealed_key = Some(hex::encode(recipient_pub.to_bytes()));
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        {
            let mut cfg = d.cfg.read().unwrap().clone();
            let route = cfg.routes.iter_mut().find(|r| r.name == "general").unwrap();
            route.security_mode = "sealed".to_string();
            route.render = crate::config::RenderConfig {
                tag: "alias".to_string(),
                max_chars: 16,
            };
            d.apply_config(cfg);
        }
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let long_body = "this body is deliberately much longer than sixteen characters and must \
                          survive sealing completely whole, with no truncation applied anywhere";
        assert!(long_body.chars().count() > 16, "fixture sanity check");
        let env = local_env("!ref", long_body);
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        let (sealed, _) = unwrap_sealed_frame(rx.try_recv().unwrap());
        let opened = fed::seal::unseal(&sealed, &recipient_secret).unwrap();
        let decoded: Envelope = ciborium::from_reader(opened.as_slice()).unwrap();
        assert_eq!(
            decoded.body, long_body,
            "route render.max_chars must never truncate a sealed route's body"
        );
    }

    #[tokio::test]
    async fn process_due_fed_sealed_mode_with_no_sealed_key_anywhere_dead_letters_no_sealed_key() {
        let dir = tempfile::tempdir().unwrap();
        let node_id = format!("rf:{}", "46".repeat(32));
        let mut fed_cfg = fed_config("verified", 4, 86_400);
        // No `sealed_key` config pin, and no advert stored for this peer
        // either -- `resolve_sealed_key` has NO source to draw from.
        fed_cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        set_route_security_mode(&d, "general", "sealed");
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let env = local_env("!ref", "body");
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        assert!(
            rx.try_recv().is_err(),
            "must never send unsealed when no sealed key is available (fail-closed)"
        );
        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after.state, "dead_letter");
        assert_eq!(after.reason.as_deref(), Some("NO_SEALED_KEY"));
    }

    #[tokio::test]
    async fn process_due_fed_sealed_mode_oversized_envelope_dead_letters_sealed_oversize_not_shrunk(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let recipient_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let recipient_pub = recipient_secret.public_key();
        let node_id = format!("rf:{}", "47".repeat(32));
        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.sealed_key = Some(hex::encode(recipient_pub.to_bytes()));
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        set_route_security_mode(&d, "general", "sealed");
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let huge_body = "x".repeat(SEALED_MAX_BYTES as usize + 1024);
        let env = local_env("!ref", &huge_body);
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        assert!(
            rx.try_recv().is_err(),
            "an oversized sealed envelope must be rejected at origin, never sent (not even shrunk)"
        );
        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after.state, "dead_letter");
        assert_eq!(after.reason.as_deref(), Some("SEALED_OVERSIZE"));
    }

    #[tokio::test]
    async fn process_due_fed_sealed_mode_uses_advert_learned_key_when_no_config_pin() {
        let dir = tempfile::tempdir().unwrap();
        let recipient_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let recipient_pub = recipient_secret.public_key();
        let peer_identity = test_peer_identity(dir.path(), "phoenix-node");
        let node_id = peer_identity.node_id();

        let mut fed_cfg = fed_config("verified", 4, 86_400);
        // No config-pinned sealed_key for this peer.
        fed_cfg.peers = vec![fed_peer_cfg("phoenix", &node_id, "verified")];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        set_route_security_mode(&d, "general", "sealed");

        let advert = signed_sealed_key_advert(
            &peer_identity,
            &node_id,
            &hex::encode(recipient_pub.to_bytes()),
        );
        let mut raw = Vec::new();
        ciborium::into_writer(&advert, &mut raw).unwrap();
        d.store
            .lock()
            .unwrap()
            .upsert_peer_advert(
                &node_id,
                &raw,
                "phoenix",
                Utc::now() + CDuration::hours(1),
                Utc::now(),
            )
            .unwrap();

        let mut rx = register_fed_conn(&d, "phoenix", &node_id);
        let env = local_env("!ref", "advert-learned-key body");
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        let (sealed, _) = unwrap_sealed_frame(rx.try_recv().expect("sealed frame expected"));
        let opened = fed::seal::unseal(&sealed, &recipient_secret)
            .expect("must decrypt with the advert-learned key");
        let decoded: Envelope = ciborium::from_reader(opened.as_slice()).unwrap();
        assert_eq!(decoded.body, "advert-learned-key body");
    }

    #[tokio::test]
    async fn process_due_fed_sealed_mode_config_pin_wins_over_a_disagreeing_advert_key() {
        let dir = tempfile::tempdir().unwrap();
        let correct_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let correct_pub = correct_secret.public_key();
        let wrong_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let wrong_pub = wrong_secret.public_key();

        let peer_identity = test_peer_identity(dir.path(), "phoenix-node-2");
        let node_id = peer_identity.node_id();

        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.sealed_key = Some(hex::encode(correct_pub.to_bytes())); // the config pin
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        set_route_security_mode(&d, "general", "sealed");

        // The peer's own advert claims a DIFFERENT (wrong) sealed_key.
        let advert =
            signed_sealed_key_advert(&peer_identity, &node_id, &hex::encode(wrong_pub.to_bytes()));
        let mut raw = Vec::new();
        ciborium::into_writer(&advert, &mut raw).unwrap();
        d.store
            .lock()
            .unwrap()
            .upsert_peer_advert(
                &node_id,
                &raw,
                "phoenix",
                Utc::now() + CDuration::hours(1),
                Utc::now(),
            )
            .unwrap();

        let mut rx = register_fed_conn(&d, "phoenix", &node_id);
        let env = local_env("!ref", "config-pin-wins body");
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        let (sealed, _) = unwrap_sealed_frame(rx.try_recv().unwrap());
        assert!(
            fed::seal::unseal(&sealed, &wrong_secret).is_err(),
            "must NOT have sealed to the disagreeing advert-learned key"
        );
        let opened = fed::seal::unseal(&sealed, &correct_secret)
            .expect("the config pin must win over a disagreeing advert-learned key");
        let decoded: Envelope = ciborium::from_reader(opened.as_slice()).unwrap();
        assert_eq!(decoded.body, "config-pin-wins body");
    }

    #[tokio::test]
    async fn process_due_fed_sealed_mode_ack_by_id_marks_delivery_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let recipient_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let recipient_pub = recipient_secret.public_key();
        let node_id = format!("rf:{}", "48".repeat(32));

        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.sealed_key = Some(hex::encode(recipient_pub.to_bytes()));
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        set_route_security_mode(&d, "general", "sealed");
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let env = local_env("!ref", "ack me");
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        let (sealed, _) = unwrap_sealed_frame(rx.try_recv().unwrap());
        assert_eq!(
            d.store
                .lock()
                .unwrap()
                .deliveries_for_id(delivery_id)
                .unwrap()
                .state,
            "attempting",
        );

        // The peer acks by the sealed header's `id` (the cleartext field a
        // receiver reads before ever decrypting) -- the same
        // `deliveries_for_fed_ack` lookup gateway-mode `Fed::Ack{id}`
        // already resolves against, unchanged.
        fed::conn::handle_fed_ack(&d, "phoenix", &sealed.id);

        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after.state, "delivered");
    }

    // ---- route-config-missing fail-closed (Task 4 review fix round 1,
    // CRITICAL: cleartext-downgrade finding) -----------------------------

    /// The reproduction: a delivery queued while its route was
    /// `security_mode: sealed` must NOT egress as a cleartext `Fed::
    /// Envelope` when that route is later removed from a live-reloaded
    /// config -- it must dead-letter `ROUTE_CONFIG_MISSING` and send
    /// NOTHING at all (neither `Fed::Envelope` nor `Fed::Sealed`).
    #[tokio::test]
    async fn process_due_fed_sealed_route_removed_before_send_dead_letters_route_config_missing_never_sends(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let recipient_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let recipient_pub = recipient_secret.public_key();
        let node_id = format!("rf:{}", "49".repeat(32));

        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.sealed_key = Some(hex::encode(recipient_pub.to_bytes()));
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        set_route_security_mode(&d, "general", "sealed");
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let env = local_env("!ref", "should never reach the wire either way");
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");

        // The route this delivery was queued under vanishes from config
        // BEFORE process_due ever runs -- a live PUT /v1/config reload, or
        // a restart against an edited config file (deliveries persist
        // across restarts).
        {
            let mut cfg = d.cfg.read().unwrap().clone();
            cfg.routes.retain(|r| r.name != "general");
            d.apply_config(cfg);
        }

        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        assert!(
            rx.try_recv().is_err(),
            "an unresolvable route's security posture is unknown -- NOTHING may be sent, \
             sealed or cleartext"
        );
        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after.state, "dead_letter");
        assert_eq!(after.reason.as_deref(), Some("ROUTE_CONFIG_MISSING"));
    }

    /// Same fail-closed posture for a `gateway`-mode delivery: an
    /// unresolvable route must dead-letter too, not fall back to sending
    /// cleartext just because gateway mode "has nothing to lose" -- the
    /// point is the daemon can no longer determine what posture this
    /// delivery was queued under, at all.
    #[tokio::test]
    async fn process_due_fed_gateway_route_removed_before_send_also_dead_letters_route_config_missing(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_config("verified", 4, 86_400),
        ));
        let mut rx = register_fed_conn(&d, "phoenix", &format!("rf:{}", "4a".repeat(32)));

        let env = local_env("!ref", "gateway body");
        // "general" is gateway-mode by default in the fixture -- no
        // `set_route_security_mode` call needed.
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");

        {
            let mut cfg = d.cfg.read().unwrap().clone();
            cfg.routes.retain(|r| r.name != "general");
            d.apply_config(cfg);
        }

        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        assert!(
            rx.try_recv().is_err(),
            "must never send cleartext when the route is gone"
        );
        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after.state, "dead_letter");
        assert_eq!(after.reason.as_deref(), Some("ROUTE_CONFIG_MISSING"));
    }

    /// The normal case, unaffected by the fix: a `del.route` that DOES
    /// resolve to a current `RouteConfig` still sends sealed/gateway
    /// exactly as before -- guards against the fix having overcorrected
    /// into dead-lettering everything.
    #[tokio::test]
    async fn process_due_fed_route_present_still_sends_sealed_and_gateway_as_before() {
        let dir = tempfile::tempdir().unwrap();
        let recipient_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let recipient_pub = recipient_secret.public_key();
        let node_id = format!("rf:{}", "4b".repeat(32));

        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.sealed_key = Some(hex::encode(recipient_pub.to_bytes()));
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));

        // Sealed, route present and unmolested.
        set_route_security_mode(&d, "general", "sealed");
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);
        let sealed_env = local_env("!ref", "sealed still works");
        let sealed_delivery =
            queue_fed_delivery_on_route(&d, &sealed_env, "phoenix/regional-chat", "general");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(sealed_delivery)
            .unwrap();
        process_due(&d, del, Utc::now()).await;
        let (sealed, _) = unwrap_sealed_frame(rx.try_recv().expect("sealed send must still work"));
        let opened = fed::seal::unseal(&sealed, &recipient_secret).unwrap();
        let decoded: Envelope = ciborium::from_reader(opened.as_slice()).unwrap();
        assert_eq!(decoded.body, "sealed still works");

        // Back to gateway, route present and unmolested.
        set_route_security_mode(&d, "general", "gateway");
        let gateway_env = local_env("!ref", "gateway still works");
        let gateway_delivery =
            queue_fed_delivery_on_route(&d, &gateway_env, "phoenix/regional-chat", "general");
        let del2 = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(gateway_delivery)
            .unwrap();
        process_due(&d, del2, Utc::now()).await;
        let (sent_env, _) =
            unwrap_envelope_frame(rx.try_recv().expect("gateway send must still work"));
        assert_eq!(sent_env.body, "gateway still works");
    }

    // ---- SEALED_MAX_BYTES margin (Task 4 review fix round 1, minor #2) --

    /// A body sized right at `SEALED_MAX_BYTES` must produce a serialized
    /// `Fed::Sealed` wire frame that still fits under `fed::noise::
    /// MAX_FRAME` -- proving `SEALED_OVERHEAD_MARGIN` actually covers the
    /// seal/frame overhead, not just that the pre-seal check fires at
    /// some boundary. Before the fix, a body at the (margin-less) ceiling
    /// produced a frame that exceeded `MAX_FRAME` and would have been
    /// rejected by `FedChannel::send_frame` AFTER `mark_attempting` had
    /// already run.
    #[tokio::test]
    async fn process_due_fed_sealed_mode_frame_at_the_size_ceiling_still_fits_under_max_frame() {
        let dir = tempfile::tempdir().unwrap();
        let recipient_secret = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let recipient_pub = recipient_secret.public_key();
        let node_id = format!("rf:{}", "4c".repeat(32));

        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.sealed_key = Some(hex::encode(recipient_pub.to_bytes()));
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        set_route_security_mode(&d, "general", "sealed");
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        // Leave slack for the rest of the envelope's own CBOR fields (id,
        // source, sender, kind, timestamps, priority, ...) so the TOTAL
        // canonical envelope size sits just under SEALED_MAX_BYTES, not
        // over it -- this test is about the margin between SEALED_MAX_BYTES
        // and MAX_FRAME, not a second oversize-rejection test.
        let body_len = SEALED_MAX_BYTES as usize - 4096;
        let body = "y".repeat(body_len);
        let env = local_env("!ref", &body);
        let delivery_id = queue_fed_delivery_on_route(&d, &env, "phoenix/regional-chat", "general");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        let frame = rx
            .try_recv()
            .expect("a body under SEALED_MAX_BYTES must still be sent");
        let (sealed, target_route) = unwrap_sealed_frame(frame);
        let mut wire_bytes = Vec::new();
        ciborium::into_writer(
            &fed::wire::Fed::Sealed {
                sealed,
                target_route,
            },
            &mut wire_bytes,
        )
        .unwrap();
        assert!(
            wire_bytes.len() as u64 <= u64::from(fed::noise::MAX_FRAME),
            "sealed wire frame ({} bytes) must fit under MAX_FRAME ({} bytes)",
            wire_bytes.len(),
            fed::noise::MAX_FRAME
        );

        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(
            after.state, "attempting",
            "must not have been oversize-rejected"
        );
    }

    #[tokio::test]
    async fn process_due_fed_retries_with_backoff_when_no_live_connection() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_config("verified", 4, 86_400),
        ));
        // Deliberately no `register_fed_conn` call: `d.fed` exists (the
        // `federation` block is configured) but no connection to "phoenix"
        // is registered -- never connected, or currently down.

        let env = local_env("!ref", "hello");
        let delivery_id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        let now = Utc::now();
        process_due(&d, del, now).await;

        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(
            after.state, "pending",
            "no connection => existing retry posture, never attempting"
        );
        assert!(after.next_attempt >= now + CDuration::seconds(5));
        assert_eq!(
            after.attempt_count, 0,
            "no send was ever attempted, so mark_attempting never ran"
        );
        // FED_EGRESS is a shared process-global counter (see fed_ingress's
        // own tests for the same constraint under parallel `cargo test`) --
        // not safely comparable to a captured "before" snapshot here.
        // `attempt_count` staying 0 on THIS row is the reliable,
        // per-Daemon proof that no send was ever attempted.
    }

    #[tokio::test]
    async fn process_due_fed_retries_when_the_peer_connections_channel_is_full() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_config("verified", 4, 86_400),
        ));
        let (tx, _rx) = mpsc::channel::<fed::wire::Fed>(1);
        tx.try_send(fed::wire::Fed::Ping {}).unwrap(); // fill the connection's one slot
        d.fed.as_ref().unwrap().conns.lock().unwrap().insert(
            "phoenix".to_string(),
            crate::fed::conn::PeerConn::new(tx, format!("rf:{}", "44".repeat(32)), Utc::now()),
        );

        let env = local_env("!ref", "hello");
        let delivery_id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        let now = Utc::now();
        process_due(&d, del, now).await;

        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(
            after.state, "pending",
            "a full connection channel must fall back to retry, not get stuck attempting forever"
        );
        assert!(after.next_attempt >= now + CDuration::seconds(5));
        assert_eq!(
            after.attempt_count, 1,
            "mark_attempting still ran once (before the send was even attempted)"
        );
    }

    // ==== process_due_fed egress budget (design §5, Task 3) ================

    #[tokio::test]
    async fn process_due_fed_budget_defers_the_second_send_and_bumps_metric() {
        let dir = tempfile::tempdir().unwrap();
        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let node_id = format!("rf:{}", "55".repeat(32));
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.messages_per_minute = 1;
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let env = local_env("!a", "one");
        let first_id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
        let second_id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
        let now = Utc::now();
        let before = metrics::BUDGET_DEFERRED.load(std::sync::atomic::Ordering::Relaxed);

        let del1 = d.store.lock().unwrap().deliveries_for_id(first_id).unwrap();
        process_due(&d, del1, now).await;
        let del2 = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(second_id)
            .unwrap();
        process_due(&d, del2, now).await;

        let after = metrics::BUDGET_DEFERRED.load(std::sync::atomic::Ordering::Relaxed);
        // process-global counter (same "monotonic-only" reasoning as every
        // other BUDGET_DEFERRED assertion in this file) -- the real,
        // race-free proof is the exactly-one-Send check below.
        assert!(
            after > before,
            "the second fed send within the minute must be budget-deferred"
        );

        rx.try_recv().expect("the first send must go through");
        assert!(
            matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "the budget-deferred second send must never have called try_send"
        );

        let first_after = d.store.lock().unwrap().deliveries_for_id(first_id).unwrap();
        assert_eq!(first_after.state, "attempting");
        let second_after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(second_id)
            .unwrap();
        assert_eq!(second_after.state, "pending", "deferred, not attempted");
        assert!(second_after.next_attempt >= now + CDuration::seconds(5));
    }

    /// `messages_per_minute: 0` (also `PeerConfig`'s own default for a peer
    /// with no explicit budget) is unlimited -- design §5's "0/absent =
    /// unlimited" -- and per `BudgetLimiter::allow`'s own fast path never
    /// even touches the limiter's map, so this also proves an unconfigured/
    /// unlimited peer's fed key never accumulates state.
    #[tokio::test]
    async fn process_due_fed_zero_messages_per_minute_is_unlimited() {
        let dir = tempfile::tempdir().unwrap();
        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let node_id = format!("rf:{}", "66".repeat(32));
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.messages_per_minute = 0;
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let env = local_env("!a", "hi");
        let now = Utc::now();
        for _ in 0..5 {
            let id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
            let del = d.store.lock().unwrap().deliveries_for_id(id).unwrap();
            process_due(&d, del, now).await;
        }
        for _ in 0..5 {
            rx.try_recv()
                .expect("an unlimited (messages_per_minute: 0) peer must never be budget-deferred");
        }
        assert!(d.budget_limiter.lock().unwrap().allow("fed/phoenix", 0, Instant::now()),
            "the 0 fast path never accumulates per-key state (mirrors BudgetLimiter::allow's own contract)");
    }

    /// The cycle-F priority ruling this task's brief calls out explicitly:
    /// UNLIKE the transport-budget check above (which lets priority-0/
    /// emergency deliveries skip the check entirely, `del.priority > 0`),
    /// federation egress has NO emergency lane at all -- an emergency
    /// envelope routed over a fed destination must still queue behind its
    /// peer's budget exactly like a normal-priority one.
    #[tokio::test]
    async fn process_due_fed_budget_has_no_priority_bypass_unlike_transport_budgets() {
        let dir = tempfile::tempdir().unwrap();
        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let node_id = format!("rf:{}", "88".repeat(32));
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.messages_per_minute = 1;
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let env = local_env("!a", "one");
        // First send (queue_fed_delivery's normal priority, 2) consumes the
        // peer's one-per-minute budget slot.
        let first_id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
        // Second send, EMERGENCY priority (0) -- queue_fed_delivery always
        // hardcodes priority 2, so this row is built directly.
        let dest = Endpoint {
            protocol: FED_PROTOCOL.to_string(),
            endpoint: "phoenix/regional-chat".to_string(),
        };
        let second_id = {
            let store = d.store.lock().unwrap();
            store.insert_message(&env).unwrap();
            store
                .insert_delivery(env.id, "general", &dest, Utc::now(), env.expires_at, 0)
                .unwrap()
        };

        let now = Utc::now();
        let del1 = d.store.lock().unwrap().deliveries_for_id(first_id).unwrap();
        process_due(&d, del1, now).await;
        let del2 = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(second_id)
            .unwrap();
        assert_eq!(
            del2.priority, 0,
            "sanity: this really is an emergency-priority row"
        );
        process_due(&d, del2, now).await;

        rx.try_recv()
            .expect("the first (normal-priority) send goes through");
        assert!(matches!(rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "an emergency-priority fed send must STILL be budget-deferred -- federation egress has \
             no emergency bypass lane (cycle-F priority ruling)");

        let second_after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(second_id)
            .unwrap();
        assert_eq!(second_after.state, "pending", "deferred even at priority 0");
    }

    /// Rebuild-on-apply (design §5 Task 3 binding): `Daemon::apply_config`
    /// resets `budget_limiter` to a fresh `BudgetLimiter::new()`
    /// unconditionally on every apply -- the SAME shared instance
    /// `process_due_fed`'s "fed/<peer_name>" keys live in, so a peer
    /// deferred in one window immediately gets a clean budget after any
    /// config apply, without needing `federation` itself to have changed.
    #[tokio::test]
    async fn fed_egress_budget_resets_on_apply_config() {
        let dir = tempfile::tempdir().unwrap();
        let mut fed_cfg = fed_config("verified", 4, 86_400);
        let node_id = format!("rf:{}", "77".repeat(32));
        let mut peer = fed_peer_cfg("phoenix", &node_id, "verified");
        peer.messages_per_minute = 1;
        fed_cfg.peers = vec![peer];
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg));
        let mut rx = register_fed_conn(&d, "phoenix", &node_id);

        let env = local_env("!a", "one");
        let first_id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
        let second_id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
        let now = Utc::now();

        let del1 = d.store.lock().unwrap().deliveries_for_id(first_id).unwrap();
        process_due(&d, del1, now).await;
        let del2 = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(second_id)
            .unwrap();
        process_due(&d, del2, now).await;

        let deferred = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(second_id)
            .unwrap();
        assert_eq!(
            deferred.state, "pending",
            "must be deferred before the reset"
        );
        rx.try_recv().expect("first send");
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        // Re-apply the SAME config: the point is that apply_config resets
        // budget_limiter unconditionally, not conditioned on `federation`
        // itself having changed.
        let cfg = d.cfg_snapshot(|c| c.clone());
        d.apply_config(cfg);

        let del2_again = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(second_id)
            .unwrap();
        process_due(&d, del2_again, now).await;
        rx.try_recv().expect(
            "after apply_config resets the budget, the previously-deferred send must go through",
        );
        let final_state = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(second_id)
            .unwrap();
        assert_eq!(final_state.state, "attempting");
    }

    /// The sliding-window semantics `process_due_fed`'s budget check relies
    /// on, exercised directly against `d.budget_limiter` under the EXACT
    /// "fed/<peer_name>" key shape that check constructs
    /// (`format!("fed/{peer_name}")`) -- same posture as `transport_budgets`'
    /// own window-rollover coverage in `limits.rs`
    /// (`budget_limiter_allows_n_then_denies_then_reallows_after_expiry`):
    /// real time never advances 61s inside a unit test, so this drives the
    /// limiter with synthetic `Instant`s instead of a real sleep -- exactly
    /// the same reason `process_due_fed`'s own budget check calls
    /// `Instant::now()` inline with no injectable clock, mirroring the
    /// pre-existing transport-budget check right above it in this file.
    #[test]
    fn fed_egress_budget_key_reallows_after_a_minute_rolls_over() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let t0 = Instant::now();
        let key = "fed/phoenix";
        assert!(d.budget_limiter.lock().unwrap().allow(key, 1, t0));
        assert!(
            !d.budget_limiter.lock().unwrap().allow(key, 1, t0),
            "second send within the same window must be denied"
        );
        assert!(
            d.budget_limiter
                .lock()
                .unwrap()
                .allow(key, 1, t0 + std::time::Duration::from_secs(61)),
            "a full minute later, the window must have rolled over"
        );
    }

    /// The binding integration test the brief calls for: an egress row
    /// inserted by `process_due_fed` must be findable by
    /// `Store::deliveries_for_fed_ack` AND actually marked delivered by the
    /// REAL `fed::conn::handle_fed_ack` -- not just asserted to match by
    /// string-format inspection. This is the single test proving the
    /// `Endpoint{protocol: "fed", endpoint: "<peer>/<route>"}` binding
    /// (Task 4 review) actually round-trips end to end between the two
    /// independently-implemented sides (egress writes it, Task 4's ack
    /// handler reads it back).
    #[tokio::test]
    async fn fed_egress_row_is_found_and_delivered_by_the_real_fed_ack_handler() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_config("verified", 4, 86_400),
        ));
        let mut rx = register_fed_conn(&d, "phoenix", &format!("rf:{}", "55".repeat(32)));

        let env = local_env("!ref", "round trip");
        let delivery_id = queue_fed_delivery(&d, &env, "phoenix/regional-chat");
        let del = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        process_due(&d, del, Utc::now()).await;

        let (sent_env, _) = unwrap_envelope_frame(rx.try_recv().unwrap());
        let after_send = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after_send.state, "attempting");

        // The lookup Task 4's real Ack handler performs, driven directly:
        // proves `process_due_fed`'s `dest_endpoint` write is EXACTLY what
        // `deliveries_for_fed_ack`'s `LIKE peer || '/%'` match expects.
        let found = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_fed_ack(sent_env.id, "phoenix")
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, delivery_id);

        let mut events_rx = d.events.subscribe();
        crate::fed::conn::handle_fed_ack(&d, "phoenix", &sent_env.id.to_string());

        let after_ack = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after_ack.state, "delivered");
        let ev = events_rx
            .try_recv()
            .expect("handle_fed_ack must emit a Delivery(delivered) event");
        match ev {
            Event::Delivery { state, .. } => assert_eq!(state, "delivered"),
            other => panic!("expected Delivery, got {other:?}"),
        }
    }
}
