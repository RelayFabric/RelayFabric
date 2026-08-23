//! Connection manager (design §1 conn lifecycle, §5 wire frames): binds an
//! optional Noise listener, dials configured peers, and drives each
//! connection's frame loop (read/write/ping/dead-timer/8h rekey) until it
//! ends, at which point an outbound connection is redialed with backoff.
//!
//! ARCHITECTURE NOTE (deviation from the brief's literal "per-conn writer
//! task drains mpsc" wording, documented rather than silent): `noise::
//! FedChannel::send_frame`/`recv_frame` both take `&mut self` and share one
//! `snow::TransportState` — the channel cannot be split into independent
//! read/write halves the way `tokio::net::TcpStream::into_split()` (used by
//! `plugins.rs`'s analogous connection loop) can. Rather than wrapping it in
//! an `Arc<tokio::sync::Mutex<_>>` shared by two spawned tasks (extra lock
//! contention, and a real deadlock-shape risk between a blocked read and a
//! blocked write), each connection runs as ONE task whose `run_conn` loop
//! `tokio::select!`s between: the next inbound frame, the next outbound
//! frame handed to it via `PeerConn.tx`'s `mpsc::Receiver` (this IS the
//! "drains mpsc" role, just not a separate OS-level task), and a ticker
//! that sends pings / checks the 90s dead timer / checks the 8h rekey
//! deadline. `PeerConn.tx` still fully decouples any OTHER task (e.g. the
//! delivery pump, Task 5) from this connection's own task: it sends into
//! the channel and returns immediately, never touching `FedChannel`
//! directly or waiting on this task's own progress.
//!
//! LOCK DISCIPLINE: `FedState.conns`'s `Mutex` is only ever locked for a
//! single insert/remove/clone-out, never held across an `.await` or while
//! acquiring `d.store`/`d.dedup`/`d.sender_limiter` — see `register_up`/
//! `register_down`/`configured_peer_name` below, each a single self-
//! contained statement.

use crate::config::{FederationConfig, PeerConfig};
use crate::engine::{self, Daemon};
use crate::events::Event;
use crate::fed::advert::{self, Advert};
use crate::fed::noise::{self, FedChannel, StaticKey};
use crate::fed::short_node_id;
use crate::fed::wire::Fed;
use crate::metrics;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
// `tokio::time::Instant`, NOT `std::time::Instant` (Task 4 review fix
// round 1): `run_conn`'s ping/rekey timing state must respect
// `tokio::time::pause`/`advance` so it's fake-clock-testable -- `std::
// time::Instant::now()` always reflects real wall-clock time regardless
// of a paused tokio clock, which would make `last_ping`/`started` here
// silently un-advanceable in a `#[tokio::test(start_paused = true)]`
// test. `tokio::time::interval`/`timeout` are already tokio-native and
// unaffected either way.
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// One live federation connection's write handle + metadata (design §1
/// interface, exact). `tx` is federation egress's send handle
/// (`engine::process_due_fed`, Task 5): looked up by peer name/node_id and
/// used to hand a `Fed::Envelope` to this connection's own task. `node_id`/
/// `connected_at` back `GET /v1/federation`'s `connected`/`last_seen`
/// fields (`admin::federation`, Task 5) -- read directly rather than
/// re-derived from whatever key this entry happens to be stored under in
/// `FedState.conns` (a configured peer's NAME vs an unconfigured
/// connection's raw node_id), so that lookup is uniform either way.
pub struct PeerConn {
    pub tx: mpsc::Sender<Fed>,
    pub node_id: String,
    pub connected_at: DateTime<Utc>,
    /// Which registration this entry belongs to (final-review I-2): a
    /// process-unique token allocated per `PeerConn` so `register_down`
    /// can prove the map entry it's about to remove is ITS OWN -- a stale
    /// teardown (a connection that lost/never had the key) must never
    /// evict a live successor registered under the same key. Private on
    /// purpose: only this module's register_up/register_down compare it.
    instance: u64,
}

impl PeerConn {
    pub fn new(tx: mpsc::Sender<Fed>, node_id: String, connected_at: DateTime<Utc>) -> Self {
        /// Monotonic per-process; never reused, so two `PeerConn`s can
        /// never share a token (relaxed ordering is enough: uniqueness,
        /// not cross-thread ordering, is all the guard needs).
        static NEXT_INSTANCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let instance = NEXT_INSTANCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            tx,
            node_id,
            connected_at,
            instance,
        }
    }
}

/// Federation runtime state on `Daemon` (design §1 interface, exact):
/// lives at `Daemon.fed: Option<FedState>`, `None` when the `federation`
/// config block is absent. Keyed by peer NAME for a connection to a
/// configured peer (whichever side dialed), or by raw `node_id` for an
/// inbound connection from a node this daemon has no `peers[]` entry for
/// -- see `configured_peer_name`.
pub struct FedState {
    pub conns: Mutex<HashMap<String, PeerConn>>,
}

// ---- tunables (design §1) -------------------------------------------------

const PING_INTERVAL: Duration = Duration::from_secs(30);
const DEAD_AFTER: Duration = Duration::from_secs(90);
const REKEY_INTERVAL: Duration = Duration::from_secs(8 * 3600);
/// Granularity of `run_conn`'s housekeeping tick (ping-due / rekey-deadline
/// checks) -- deliberately finer than `PING_INTERVAL` so a ping goes out
/// within `TICK` of being due, not up to a whole `PING_INTERVAL` late.
const TICK: Duration = Duration::from_secs(5);
/// Bound on how long a single `channel.send_frame` call (a ping, an Ack
/// reply, or a frame handed in via `PeerConn.tx`) may block (Task 4 review
/// fix round 1, DoS hardening): a peer that completes the Noise handshake
/// and then simply stops reading (a zero-window TCP peer, or one that
/// never drains its own read side) would otherwise stall `write_all`
/// forever -- and because `tokio::select!`'s chosen arm runs its body to
/// completion before the next iteration, a stalled write also starves the
/// SAME task's own dead-timer/ping/rekey checks (they never get polled
/// again either), wedging the task AND its socket permanently, and (for
/// an outbound connection) wedging `spawn_outbound`'s redial loop too,
/// since `admit_and_run` never returns.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard ceiling on concurrently-active inbound connections (design §1,
/// Task 4 review fix round 1, DoS hardening): completing a bare Noise
/// handshake is cheap for an attacker, but this daemon still pays a full
/// task + TCP socket for each one accepted -- unbounded acceptance lets a
/// connection-flood attacker with NO trust at all exhaust file
/// descriptors/memory before ever being evaluated against any policy. A
/// config knob is deferred to a later cycle; this is a fixed safety
/// ceiling, not yet an operator-tunable value.
const MAX_INBOUND_CONNS: usize = 64;

/// Bound on how long a Noise handshake may take before the connection is
/// dropped. Without it a peer that completes TCP but stalls mid-handshake
/// holds its inbound `Semaphore` permit for the whole task lifetime; enough
/// such slow-loris connections wedge all `MAX_INBOUND_CONNS` inbound slots and
/// deny federation to everyone (audit HIGH finding). Applied to both the
/// responder (inbound) and initiator (outbound, where a stalled peer would
/// otherwise wedge that peer's redial loop) sides.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

// ---- RFDP discovery tunables (design §2/§3, cycle G) ----------------------

/// Cap on a received `Fed::Advert`'s own serialized size -- NOT `noise::
/// MAX_FRAME`'s much larger 16MiB transport-level ceiling, a tighter bound
/// specific to how big a legitimate advert document should ever need to be
/// (design §2).
const ADVERT_MAX_BYTES: usize = 16 * 1024;
/// `advert::Advert::name`'s doc comment: "<=64 chars" (design §1).
const ADVERT_MAX_NAME_CHARS: usize = 64;
/// Clock-skew clamp (design §3): an advert claiming to expire further out
/// than this from `now` is accepted but clamped DOWN to it, never rejected
/// outright -- a generous TTL claim isn't itself evidence of a bad advert,
/// just something this receiver refuses to honor past a sane bound.
const ADVERT_MAX_FUTURE_SECS: i64 = 86_400;
/// Per-peer throttle for a rejected advert's warn log line -- the same
/// 1/min-per-peer shape as `engine::warn_pre_trust_rejection`, kept as its
/// own map (not shared with that one) so the log line reads correctly for
/// what it actually is ("federation advert rejected...") instead of
/// borrowing envelope-ingress wording for an unrelated frame type.
const ADVERT_REJECT_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Top-level entry point (called once from `main.rs` when
/// `cfg.federation.is_some()`): seeds the trust store from `fcfg` (design
/// §3: config wins over DB on load, re-seeded every boot), loads/creates
/// this node's persistent Noise static keypair
/// (`data_dir/fed_static.key`), then spawns the listener (if `fcfg.listen`
/// is set) and one outbound dialer task per configured peer. Never awaits
/// anything itself -- every task it spawns runs independently and this
/// function returns immediately, matching every other `main.rs` spawn
/// site's fire-and-forget shape.
pub fn spawn_federation(d: Arc<Daemon>, fcfg: FederationConfig) {
    let now = Utc::now();
    if let Err(e) = d.store.lock().unwrap().seed_federation_trust(&fcfg, now) {
        warn!(error = %e, "failed to seed federation trust store");
    }
    let key_path = d
        .cfg_snapshot(|c| c.node.data_dir.clone())
        .join("fed_static.key");
    let static_key = match StaticKey::load_or_create(&key_path) {
        Ok(k) => Arc::new(k),
        Err(e) => {
            warn!(error = %e, "failed to load/create federation static key; federation disabled");
            return;
        }
    };
    if let Some(addr) = fcfg.listen.clone() {
        let d = d.clone();
        let static_key = static_key.clone();
        tokio::spawn(async move { run_listener(d, addr, static_key).await });
    }
    for peer in fcfg.peers.clone() {
        let d = d.clone();
        let static_key = static_key.clone();
        tokio::spawn(async move { spawn_outbound(d, peer, static_key).await });
    }
}

async fn run_listener(d: Arc<Daemon>, addr: String, static_key: Arc<StaticKey>) {
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(addr, error = %e, "failed to bind federation listener");
            return;
        }
    };
    let bound = listener.local_addr().map(|a| a.to_string()).unwrap_or(addr);
    info!(addr = %bound, "federation listener bound");
    accept_loop(d, listener, static_key).await;
}

/// The accept loop itself, factored out from `run_listener`'s bind step so
/// a test can bind `127.0.0.1:0` (an OS-assigned ephemeral port) directly,
/// read the real bound address back via `TcpListener::local_addr`, and
/// drive this loop without going through `spawn_federation`'s config-driven
/// `addr: String` parsing -- see the listener smoke test below. Uses the
/// production `MAX_INBOUND_CONNS` cap; `accept_loop_with_cap` (below) is
/// the same loop with the cap as a parameter, for the accept-cap test.
async fn accept_loop(d: Arc<Daemon>, listener: TcpListener, static_key: Arc<StaticKey>) {
    accept_loop_with_cap(
        d,
        listener,
        static_key,
        MAX_INBOUND_CONNS,
        HANDSHAKE_TIMEOUT,
    )
    .await
}

/// Accepts connections up to `max_inbound` concurrently active at once
/// (a `tokio::sync::Semaphore` permit held for the FULL lifetime of each
/// accepted connection's task, not just its handshake -- design §1, Task
/// 4 review fix round 1): once every permit is taken, a newly-accepted
/// socket is dropped IMMEDIATELY, before any Noise handshake is even
/// attempted -- an attacker at the cap doesn't get to spend this daemon's
/// CPU on a handshake it was always going to refuse.
async fn accept_loop_with_cap(
    d: Arc<Daemon>,
    listener: TcpListener,
    static_key: Arc<StaticKey>,
    max_inbound: usize,
    handshake_timeout: Duration,
) {
    let permits = Arc::new(Semaphore::new(max_inbound));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    warn!(
                        cap = max_inbound,
                        "federation inbound connection cap reached, dropping"
                    );
                    drop(stream);
                    continue;
                };
                let d = d.clone();
                let static_key = static_key.clone();
                tokio::spawn(async move {
                    // Held for this task's entire lifetime (handshake +
                    // admit_and_run + run_conn); released automatically
                    // when the task ends, freeing the slot for the next
                    // accept.
                    let _permit = permit;
                    // Bound the handshake so a stalled peer can't hold this
                    // permit forever (slow-loris DoS); on timeout the task
                    // ends and the permit is freed for the next accept.
                    let hs = tokio::time::timeout(
                        handshake_timeout,
                        noise::handshake_responder(stream, &static_key, &d.identity),
                    )
                    .await;
                    match hs {
                        Ok(Ok((channel, node_id))) => {
                            // A configured peer that dials US is still keyed
                            // by its config `name` (matching whatever a live
                            // OUTBOUND connection to the same peer would use)
                            // -- see `deliveries_for_fed_ack`'s doc comment
                            // for why this matters.
                            let peer_key = configured_peer_name(&d, &node_id)
                                .unwrap_or_else(|| node_id.clone());
                            admit_and_run(d, channel, peer_key, node_id).await;
                        }
                        Ok(Err(e)) => warn!(error = %e, "federation inbound handshake failed"),
                        Err(_) => warn!("federation inbound handshake timed out"),
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "federation accept failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

/// The configured peer NAME whose `node_id` matches, if any -- a single
/// self-contained `cfg_snapshot` call (lock discipline: never held across
/// an await or another lock).
fn configured_peer_name(d: &Daemon, node_id: &str) -> Option<String> {
    d.cfg_snapshot(|c| {
        c.federation.as_ref().and_then(|f| {
            f.peers
                .iter()
                .find(|p| p.node_id == node_id)
                .map(|p| p.name.clone())
        })
    })
}

/// Whether a live connection is currently registered under `peer_key` --
/// a single self-contained lock scope (module lock discipline). Consulted
/// by `spawn_outbound` before each dial (final-review I-2): once ANY
/// connection (its own earlier dial, or an inbound one from the same peer)
/// holds the key, redialing is pure waste -- the new connection would only
/// be refused by `register_up`'s first-wins guard on one side or the
/// other. Checked per-attempt rather than once, so the dialer resumes
/// within one recheck interval of the live connection ending.
fn has_live_conn(d: &Daemon, peer_key: &str) -> bool {
    d.fed
        .as_ref()
        .is_some_and(|fed| fed.conns.lock().unwrap().contains_key(peer_key))
}

/// How often `spawn_outbound` rechecks a peer it's NOT dialing because a
/// live connection already covers it -- also the ceiling on how stale the
/// "someone else already holds this key" observation can get.
const DIAL_RECHECK: Duration = Duration::from_secs(5);

/// Outbound dialer for one configured peer (design §1): connects, drives
/// the initiator handshake with `expected_node_id` set (a peer presenting
/// a different identity than configured is dropped by `noise::
/// handshake_initiator` itself, before this function ever sees a channel),
/// runs the connection until it ends (naturally, or the 8h rekey deadline
/// inside `run_conn`), then redials. Backoff is exponential 1s..60s on any
/// failure to connect or handshake; a successful handshake resets it back
/// to 1s (still with at least a 1s pause before the next attempt, so a
/// peer that accepts-then-immediately-drops every connection can't spin
/// this loop hot). While `has_live_conn` reports the peer's key already
/// held (e.g. by an inbound connection from that same peer -- the crossed
/// mutual-listen case, final-review I-2), no dial is attempted at all;
/// the loop just rechecks every `DIAL_RECHECK`.
async fn spawn_outbound(d: Arc<Daemon>, peer: PeerConfig, static_key: Arc<StaticKey>) {
    let mut backoff = Duration::from_secs(1);
    loop {
        if has_live_conn(&d, &peer.name) {
            tokio::time::sleep(DIAL_RECHECK).await;
            continue;
        }
        let handshake_ok = match TcpStream::connect(&peer.addr).await {
            Ok(stream) => {
                // Bound the handshake so a peer that stalls mid-handshake
                // can't wedge this peer's redial loop.
                let hs = tokio::time::timeout(
                    HANDSHAKE_TIMEOUT,
                    noise::handshake_initiator(
                        stream,
                        &static_key,
                        &d.identity,
                        Some(&peer.node_id),
                    ),
                )
                .await;
                match hs {
                    Ok(Ok(channel)) => {
                        admit_and_run(d.clone(), channel, peer.name.clone(), peer.node_id.clone())
                            .await;
                        true
                    }
                    Ok(Err(e)) => {
                        warn!(peer = %peer.name, error = %e, "federation outbound handshake failed");
                        false
                    }
                    Err(_) => {
                        warn!(peer = %peer.name, "federation outbound handshake timed out");
                        false
                    }
                }
            }
            Err(e) => {
                warn!(peer = %peer.name, error = %e, "federation outbound connect failed");
                false
            }
        };
        backoff = if handshake_ok {
            Duration::from_secs(1)
        } else {
            (backoff * 2).min(Duration::from_secs(60))
        };
        tokio::time::sleep(backoff).await;
    }
}

/// Post-handshake admission (design §3/§1): a `blocked` peer's connection
/// is refused here even though the Noise handshake itself already
/// succeeded and the identity is cryptographically genuine (§112.7: trust
/// is about POLICY, not identity) -- the channel is simply dropped, no
/// frame ever flows. Otherwise records `seen` (never raises trust beyond
/// it, §112.7 MUST -- `record_seen`'s own `INSERT OR IGNORE` enforces
/// this), registers the connection (`register_up`, SSE `federation` event
/// and `relayfabric_federation_peer_up` gauge and `FedState.conns`
/// insert), runs the frame loop until it ends, then deregisters
/// (`register_down`, the symmetric down event/gauge/removal).
async fn admit_and_run<S>(d: Arc<Daemon>, channel: FedChannel<S>, peer_key: String, node_id: String)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let now = Utc::now();
    let blocked = d
        .store
        .lock()
        .unwrap()
        .trust_level(&node_id)
        .unwrap_or(None)
        .as_deref()
        == Some("blocked");
    if blocked {
        warn!(node = %display_peer_key(&node_id), "blocked federation peer dropped at handshake");
        return;
    }
    if let Err(e) = d.store.lock().unwrap().record_seen(&node_id, now) {
        warn!(error = %e, "failed to record federation peer as seen");
    }

    let (tx, rx) = mpsc::channel::<Fed>(64);
    let Some(instance) = register_up(&d, &peer_key, &node_id, now, tx) else {
        // Crossed dials (final-review I-2): a live connection already holds
        // this peer key -- mutual listen + mutual peering means A dialing B
        // while B dials A lands BOTH connections on the same key. Keep the
        // existing one, drop this one: returning here ends this task, so
        // the channel (and, for an inbound conn, its accept permit) is
        // released cleanly, and no down event/teardown ever fires for a
        // registration that never happened.
        debug!(peer = %display_peer_key(&peer_key),
            "federation connection for an already-connected peer dropped (crossed dial)");
        return;
    };
    run_conn(&d, channel, &peer_key, &node_id, rx).await;
    register_down(&d, &peer_key, instance);
}

/// SSE/metrics-safe rendering of a `FedState.conns` key: a configured
/// peer's `name` is already short and operator-chosen, so it's used
/// verbatim; a raw `rf:<64hex>` node_id (an unconfigured/inbound-only
/// connection) is shortened to its first-8-hex-chars form -- events.rs
/// privacy convention: no full node_id in an SSE payload or metric label
/// (a peer `name` can never itself start with `"rf:"`, since
/// `config::validate_federation` restricts it to `[a-z0-9-]`, which
/// excludes `:` -- an unambiguous discriminator).
fn display_peer_key(peer_key: &str) -> String {
    if peer_key.starts_with("rf:") {
        short_node_id(peer_key)
    } else {
        peer_key.to_string()
    }
}

/// Registers a new connection under `peer_key`, first-wins (final-review
/// I-2): if a live connection already holds the key, this one is REFUSED
/// (`None`) and the map is untouched -- never an overwrite, which is what
/// let crossed dials cascade (the first conn's teardown removing the
/// second, live, entry -- a perpetual flap). On success returns the new
/// `PeerConn`'s instance token, which the caller must hand back to
/// `register_down` so teardown is provably scoped to THIS registration.
#[must_use]
fn register_up(
    d: &Daemon,
    peer_key: &str,
    node_id: &str,
    now: DateTime<Utc>,
    tx: mpsc::Sender<Fed>,
) -> Option<u64> {
    let fed = d.fed.as_ref()?;
    let conn = PeerConn::new(tx, node_id.to_string(), now);
    let instance = conn.instance;
    {
        // Single self-contained lock scope (module lock discipline).
        let mut conns = fed.conns.lock().unwrap();
        if conns.contains_key(peer_key) {
            return None;
        }
        conns.insert(peer_key.to_string(), conn);
    }
    let label = display_peer_key(peer_key);
    metrics::set_federation_peer_up(&label, true);
    d.emit_event(|| Event::Federation {
        peer: label.clone(),
        up: true,
        ts: now,
    });
    info!(peer = %label, "federation connection up");
    Some(instance)
}

/// Tears down `peer_key`'s registration ONLY if the map entry still
/// belongs to the caller's own registration (`instance` matches -- see
/// `PeerConn.instance`). A stale teardown is a silent no-op: no removal,
/// no metric flip, no down event -- a live successor under the same key
/// must be completely unaffected.
fn register_down(d: &Daemon, peer_key: &str, instance: u64) {
    let Some(fed) = &d.fed else { return };
    let removed = {
        // Single self-contained lock scope (module lock discipline).
        let mut conns = fed.conns.lock().unwrap();
        if conns.get(peer_key).is_some_and(|c| c.instance == instance) {
            conns.remove(peer_key);
            true
        } else {
            false
        }
    };
    if !removed {
        return;
    }
    let label = display_peer_key(peer_key);
    metrics::set_federation_peer_up(&label, false);
    d.emit_event(|| Event::Federation {
        peer: label.clone(),
        up: false,
        ts: Utc::now(),
    });
    info!(peer = %label, "federation connection down");
}

/// The frame loop for one already-admitted connection (design §1 read
/// loop, §5 keepalive): drains `rx` (frames handed to this connection from
/// elsewhere in the daemon) and `channel`'s inbound frames concurrently,
/// sends a `Ping` every `PING_INTERVAL`, and closes the connection after
/// `REKEY_INTERVAL` since it started (design §1 "connections are torn
/// down and re-handshaken every 8h") -- see this module's top doc comment
/// for why this is one task rather than a split reader/writer pair.
///
/// I/O TIMEOUTS (Task 4 review fix round 1, DoS hardening; Task 2 review
/// fix round 1, correctness fix on the dead-timer below): every `send_fed`
/// call (ping, an Ack/Pong reply, or a frame handed in via `rx`) is
/// bounded by `SEND_TIMEOUT` inside `send_fed` itself -- timing out is
/// treated exactly like a stream error: the loop breaks, `admit_and_run`
/// deregisters, and (for an outbound connection) `spawn_outbound`'s redial
/// loop resumes -- see `SEND_TIMEOUT`'s doc comment for the wedge this
/// closes. The dead-peer detector is `last_activity` (a `tokio::time::
/// Instant`, set at connect and updated on every successful `recv_frame`)
/// checked against `DEAD_AFTER` from INSIDE the `tick` branch -- the same
/// "compare a stable `Instant` against the always-firing 5s tick" shape
/// `REKEY_INTERVAL`/`started` use. (A per-recv `timeout(DEAD_AFTER, ..)`
/// wrapper used to sit on `recv_frame` as a "backstop", but a `select!`
/// branch expression is reconstructed every iteration regardless of which
/// branch won, and the 5s tick always wins first -- its 90s budget could
/// never elapse, so it was removed as dead.)
async fn run_conn<S>(
    d: &Arc<Daemon>,
    mut channel: FedChannel<S>,
    peer_key: &str,
    node_id: &str,
    mut rx: mpsc::Receiver<Fed>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut last_ping = Instant::now();
    let started = Instant::now();
    // Dead-peer detector (see this function's doc comment). Set at
    // connect (a fresh connection that never receives anything must still
    // be dropped after `DEAD_AFTER`, not given an unlimited grace period),
    // and refreshed on every successful `recv_frame` regardless of whether
    // the bytes decode to a recognized `Fed` frame -- this is about
    // transport-level responsiveness, not frame validity.
    let mut last_activity = Instant::now();
    let mut tick = tokio::time::interval(TICK);
    tick.tick().await; // interval fires immediately on creation; consume that first tick

    // RFDP discovery, conn-up (design §2, cycle G): ask the peer for its
    // current advert, gated by the SAME scope check (`advert_scope_allows`)
    // that governs every other advert send/accept decision with this peer
    // -- `disabled` discovery never asks (and therefore never answers a
    // peer's own AdvertReq either, see `handle_frame`), `federation` only
    // asks a peer that already meets `accept_from`, `public` asks anyone
    // already on this authenticated connection. Runs for BOTH the
    // initiator and responder path, since `run_conn` is the one frame loop
    // shared by both (`admit_and_run`'s only caller of this function). A
    // send failure here is not specially handled: the loop below's own
    // recv/send error paths will observe and tear down the same broken
    // connection within one more iteration.
    if advert_scope_allows(d, node_id) {
        let _ = send_fed(&mut channel, &Fed::AdvertReq {}).await;
    }
    // Refresh timer (design §2: re-send at `advert_ttl_secs / 2` without
    // waiting for another `AdvertReq`), piggybacked on the existing `tick`
    // housekeeping cadence below -- the same "last_X.elapsed() >= INTERVAL"
    // shape `last_ping`/`PING_INTERVAL` already use, rather than a second
    // independent `tokio::select!` arm. Read once, at connection start
    // (matches `discovery`'s "daemon restart required" config posture --
    // see `Config::discovery`'s doc comment): a config edit landing mid-
    // connection takes effect on this connection's next 8h rekey, not
    // instantly.
    let advert_ttl_secs = d.cfg_snapshot(|c| c.discovery.advert_ttl_secs);
    let advert_refresh_interval = Duration::from_secs((advert_ttl_secs / 2).max(1));
    let mut last_advert_refresh = Instant::now();

    loop {
        tokio::select! {
            frame = channel.recv_frame() => {
                match frame {
                    Ok(bytes) => {
                        last_activity = Instant::now();
                        if let Ok(decoded) = ciborium::from_reader::<Fed, _>(bytes.as_slice()) {
                            if let Some(reply) = handle_frame(d, node_id, peer_key, decoded) {
                                if send_fed(&mut channel, &reply).await.is_err() { break; }
                            }
                        }
                        // a frame that isn't valid CBOR / doesn't match
                        // `Fed`'s shape is ignored -- the connection stays
                        // up (design §5's additive-versioning posture
                        // already tolerates an unrecognized-but-well-formed
                        // frame via `Fed::Unknown`; this is the same
                        // tolerance extended to outright garbage).
                    }
                    Err(_) => break, // stream error: EOF, decrypt failure, etc.
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(f) => { if send_fed(&mut channel, &f).await.is_err() { break; } }
                    None => break, // PeerConn's tx was dropped (deregistered)
                }
            }
            _ = tick.tick() => {
                if last_activity.elapsed() >= DEAD_AFTER {
                    warn!(peer = %peer_key, "federation connection silent for {DEAD_AFTER:?}, closing");
                    break;
                }
                if started.elapsed() > REKEY_INTERVAL {
                    info!(peer = %peer_key, "federation connection reached its rekey interval, closing");
                    break;
                }
                if last_ping.elapsed() >= PING_INTERVAL {
                    last_ping = Instant::now();
                    if send_fed(&mut channel, &Fed::Ping {}).await.is_err() { break; }
                }
                if last_advert_refresh.elapsed() >= advert_refresh_interval {
                    last_advert_refresh = Instant::now();
                    if advert_scope_allows(d, node_id) {
                        if let Some(advert) = build_signed_advert(d) {
                            metrics::inc(&metrics::ADVERT_TX);
                            if send_fed(&mut channel, &Fed::Advert { advert }).await.is_err() { break; }
                        }
                    }
                }
            }
        }
    }
}

/// Sends one `Fed` frame, bounded by `SEND_TIMEOUT` (see its doc comment
/// for why this exists) -- a timeout is surfaced as an `io::Error` just
/// like any other write failure, so every caller's existing
/// `.is_err() { break }` handling already covers it without change.
async fn send_fed<S: AsyncRead + AsyncWrite + Unpin>(
    channel: &mut FedChannel<S>,
    f: &Fed,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    ciborium::into_writer(f, &mut buf).map_err(std::io::Error::other)?;
    match tokio::time::timeout(SEND_TIMEOUT, channel.send_frame(&buf)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "federation send timed out",
        )),
    }
}

/// Dispatches one decoded frame (design §5): `Ping` -> `Pong` reply;
/// `Pong` -> nothing (keepalive reply, no further action); `Ack{id}` ->
/// resolves and marks the acknowledged delivery row(s) delivered
/// (`handle_fed_ack`), no reply; `Envelope{env, target_route}` ->
/// `engine::fed_ingress`, replying `Ack{id}` only on `Accepted` (design
/// §5: rejections are never acked, so a misbehaving/rejected sender's
/// retry machinery eventually gives up via its own TTL rather than being
/// told "yes" for something that was actually dropped); `Sealed{sealed,
/// target_route}` -> `engine::fed_sealed_ingress` (design §5/§113.2, cycle
/// H, Task 5): unseal -> verify_chain -> trust -> downgrade-refusal ->
/// dedup -> deliver, replying `Ack{id}` only on `Accepted` -- the exact
/// same "never ack a rejection" posture `Envelope` gets, above; `Unknown`
/// -> nothing (design §5 additive versioning: an unrecognized frame type
/// from a newer peer is silently ignored, not an error).
fn handle_frame(d: &Daemon, peer_node_id: &str, peer_key: &str, frame: Fed) -> Option<Fed> {
    match frame {
        Fed::Ping {} => Some(Fed::Pong {}),
        Fed::Pong {} => None,
        Fed::Ack { id } => {
            handle_fed_ack(d, peer_key, &id);
            None
        }
        Fed::Envelope { env, target_route } => {
            match engine::fed_ingress(d, peer_node_id, *env, target_route) {
                engine::FedIngressOutcome::Accepted(id) => Some(Fed::Ack { id: id.to_string() }),
                engine::FedIngressOutcome::Rejected(_) => None,
            }
        }
        Fed::AdvertReq {} => {
            if !advert_scope_allows(d, peer_node_id) {
                return None;
            }
            build_signed_advert(d).map(|advert| {
                metrics::inc(&metrics::ADVERT_TX);
                Fed::Advert { advert }
            })
        }
        Fed::Advert { advert } => {
            receive_advert(d, peer_node_id, advert);
            None
        }
        Fed::Sealed {
            sealed,
            target_route,
        } => match engine::fed_sealed_ingress(d, peer_node_id, sealed, target_route) {
            engine::FedIngressOutcome::Accepted(id) => Some(Fed::Ack { id: id.to_string() }),
            engine::FedIngressOutcome::Rejected(_) => None,
        },
        Fed::Unknown => None,
    }
}

// ---- RFDP discovery (design §2/§3, cycle G) -------------------------------

/// Whether this daemon's discovery config permits advert exchange with
/// `peer_node_id` right now -- shared by EVERY advert send/receive
/// decision (conn-up `AdvertReq`, the `AdvertReq` reply, the refresh
/// timer, and the receive-path trust gate: design's own "trust gate same
/// scope rule as sending"). `disabled` -> `false` always (never send,
/// never accept); `federation` -> the SAME `accept_from` comparison
/// `engine::fed_ingress` uses (`peer_node_id`'s stored trust level must
/// rank >= `federation.accept_from`); `public` -> `true` for any peer this
/// is even called about, since every caller already holds a live, Noise-
/// authenticated connection to `peer_node_id` -- "public" widens WHO among
/// already-handshaken peers qualifies, never the transport itself.
fn advert_scope_allows(d: &Daemon, peer_node_id: &str) -> bool {
    let mode = d.cfg_snapshot(|c| c.discovery.mode.clone());
    match mode.as_str() {
        "disabled" => false,
        "public" => true,
        "federation" => {
            let Some(accept_from) =
                d.cfg_snapshot(|c| c.federation.as_ref().map(|f| f.accept_from.clone()))
            else {
                // Federation config vanished from under a live connection
                // -- defensive, matches `fed_ingress`'s own posture for the
                // analogous case (fail closed, never open).
                return false;
            };
            let level = d
                .store
                .lock()
                .unwrap()
                .trust_level(peer_node_id)
                .unwrap_or(None);
            let level_str = level.as_deref().unwrap_or("unknown");
            engine::trust_rank(level_str) >= engine::trust_rank(&accept_from)
        }
        _ => false, // config::validate rejects any other mode; defensive.
    }
}

/// Builds and signs this node's current advert from the live config
/// snapshot (design §2: "built fresh from current cfg snapshot" on every
/// send, never cached). `None` when discovery is off
/// (`advert::build_from_config`'s own `mode == "disabled"` check) --
/// `advert_scope_allows` already keeps disabled-mode callers from ever
/// reaching this, so the two independently agree rather than one relying
/// on the other.
///
/// `pub(crate)` (not private): Task 3's `GET /v1/discovery` (`admin.rs`)
/// reuses this directly for the response's `our_advert` field, rather
/// than re-implementing "build + sign from cfg" a second time -- admin
/// must never show a DIFFERENT advert than what this daemon actually
/// sends peers over the wire.
pub(crate) fn build_signed_advert(d: &Daemon) -> Option<Advert> {
    let sealed_key_hex = hex::encode(d.sealed_key.public());
    let unsigned =
        d.cfg_snapshot(|c| advert::build_from_config(c, &d.node_id, &sealed_key_hex, Utc::now()))?;
    Some(advert::sign(unsigned, &d.identity))
}

/// Sanity gate on `services`/`protocols` map keys (Task 1 review binding
/// note): unlike `name` below (cosmetic -- sanitize and store), a garbage
/// key here is a REJECT of the whole advert, not a strip-and-store -- these
/// keys are meant to be short, machine-chosen protocol/service-class
/// identifiers (design §111.2: "chat"/"store_forward"/... , "lxmf", ...),
/// never the operator/attacker-influenced free text `name` is.
fn advert_keys_sane(advert: &Advert) -> bool {
    fn ok(k: &str) -> bool {
        !k.is_empty()
            && k.len() <= 32
            && k.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    }
    advert.services.keys().all(|k| ok(k.as_str()))
        && advert.protocols.keys().all(|k| ok(k.as_str()))
}

/// Unicode display-spoofing codepoints NOT covered by `char::is_control()`
/// (Task 2 review fix round 1, Important): bidi-control characters can
/// reorder how the REST of a name renders in a terminal/UI without
/// altering its bytes (e.g. an RLO before an otherwise-innocuous suffix
/// can make it display in reverse, disguising it), and default-ignorable
/// codepoints render invisibly but still occupy "characters" a naive
/// display/eyeball check would miss entirely. Hardcoded ranges rather than
/// pulling in a unicode-properties crate for the full `Bidi_Control`/
/// `Default_Ignorable_Code_Point` categories -- this is the complete,
/// deliberately narrow set a name field needs blocked, not a general
/// Unicode classifier: `\u{061C}` ALM, `\u{200E}`/`\u{200F}` LRM/RLM,
/// `\u{202A}`..=`\u{202E}` LRE/RLE/PDF/LRO/RLO, `\u{2066}`..=`\u{2069}`
/// LRI/RLI/FSI/PDI (bidi-control); `\u{200B}`..=`\u{200D}` ZWSP/ZWNJ/ZWJ,
/// `\u{FEFF}` BOM/ZWNBSP, `\u{2060}` word joiner (default-ignorable).
fn is_display_spoofing(c: char) -> bool {
    matches!(c,
        '\u{061C}'
            | '\u{200E}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200B}'..='\u{200D}'
            | '\u{FEFF}'
            | '\u{2060}')
}

/// Strips every Unicode control character plus the display-spoofing
/// codepoints above, and truncates to `ADVERT_MAX_NAME_CHARS` (Task 1
/// review binding ruling: an advert's `name` is UNTRUSTED even though the
/// advert is signed -- a signature proves WHO sent it, not that its
/// content is safe to print to a terminal or embed in a UI).
/// `char::is_control()` covers C0 (U+0000-U+001F, including the ESC byte
/// 0x1b that starts every ANSI escape sequence -- removing just that byte
/// reduces a CSI/OSC sequence to inert printable text, e.g.
/// `"\x1b[31mred"` -> `"[31mred"`, no longer an active escape once ESC is
/// gone), DEL (U+007F), and C1 (U+0080-U+009F); `is_display_spoofing`
/// (Task 2 review fix round 1) closes the gap `is_control()` leaves open
/// for RLO/LRO/isolates/ZWSP/BOM and friends, which are printable-per-
/// Unicode but exist specifically to misrepresent how the REST of a
/// string renders. Cosmetic-only (RULING): a name needing this is
/// stripped-and-stored, NOT grounds to reject the whole advert (unlike
/// `advert_keys_sane` above).
///
/// `pub(crate)` (not private): `advert_cbor` as stored by `upsert_peer_advert`
/// keeps the ORIGINAL, unsanitized `name` (see that function's doc comment
/// for why) -- so Task 3's admin/ctl surfaces, which decode `advert_cbor`
/// fresh on every serve to re-verify it, MUST call this again on whatever
/// `.name` they get back before ever rendering it. Idempotent: re-running
/// this over an already-sanitized string is a no-op.
pub(crate) fn sanitize_advert_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control() && !is_display_spoofing(*c))
        .take(ADVERT_MAX_NAME_CHARS)
        .collect()
}

/// Per-peer throttle map for `reject_advert`'s warn log line (mirrors
/// `engine::warn_pre_trust_rejection`'s shape, kept separate -- see
/// `ADVERT_REJECT_WARN_INTERVAL`'s doc comment for why).
static ADVERT_REJECT_WARN_THROTTLE: std::sync::LazyLock<
    Mutex<HashMap<String, std::time::Instant>>,
> = std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Bumps `ADVERT_REJECTED` and, at most once per peer per minute, warns
/// with `reason` -- called for every receive-path validation failure
/// below. NEVER persists anything (design §2: pre-trust posture, matches
/// `fed_ingress`'s `Persistence::NoPersist` -- an advert is only accepted
/// from a peer that ALREADY clears `advert_scope_allows`, but every check
/// before that gate is reachable by any peer that merely completed a bare
/// Noise handshake).
fn reject_advert(peer_node_id: &str, reason: &str) {
    metrics::inc(&metrics::ADVERT_REJECTED);
    if super::warn_throttle_due(
        &ADVERT_REJECT_WARN_THROTTLE,
        peer_node_id,
        ADVERT_REJECT_WARN_INTERVAL,
    ) {
        warn!(peer = %short_node_id(peer_node_id), reason,
            "federation advert rejected (not persisted; further repeats from this peer are \
             throttled to 1/min)");
    }
}

/// Receive-path validation chain for an inbound `Fed::Advert` (design §2,
/// mirrors `fed_ingress`'s gate-order posture): size cap -> node_id binds
/// to the CONNECTION's authenticated peer (an advert relayed for a third
/// party is rejected -- gossip is future work) -> signature verify ->
/// services/protocols key sanity -> expires freshness (stale rejected,
/// far-future clamped) -> the same scope/trust gate sending uses ->
/// sanitize `name` -> upsert. `advert_cbor` is stored as a fresh CBOR
/// re-encode of the verified struct, NOT the literal bytes read off the
/// wire (still independently signature-verifiable regardless -- see
/// `Store::upsert_peer_advert`'s doc comment for why) -- see that same
/// comment for why `name` is sanitized into its own column instead of by
/// mutating the stored document.
fn receive_advert(d: &Daemon, peer_node_id: &str, advert: Advert) {
    let mut raw = Vec::new();
    if ciborium::into_writer(&advert, &mut raw).is_err() || raw.len() > ADVERT_MAX_BYTES {
        reject_advert(peer_node_id, "OVERSIZED");
        return;
    }
    if advert.node_id != peer_node_id {
        reject_advert(peer_node_id, "NODE_ID_MISMATCH");
        return;
    }
    if advert::verify(&advert).is_err() {
        reject_advert(peer_node_id, "BAD_SIGNATURE");
        return;
    }
    if !advert_keys_sane(&advert) {
        reject_advert(peer_node_id, "INVALID_SHAPE");
        return;
    }
    let now = Utc::now();
    if advert.expires <= now.timestamp() {
        reject_advert(peer_node_id, "EXPIRED");
        return;
    }
    if !advert_scope_allows(d, peer_node_id) {
        reject_advert(peer_node_id, "TRUST_DENIED");
        return;
    }

    let clamped_expires = advert.expires.min(now.timestamp() + ADVERT_MAX_FUTURE_SECS);
    let expires_dt = DateTime::<Utc>::from_timestamp(clamped_expires, 0).unwrap_or(now);
    let sanitized_name = sanitize_advert_name(&advert.name);

    let result = d.store.lock().unwrap().upsert_peer_advert(
        &advert.node_id,
        &raw,
        &sanitized_name,
        expires_dt,
        now,
    );
    match result {
        Ok(()) => {
            metrics::inc(&metrics::ADVERT_RX);
            d.emit_event(|| Event::Advert {
                node_id: advert.node_id.clone(),
                name: sanitized_name.clone(),
                ts: now,
            });
        }
        Err(e) => warn!(error = %e, "failed to persist peer advert"),
    }
}

/// Resolves an inbound `Fed::Ack{id}` frame back to whichever local
/// delivery row(s) it acknowledges (design §5 egress: `Fed::Ack{id}` =>
/// delivered) and marks each delivered, state-guarded so a duplicate/late
/// Ack for an already-delivered row is inert -- both for the DB write
/// (`storage::Store::mark_delivered`'s own `WHERE state = 'attempting'`
/// guard) AND for the SSE `Delivery` event, which this function only
/// emits for a row it can see was actually still `attempting` (checked
/// BEFORE calling `mark_delivered`, so a replay -- whose freshly-queried
/// row is already `delivered` from the first Ack -- emits nothing the
/// second time either). `peer_key` is this connection's own
/// `FedState.conns` registration key -- see
/// `storage::Store::deliveries_for_fed_ack`'s doc comment for the scoping
/// rationale.
///
/// `pub(crate)` (not private): `engine`'s own egress round-trip test
/// (`fed_egress_row_is_found_and_delivered_by_the_real_fed_ack_handler`,
/// Task 5) drives this directly to prove `process_due_fed`'s
/// `dest_endpoint` format is EXACTLY what this function's own
/// `deliveries_for_fed_ack` lookup expects, end to end, rather than
/// asserting the two sides' string formats match by inspection alone.
pub(crate) fn handle_fed_ack(d: &Daemon, peer_key: &str, id: &str) {
    let Ok(message_id) = id.parse::<uuid::Uuid>() else {
        warn!(peer = %peer_key, "federation Ack carried a malformed envelope id");
        return;
    };
    let store = d.store.lock().unwrap();
    let rows = store
        .deliveries_for_fed_ack(message_id, peer_key)
        .unwrap_or_default();
    let mut delivered: Vec<(uuid::Uuid, String)> = Vec::new();
    for row in &rows {
        if row.state != "attempting" {
            continue; // already terminal (e.g. a replayed Ack) -- inert
        }
        match store.mark_delivered(row.id) {
            Ok(()) => delivered.push((row.message_id, row.route.clone())),
            Err(e) => {
                warn!(delivery = row.id, error = %e, "failed to persist federation delivery ack")
            }
        }
    }
    drop(store);
    for (message_id, route) in delivered {
        engine::emit_delivery(d, message_id, route, "delivered");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tests_support::test_daemon_with_federation;
    use crate::fed::noise::handshake_initiator;
    use relay_core::{Endpoint, Sender};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Distinct static-key/identity files per call within one test process
    /// (mirrors `fed/noise.rs`'s own `identity_pair` test helper).
    fn keypair(dir: &std::path::Path) -> (StaticKey, crate::node_identity::NodeIdentity) {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let key = StaticKey::load_or_create(&dir.join(format!("peer-static-{n}.key"))).unwrap();
        let identity = crate::node_identity::NodeIdentity::load_or_create(
            &dir.join(format!("peer-identity-{n}")),
        )
        .unwrap();
        (key, identity)
    }

    fn fed_cfg(peers: Vec<PeerConfig>, blocked: Vec<String>) -> FederationConfig {
        FederationConfig {
            listen: None,
            accept_from: "verified".into(),
            max_hops: 4,
            max_ttl_secs: 86_400,
            identity_exposure: "pseudonymous".into(),
            ingress_routes: vec!["general".into()],
            peers,
            trusted: vec![],
            blocked,
        }
    }

    // ---- blocked-at-handshake (duplex) ------------------------------------

    #[tokio::test]
    async fn blocked_peer_is_dropped_at_handshake_never_registers() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        let cfg = fed_cfg(vec![], vec![node_id.clone()]); // blocked
                                                          // test_daemon_with_federation seeds the trust store from `cfg`
                                                          // itself (mirroring spawn_federation's boot-time seeding), so the
                                                          // blocked list above is already in effect once this returns.
        let d = Arc::new(test_daemon_with_federation(dir.path(), cfg));

        let (a, b) = tokio::io::duplex(1 << 16);
        let (daemon_static, daemon_identity) = keypair(dir.path());
        let responder = tokio::spawn(async move {
            noise::handshake_responder(b, &daemon_static, &daemon_identity).await
        });
        let (client_channel, _server_node_id) = {
            let client = handshake_initiator(a, &peer_key, &peer_id, None)
                .await
                .unwrap();
            let (server_channel, server_node_id) = responder.await.unwrap().unwrap();
            let d2 = d.clone();
            tokio::spawn(async move {
                admit_and_run(d2, server_channel, node_id.clone(), node_id).await;
            });
            (client, server_node_id)
        };

        assert!(
            d.fed.as_ref().unwrap().conns.lock().unwrap().is_empty(),
            "a blocked peer must never be registered"
        );

        // The blocked side returns immediately without entering run_conn,
        // dropping the stream -- the client's next read must therefore
        // fail (EOF/reset), a deterministic completion signal.
        let mut client_channel = client_channel;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_channel.recv_frame(),
        )
        .await;
        assert!(result.is_ok(), "must not hang");
        assert!(
            result.unwrap().is_err(),
            "blocked peer's connection must be closed, not idle"
        );
    }

    // ---- SEEN recorded on successful handshake -----------------------------

    #[tokio::test]
    async fn unconfigured_peer_handshake_records_seen_and_emits_up_then_down() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        // No peers/trusted/blocked entry at all for this node_id.
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_cfg(vec![], vec![]),
        ));
        assert_eq!(d.store.lock().unwrap().trust_level(&node_id).unwrap(), None);

        let mut rx = d.events.subscribe();
        let (a, b) = tokio::io::duplex(1 << 16);
        let (daemon_static, daemon_identity) = keypair(dir.path());
        let responder = tokio::spawn(async move {
            noise::handshake_responder(b, &daemon_static, &daemon_identity).await
        });
        let mut client_channel = handshake_initiator(a, &peer_key, &peer_id, None)
            .await
            .unwrap();
        let (server_channel, server_node_id) = responder.await.unwrap().unwrap();
        assert_eq!(server_node_id, node_id);

        let d2 = d.clone();
        let conn_task = tokio::spawn(async move {
            admit_and_run(d2, server_channel, node_id.clone(), node_id).await
        });

        let up = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for the up event")
            .unwrap();
        match up {
            Event::Federation { up, .. } => assert!(up),
            other => panic!("expected Federation, got {other:?}"),
        }

        assert_eq!(
            d.store
                .lock()
                .unwrap()
                .trust_level(&peer_id.node_id())
                .unwrap()
                .as_deref(),
            Some("seen"),
            "a successful handshake from an unconfigured node must record 'seen'"
        );

        // Close the client side so the server's run_conn sees EOF and ends.
        let _ = client_channel.send_frame(b"").await; // best-effort, don't care if it errors
        drop(client_channel);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), conn_task).await;

        let down = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for the down event")
            .unwrap();
        match down {
            Event::Federation { up, .. } => assert!(!up),
            other => panic!("expected Federation, got {other:?}"),
        }
    }

    // ---- crossed-dial collision (final-review I-2) -------------------------

    /// Mutual listen + mutual peering: A dials B while B dials A, and both
    /// connections land on the SAME `FedState.conns` key. The FIRST live
    /// connection must win -- the second `register_up` is refused, never an
    /// overwrite (an overwrite is what set off the perpetual flap: the
    /// first conn's teardown then removed the second, live, entry).
    #[tokio::test]
    async fn crossed_register_up_keeps_the_first_connection_not_the_last() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![]));
        let node_id = format!("rf:{}", "11".repeat(32));
        let now = Utc::now();

        let (tx1, mut rx1) = mpsc::channel::<Fed>(4);
        let (tx2, mut rx2) = mpsc::channel::<Fed>(4);
        assert!(
            register_up(&d, "phoenix", &node_id, now, tx1).is_some(),
            "first registration must succeed"
        );
        assert!(
            register_up(&d, "phoenix", &node_id, now, tx2).is_none(),
            "second registration for a live key must be refused"
        );

        let conns = d.fed.as_ref().unwrap().conns.lock().unwrap();
        assert_eq!(conns.len(), 1);
        conns
            .get("phoenix")
            .unwrap()
            .tx
            .try_send(Fed::Ping {})
            .unwrap();
        drop(conns);
        assert!(
            rx1.try_recv().is_ok(),
            "the registered connection must still be the FIRST one -- \
             a crossed second registration must not displace a live conn"
        );
        assert!(rx2.try_recv().is_err());
    }

    /// Instance-guarded teardown: a `register_down` carrying a STALE
    /// instance token (a connection that no longer owns the map entry) must
    /// not evict the live successor holding the same key -- and must not
    /// emit a spurious `Federation{up:false}` event for it either. Only the
    /// down carrying the LIVE instance's own token removes the entry.
    #[tokio::test]
    async fn stale_register_down_does_not_evict_a_live_successor() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![]));
        let node_id = format!("rf:{}", "22".repeat(32));
        let now = Utc::now();

        let (tx1, _rx1) = mpsc::channel::<Fed>(4);
        let stale = register_up(&d, "phoenix", &node_id, now, tx1)
            .expect("first registration must succeed");
        // Simulate the first conn's entry being replaced by a successor
        // out from under it (the interleaving the instance guard defends
        // against): remove + re-register.
        d.fed
            .as_ref()
            .unwrap()
            .conns
            .lock()
            .unwrap()
            .remove("phoenix");
        let (tx2, _rx2) = mpsc::channel::<Fed>(4);
        let live = register_up(&d, "phoenix", &node_id, now, tx2)
            .expect("successor registration must succeed once the key is free");
        assert_ne!(
            stale, live,
            "each registration must get its own instance token"
        );

        let mut events = d.events.subscribe();
        register_down(&d, "phoenix", stale);
        assert!(
            d.fed
                .as_ref()
                .unwrap()
                .conns
                .lock()
                .unwrap()
                .contains_key("phoenix"),
            "a stale teardown must not evict the live successor"
        );
        assert!(
            events.try_recv().is_err(),
            "a stale teardown must not emit a Federation down event"
        );

        register_down(&d, "phoenix", live);
        assert!(
            d.fed.as_ref().unwrap().conns.lock().unwrap().is_empty(),
            "the live instance's own teardown must still remove the entry"
        );
        match events
            .try_recv()
            .expect("the live teardown must emit the down event")
        {
            Event::Federation { up, .. } => assert!(!up),
            other => panic!("expected Federation, got {other:?}"),
        }
    }

    /// The dialer-side half of the crossed-dial fix: `spawn_outbound`
    /// consults `has_live_conn` before each dial attempt so a peer whose
    /// key is already served by a live (e.g. inbound) connection isn't
    /// redialed over and over just to be refused by the far side's own
    /// admission guard.
    #[tokio::test]
    async fn has_live_conn_tracks_registration_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![]));
        assert!(!has_live_conn(&d, "phoenix"));

        let (tx, _rx) = mpsc::channel::<Fed>(4);
        let node_id = format!("rf:{}", "33".repeat(32));
        let instance = register_up(&d, "phoenix", &node_id, Utc::now(), tx).unwrap();
        assert!(has_live_conn(&d, "phoenix"));
        assert!(!has_live_conn(&d, "tucson"));

        register_down(&d, "phoenix", instance);
        assert!(!has_live_conn(&d, "phoenix"));
    }

    /// The full crossed-dial shape at the `admit_and_run` level (duplex, no
    /// TCP): while the first connection for a peer key is live, a second
    /// `admit_and_run` for the SAME key must drop its connection and return
    /// promptly (its remote side sees EOF) -- leaving the first connection
    /// registered and NOT emitting any down event for the shared key.
    #[tokio::test]
    async fn crossed_admit_and_run_drops_the_second_connection_and_keeps_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_cfg(vec![], vec![]),
        ));

        // First connection: full handshake, then parked in run_conn.
        let (peer1_key, peer1_id) = keypair(dir.path());
        let (a1, b1) = tokio::io::duplex(1 << 16);
        let (ds1, di1) = keypair(dir.path());
        let responder =
            tokio::spawn(async move { noise::handshake_responder(b1, &ds1, &di1).await });
        let _client1 = handshake_initiator(a1, &peer1_key, &peer1_id, None)
            .await
            .unwrap();
        let (server1, node1) = responder.await.unwrap().unwrap();
        let d2 = d.clone();
        tokio::spawn(async move { admit_and_run(d2, server1, "phoenix".to_string(), node1).await });
        // Wait until the first connection is actually registered.
        for _ in 0..100 {
            if d.fed
                .as_ref()
                .unwrap()
                .conns
                .lock()
                .unwrap()
                .contains_key("phoenix")
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let first_instance = d
            .fed
            .as_ref()
            .unwrap()
            .conns
            .lock()
            .unwrap()
            .get("phoenix")
            .unwrap()
            .instance;

        // Second connection, same peer key (the crossed dial).
        let mut events = d.events.subscribe();
        let (peer2_key, peer2_id) = keypair(dir.path());
        let (a2, b2) = tokio::io::duplex(1 << 16);
        let (ds2, di2) = keypair(dir.path());
        let responder =
            tokio::spawn(async move { noise::handshake_responder(b2, &ds2, &di2).await });
        let mut client2 = handshake_initiator(a2, &peer2_key, &peer2_id, None)
            .await
            .unwrap();
        let (server2, node2) = responder.await.unwrap().unwrap();
        let d3 = d.clone();
        let second =
            tokio::spawn(
                async move { admit_and_run(d3, server2, "phoenix".to_string(), node2).await },
            );

        // The second admit_and_run must return promptly (refused, not run) --
        // its client sees the channel closed rather than a live idle conn.
        tokio::time::timeout(std::time::Duration::from_secs(2), second)
            .await
            .expect("the crossed second connection must be dropped promptly, not kept running")
            .unwrap();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), client2.recv_frame()).await;
        assert!(result.is_ok(), "must not hang");
        assert!(
            result.unwrap().is_err(),
            "the second connection must be closed, not idle"
        );

        let conns = d.fed.as_ref().unwrap().conns.lock().unwrap();
        assert_eq!(
            conns.get("phoenix").map(|c| c.instance),
            Some(first_instance),
            "the FIRST connection must still be the registered one"
        );
        drop(conns);
        assert!(
            events.try_recv().is_err(),
            "dropping the refused second connection must not emit any Federation down event"
        );
    }

    // ---- ack exactly-once (state-guard replay) -----------------------------

    fn dest() -> Endpoint {
        Endpoint {
            protocol: "fed".into(),
            endpoint: "phoenix/general".into(),
        }
    }

    fn seed_attempting_fed_delivery(d: &Daemon) -> (uuid::Uuid, i64) {
        let now = Utc::now();
        let env = relay_core::Envelope::new(
            "mock:chan".parse().unwrap(),
            Sender {
                native_ref: "!a".into(),
            },
            "text".into(),
            "hello".into(),
            now,
            now + chrono::Duration::hours(1),
            8,
        );
        let store = d.store.lock().unwrap();
        store.insert_message(&env).unwrap();
        let delivery_id = store
            .insert_delivery(env.id, "general", &dest(), now, env.expires_at, 2)
            .unwrap();
        store.mark_attempting(delivery_id).unwrap();
        (env.id, delivery_id)
    }

    #[tokio::test]
    async fn fed_ack_marks_delivered_exactly_once_state_guarded_replay() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![]));
        let (message_id, delivery_id) = seed_attempting_fed_delivery(&d);

        let mut rx = d.events.subscribe();
        handle_fed_ack(&d, "phoenix", &message_id.to_string());

        let after_first = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after_first.state, "delivered");
        let ev = rx
            .try_recv()
            .expect("first Ack must emit a Delivery(delivered) event");
        match ev {
            Event::Delivery { state, .. } => assert_eq!(state, "delivered"),
            other => panic!("expected Delivery, got {other:?}"),
        }

        // Replay: same Ack again -- must not error, must not change
        // updated_at/state again, and must not emit a second event.
        let before_replay = after_first.updated_at;
        handle_fed_ack(&d, "phoenix", &message_id.to_string());
        let after_replay = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(after_replay.state, "delivered");
        assert_eq!(
            after_replay.updated_at, before_replay,
            "a replayed Ack must not touch an already-delivered row"
        );
        assert!(
            rx.try_recv().is_err(),
            "a replayed Ack must not emit a second Delivery event"
        );
    }

    #[test]
    fn fed_ack_with_malformed_id_is_ignored_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![]));
        handle_fed_ack(&d, "phoenix", "not-a-uuid"); // must not panic
    }

    #[test]
    fn fed_ack_for_a_different_peer_does_not_mark_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![]));
        let (message_id, delivery_id) = seed_attempting_fed_delivery(&d);

        handle_fed_ack(&d, "seattle", &message_id.to_string()); // wrong peer

        let after = d
            .store
            .lock()
            .unwrap()
            .deliveries_for_id(delivery_id)
            .unwrap();
        assert_eq!(
            after.state, "attempting",
            "an Ack from the wrong peer must not resolve the row"
        );
    }

    // ---- full wire round-trip: Fed::Envelope in, Fed::Ack out (duplex) ----

    #[tokio::test]
    async fn envelope_frame_over_the_wire_is_ingressed_and_acked() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        let mut cfg = fed_cfg(vec![], vec![]);
        cfg.peers = vec![PeerConfig {
            name: "phoenix".into(),
            node_id: node_id.clone(),
            addr: "10.0.0.2:47000".into(),
            trust: "verified".into(),
            messages_per_minute: 0,
            sealed_key: None,
        }];
        let d = Arc::new(test_daemon_with_federation(dir.path(), cfg));

        let (a, b) = tokio::io::duplex(1 << 16);
        let (daemon_static, daemon_identity) = keypair(dir.path());
        let responder = tokio::spawn(async move {
            noise::handshake_responder(b, &daemon_static, &daemon_identity).await
        });
        let mut client_channel = handshake_initiator(a, &peer_key, &peer_id, None)
            .await
            .unwrap();
        let (server_channel, server_node_id) = responder.await.unwrap().unwrap();

        let d2 = d.clone();
        tokio::spawn(async move {
            admit_and_run(d2, server_channel, "phoenix".to_string(), server_node_id).await
        });

        let now = Utc::now();
        let mut env = relay_core::Envelope::new(
            "mock:origin".parse().unwrap(),
            Sender {
                native_ref: "!remote".into(),
            },
            "text".into(),
            "hi from phoenix".into(),
            now,
            now + chrono::Duration::hours(1),
            8,
        );
        env.origin = Some(crate::fed::sign::sign_origin(&env, &peer_id));
        let env_id = env.id;
        let frame = Fed::Envelope {
            env: Box::new(env),
            target_route: "general".into(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&frame, &mut buf).unwrap();
        client_channel.send_frame(&buf).await.unwrap();

        let reply_bytes = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client_channel.recv_frame(),
        )
        .await
        .expect("timed out waiting for an Ack")
        .unwrap();
        let reply: Fed = ciborium::from_reader(reply_bytes.as_slice()).unwrap();
        match reply {
            Fed::Ack { id } => assert_eq!(id, env_id.to_string()),
            other => panic!("expected Ack, got {other:?}"),
        }

        let store = d.store.lock().unwrap();
        assert_eq!(
            store.queue_counts().unwrap(),
            vec![("pending".to_string(), 2)]
        );
    }

    // ---- TCP listener smoke test (design says: not exhaustive timing,
    // just "bind :0" wiring) ------------------------------------------------

    #[tokio::test]
    async fn federation_listener_binds_accepts_and_registers_over_real_tcp() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_cfg(vec![], vec![]),
        ));
        let mut rx = d.events.subscribe();

        let (daemon_static, _daemon_identity) = keypair(dir.path());
        let daemon_static = Arc::new(daemon_static);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let d2 = d.clone();
        tokio::spawn(async move { accept_loop(d2, listener, daemon_static).await });

        let stream = TcpStream::connect(addr).await.unwrap();
        let _client_channel = handshake_initiator(stream, &peer_key, &peer_id, None)
            .await
            .unwrap();

        let up = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for the up event over real TCP")
            .unwrap();
        match up {
            Event::Federation { peer, up, .. } => {
                assert!(up);
                assert_eq!(peer, short_node_id(&node_id));
            }
            other => panic!("expected Federation, got {other:?}"),
        }
        assert_eq!(d.fed.as_ref().unwrap().conns.lock().unwrap().len(), 1);
    }

    // ---- accept cap (Task 4 review fix round 1, DoS hardening) ------------

    #[tokio::test]
    async fn accept_loop_drops_connections_beyond_the_inbound_cap_before_any_handshake() {
        use tokio::io::AsyncReadExt;

        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_cfg(vec![], vec![]),
        ));
        let (daemon_static, _daemon_identity) = keypair(dir.path());
        let daemon_static = Arc::new(daemon_static);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Cap forced to 1 for this test (the production constant is 64). The
        // production handshake timeout (15s) far exceeds this test's ~2s
        // window, so the stalled first connection still holds its permit
        // throughout -- exactly the pre-timeout behavior this test asserts.
        tokio::spawn(async move {
            accept_loop_with_cap(d, listener, daemon_static, 1, HANDSHAKE_TIMEOUT).await
        });

        // First connection: never sends a single handshake byte, so the
        // spawned responder task blocks forever reading message 1 and
        // never releases its one permit for the rest of this test.
        let _hold = TcpStream::connect(addr).await.unwrap();
        // Give accept_loop_with_cap's own loop (not the spawned task) a
        // moment to accept it and synchronously acquire the permit --
        // that acquisition happens BEFORE the per-connection task is even
        // spawned, so this is a generous safety margin, not a
        // correctness requirement.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Second connection: accepted at the TCP level (the OS backlog
        // isn't the bottleneck, the semaphore is), but must be dropped
        // immediately -- no handshake attempted -- since the one permit
        // is already spent.
        let mut over_cap = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), over_cap.read(&mut buf)).await;
        assert!(
            result.is_ok(),
            "an over-cap connection must be closed promptly, not left hanging"
        );
        assert_eq!(result.unwrap().unwrap(), 0,
            "an over-cap connection must be closed with EOF and zero bytes (no handshake attempted)");
    }

    /// Slow-loris DoS (audit HIGH): a peer that completes TCP but stalls
    /// mid-handshake must NOT hold its inbound permit forever. With cap=1 and
    /// a short handshake timeout, a stalled connection frees its slot after
    /// the timeout, so a subsequent real handshake succeeds -- without the
    /// timeout the slot would be held permanently and this would hang.
    #[tokio::test]
    async fn a_stalled_handshake_frees_its_permit_after_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_cfg(vec![], vec![]),
        ));
        let (daemon_static, _daemon_identity) = keypair(dir.path());
        let daemon_static = Arc::new(daemon_static);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let short = std::time::Duration::from_millis(200);
        tokio::spawn(
            async move { accept_loop_with_cap(d, listener, daemon_static, 1, short).await },
        );

        // A stalls: connects, sends nothing, holds the single permit.
        let _stalled = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Wait past the handshake timeout so A's slot is reclaimed.
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        // A real handshake must now succeed -- proof the permit was freed.
        let stream = TcpStream::connect(addr).await.unwrap();
        let handshake = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            handshake_initiator(stream, &peer_key, &peer_id, None),
        )
        .await;
        let ok = matches!(handshake, Ok(Ok(_)));
        assert!(
            ok,
            "handshake after a stalled peer's timeout should succeed (permit must have been freed)"
        );
    }

    // ---- I/O timeouts, fake-clock (Task 4 review fix round 1, DoS
    // hardening: the wedge a zero-window/non-reading peer causes) ----------

    /// A test-only `AsyncRead + AsyncWrite` wrapper that behaves exactly
    /// like its inner stream until `stall_writes` is flipped, after which
    /// every `poll_write` returns `Poll::Pending` FOREVER (no waker is
    /// ever woken by the write itself) -- simulating a peer that stops
    /// reading from its own socket (a zero TCP receive window, or simply
    /// a connection whose reader is never driven again). Reads still pass
    /// through normally (this test only needs the SEND side to stall).
    struct StallWritesAfterHandshake<S> {
        inner: S,
        stall_writes: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for StallWritesAfterHandshake<S> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for StallWritesAfterHandshake<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.stall_writes.load(Ordering::Relaxed) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut this.inner).poll_write(cx, buf)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.stall_writes.load(Ordering::Relaxed) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut this.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// FAKE-CLOCK METHODOLOGY: `#[tokio::test(start_paused = true)]`
    /// pauses tokio's clock for both this test task AND any task it
    /// spawns on the same (default, single-threaded) test runtime.
    /// `tokio::time::advance` fast-forwards that shared virtual clock and
    /// drives the runtime far enough for any now-due timers to fire and
    /// wake their tasks. Two things had to change in `run_conn` itself for
    /// this to actually observe anything: `last_ping`/`started` had to be
    /// `tokio::time::Instant` (see the top-of-file import comment) --
    /// `std::time::Instant::now()` is NEVER affected by `pause`/`advance`,
    /// so a `run_conn` still using it would silently never notice the
    /// clock moving; and `tokio::time::interval`/`timeout` are tokio-
    /// native, so they were already advance-aware without any change.
    #[tokio::test(start_paused = true)]
    async fn stalled_write_is_torn_down_within_send_timeout_not_wedged_forever() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        let (daemon_static, daemon_identity) = keypair(dir.path());
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_cfg(vec![], vec![]),
        ));

        let (a, b) = tokio::io::duplex(1 << 16);
        let stall = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let wrapped_b = StallWritesAfterHandshake {
            inner: b,
            stall_writes: stall.clone(),
        };

        let responder = tokio::spawn(async move {
            noise::handshake_responder(wrapped_b, &daemon_static, &daemon_identity).await
        });
        let client_channel = handshake_initiator(a, &peer_key, &peer_id, None)
            .await
            .unwrap();
        let (server_channel, server_node_id) = responder.await.unwrap().unwrap();
        assert_eq!(server_node_id, node_id);

        // Handshake is done (needed real read/write in both directions);
        // NOW stop accepting writes on the daemon's outbound side, as if
        // the peer had gone silent / stopped draining its socket. The
        // client channel is intentionally never read from again either,
        // matching "a duplex peer that stops reading".
        stall.store(true, Ordering::Relaxed);
        drop(client_channel); // nothing left to read/write from the test's side

        // The connection's `FedState.conns` registration key -- this peer
        // isn't configured, so it's keyed by its own node_id (matching
        // `unconfigured_peer_handshake_records_seen_and_emits_up_then_down`'s
        // convention). Distinct from `peer_key: StaticKey` above (an
        // unfortunately-overloaded name shared with `keypair`'s own
        // destructuring elsewhere in this test module).
        let conn_registration_key = node_id.clone();
        let d2 = d.clone();
        let conn_task = tokio::spawn(async move {
            admit_and_run(d2, server_channel, conn_registration_key, node_id).await;
        });

        // Past PING_INTERVAL: run_conn's tick attempts to send a ping,
        // which now stalls forever at the (fake) OS level. Past
        // SEND_TIMEOUT on top of that: the send-side timeout must fire,
        // tearing the connection down -- all within virtual time, so this
        // assertion resolves near-instantly in real wall-clock time.
        tokio::time::advance(PING_INTERVAL + Duration::from_secs(1)).await;
        tokio::time::advance(SEND_TIMEOUT + Duration::from_secs(1)).await;

        let result = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        assert!(
            result.is_ok(),
            "the connection must be torn down, not wedged forever on a stalled write"
        );
        assert!(
            d.fed.as_ref().unwrap().conns.lock().unwrap().is_empty(),
            "a send-timed-out connection must deregister, exactly like any other closed connection"
        );
    }

    // ---- RFDP discovery (design §2/§3, cycle G) ---------------------------

    use chrono::Duration as ChronoDuration;
    use std::collections::BTreeMap;

    /// Test-only override of `d.cfg.discovery` -- `test_daemon_with_federation`
    /// always builds a `DiscoveryConfig::default()` (`mode: "disabled"`), so
    /// every test below that needs `federation`/`public` scope (or a short
    /// `advert_ttl_secs` for the refresh-timer fake-clock test) mutates it
    /// directly here rather than adding another `test_daemon_with_*`
    /// constructor for one field.
    fn set_discovery(d: &Daemon, mode: &str, advert_ttl_secs: u64) {
        d.cfg.write().unwrap().discovery = crate::config::DiscoveryConfig {
            mode: mode.to_string(),
            advert_ttl_secs,
        };
    }

    fn test_advert(node_id: &str, name: &str, expires: i64) -> Advert {
        Advert {
            rf_version: 1,
            node_id: node_id.to_string(),
            name: name.to_string(),
            services: BTreeMap::from([("federation".to_string(), true)]),
            protocols: BTreeMap::new(),
            security: advert::SecurityCaps {
                translate: true,
                signed: true,
                sealed: true,
                sealed_key: Some("22".repeat(32)),
            },
            expires,
            sig: Vec::new(),
        }
    }

    /// Full Noise handshake wiring shared by every wire-level advert test
    /// below: given a PRE-GENERATED `(peer_key, peer_id)` identity (so the
    /// caller can seed config/trust for that exact node_id BEFORE
    /// connecting -- `envelope_frame_over_the_wire_is_ingressed_and_acked`'s
    /// own pattern), spawns `admit_and_run` on the daemon side keyed
    /// `peer_key_str` and hands back the CLIENT-held channel the test
    /// drives by hand.
    async fn connect_for_advert_test(
        d: &Arc<Daemon>,
        dir: &std::path::Path,
        peer_key_str: &str,
        peer_key: &StaticKey,
        peer_id: &crate::node_identity::NodeIdentity,
    ) -> FedChannel<tokio::io::DuplexStream> {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (daemon_static, daemon_identity) = keypair(dir);
        let responder = tokio::spawn(async move {
            noise::handshake_responder(b, &daemon_static, &daemon_identity).await
        });
        let client_channel = handshake_initiator(a, peer_key, peer_id, None)
            .await
            .unwrap();
        let (server_channel, server_node_id) = responder.await.unwrap().unwrap();
        let d2 = d.clone();
        let peer_key_owned = peer_key_str.to_string();
        tokio::spawn(async move {
            admit_and_run(d2, server_channel, peer_key_owned, server_node_id).await
        });
        client_channel
    }

    /// A "verified"-trust daemon+config pair shared by most tests below: a
    /// single configured peer, `federation` discovery, generous TTL.
    fn advert_test_daemon_and_peer(
        dir: &std::path::Path,
    ) -> (
        Arc<Daemon>,
        StaticKey,
        crate::node_identity::NodeIdentity,
        String,
    ) {
        let (peer_key, peer_id) = keypair(dir);
        let node_id = peer_id.node_id();
        let mut cfg = fed_cfg(vec![], vec![]);
        cfg.peers = vec![PeerConfig {
            name: "phoenix".into(),
            node_id: node_id.clone(),
            addr: "10.0.0.2:47000".into(),
            trust: "verified".into(),
            messages_per_minute: 0,
            sealed_key: None,
        }];
        let d = Arc::new(test_daemon_with_federation(dir, cfg));
        set_discovery(&d, "federation", 3600);
        (d, peer_key, peer_id, node_id)
    }

    // ---- pure functions: name sanitization + key-charset sanity -----------

    #[test]
    fn sanitize_advert_name_strips_control_chars_and_truncates() {
        assert_eq!(sanitize_advert_name("hello"), "hello");
        // ESC bytes removed; the surrounding printable text (now inert,
        // no longer an active escape sequence) survives untouched.
        assert_eq!(sanitize_advert_name("\x1b[31mred\x1b[0m"), "[31mred[0m");
        assert_eq!(sanitize_advert_name("line1\nline2\r\n"), "line1line2");
        assert_eq!(sanitize_advert_name("null\x00byte"), "nullbyte");
        assert_eq!(
            sanitize_advert_name(&"x".repeat(100)).chars().count(),
            ADVERT_MAX_NAME_CHARS
        );
    }

    /// Task 2 review fix round 1 (Important): `char::is_control()` alone
    /// misses Unicode display-spoofing codepoints -- RLO (right-to-left
    /// override) can make the REST of a rendered name display reversed/
    /// disguised without changing its bytes, and ZWSP is invisible but
    /// still a "character". Neither is a `char::is_control()` control
    /// character, so both needed `is_display_spoofing`'s dedicated check.
    #[test]
    fn sanitize_advert_name_strips_bidi_and_ignorable_spoofing_codepoints() {
        // U+202E RLO + U+200B ZWSP interleaved with normal text -- only the
        // normal text must survive.
        let hostile = "safe\u{202E}\u{200B}name";
        let sanitized = sanitize_advert_name(hostile);
        assert_eq!(sanitized, "safename");
        assert!(!sanitized.contains('\u{202E}'));
        assert!(!sanitized.contains('\u{200B}'));

        // The rest of the hardcoded set, individually.
        for spoof in [
            '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
            '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{200C}', '\u{200D}', '\u{FEFF}',
            '\u{2060}',
        ] {
            let name = format!("a{spoof}b");
            assert_eq!(
                sanitize_advert_name(&name),
                "ab",
                "spoofing char {spoof:?} was not stripped"
            );
        }
    }

    #[test]
    fn advert_keys_sane_accepts_normal_service_and_protocol_names() {
        let mut a = test_advert("rf:00", "n", 1);
        a.services.insert("store_forward".to_string(), true);
        a.protocols.insert(
            "lxmf".to_string(),
            advert::ProtoCaps {
                rx: true,
                tx: true,
                text: true,
                files: false,
                max_payload: None,
            },
        );
        assert!(advert_keys_sane(&a));
    }

    #[test]
    fn advert_keys_sane_rejects_a_key_outside_the_expected_charset() {
        let mut a = test_advert("rf:00", "n", 1);
        a.services.insert("bad key!\x1b".to_string(), true);
        assert!(!advert_keys_sane(&a));
    }

    #[test]
    fn advert_keys_sane_rejects_an_empty_key() {
        let mut a = test_advert("rf:00", "n", 1);
        a.services.insert(String::new(), true);
        assert!(!advert_keys_sane(&a));
    }

    // ---- scope matrix (design §2, disabled/federation/public) -------------

    #[test]
    fn advert_scope_disabled_never_allows_any_peer() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![]));
        set_discovery(&d, "disabled", 3600);
        let node_id = format!("rf:{}", "44".repeat(32));
        d.store
            .lock()
            .unwrap()
            .seed_trust(&node_id, "trusted", Utc::now())
            .unwrap();
        assert!(
            !advert_scope_allows(&d, &node_id),
            "disabled discovery must never allow advert exchange, even with a fully trusted peer"
        );
    }

    #[test]
    fn advert_scope_federation_requires_accept_from_rank_a_merely_seen_peer_fails() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![])); // accept_from: verified
        set_discovery(&d, "federation", 3600);
        let seen_node = format!("rf:{}", "55".repeat(32));
        d.store
            .lock()
            .unwrap()
            .record_seen(&seen_node, Utc::now())
            .unwrap();
        assert!(
            !advert_scope_allows(&d, &seen_node),
            "a merely-seen peer must not pass federation-mode's accept_from gate"
        );
    }

    #[test]
    fn advert_scope_federation_allows_a_peer_meeting_accept_from() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![]));
        set_discovery(&d, "federation", 3600);
        let verified_node = format!("rf:{}", "66".repeat(32));
        d.store
            .lock()
            .unwrap()
            .seed_trust(&verified_node, "verified", Utc::now())
            .unwrap();
        assert!(advert_scope_allows(&d, &verified_node));
    }

    #[test]
    fn advert_scope_public_allows_even_a_merely_seen_peer() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![]));
        set_discovery(&d, "public", 3600);
        let seen_node = format!("rf:{}", "77".repeat(32));
        d.store
            .lock()
            .unwrap()
            .record_seen(&seen_node, Utc::now())
            .unwrap();
        assert!(
            advert_scope_allows(&d, &seen_node),
            "public scope must allow any authenticated peer, regardless of trust level"
        );
    }

    // ---- duplex wire-level exchange ----------------------------------------

    #[tokio::test]
    async fn advert_exchange_is_duplex_both_sides_send_and_receive() {
        let dir = tempfile::tempdir().unwrap();
        let (d, peer_key, peer_id, node_id) = advert_test_daemon_and_peer(dir.path());
        let mut client_channel =
            connect_for_advert_test(&d, dir.path(), "phoenix", &peer_key, &peer_id).await;

        // The server must proactively ask the client for its advert at
        // connect (design §2: each side sends AdvertReq).
        let first = tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame())
            .await
            .expect("timed out waiting for the server's AdvertReq")
            .unwrap();
        assert!(matches!(
            ciborium::from_reader::<Fed, _>(first.as_slice()).unwrap(),
            Fed::AdvertReq {}
        ));

        // Client answers with its OWN signed advert (node_id bound to this
        // connection's authenticated identity) -- the server must verify,
        // accept, and store it.
        let client_advert = advert::sign(
            test_advert(
                &node_id,
                "client-node",
                (Utc::now() + ChronoDuration::hours(1)).timestamp(),
            ),
            &peer_id,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(
            &Fed::Advert {
                advert: client_advert,
            },
            &mut buf,
        )
        .unwrap();
        client_channel.send_frame(&buf).await.unwrap();

        // Client also sends its own AdvertReq -- the server must answer
        // with its own valid, self-signed advert.
        let mut req = Vec::new();
        ciborium::into_writer(&Fed::AdvertReq {}, &mut req).unwrap();
        client_channel.send_frame(&req).await.unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame())
            .await
            .expect("timed out waiting for the server's advert reply")
            .unwrap();
        match ciborium::from_reader::<Fed, _>(reply.as_slice()).unwrap() {
            Fed::Advert { advert } => {
                assert_eq!(advert.node_id, d.node_id);
                assert!(advert::verify(&advert).is_ok());
                // Cycle H (design §1): the server's own live advert, over
                // the real wire path (build_signed_advert -> Fed::Advert),
                // must carry ITS OWN daemon's real sealed key -- not a
                // fixture, the actual `d.sealed_key.public()` this daemon
                // loaded/created at construction.
                assert!(advert.security.sealed);
                assert_eq!(
                    advert.security.sealed_key,
                    Some(hex::encode(d.sealed_key.public()))
                );
            }
            other => panic!("expected Advert, got {other:?}"),
        }

        // The server's receive path is async relative to this test; poll
        // briefly for the client's advert to land.
        let mut stored = Vec::new();
        for _ in 0..100 {
            stored = d
                .store
                .lock()
                .unwrap()
                .list_peer_adverts(Utc::now())
                .unwrap();
            if !stored.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            stored.len(),
            1,
            "the client's advert must be stored on the server side"
        );
        assert_eq!(stored[0].0, node_id);
    }

    #[tokio::test]
    async fn advert_from_a_third_party_node_id_is_rejected_not_stored() {
        let dir = tempfile::tempdir().unwrap();
        let (d, peer_key, peer_id, _node_id) = advert_test_daemon_and_peer(dir.path());
        let mut client_channel =
            connect_for_advert_test(&d, dir.path(), "phoenix", &peer_key, &peer_id).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame())
            .await
            .unwrap()
            .unwrap(); // the server's own initial AdvertReq

        // A DIFFERENT identity signs a perfectly valid advert for ITSELF,
        // but it arrives over a connection authenticated as `peer_id` --
        // an advert relayed for a third party.
        let (_third_key, third_party) = keypair(dir.path());
        let third_advert = advert::sign(
            test_advert(
                &third_party.node_id(),
                "impersonator",
                (Utc::now() + ChronoDuration::hours(1)).timestamp(),
            ),
            &third_party,
        );
        let before = metrics::ADVERT_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        let mut buf = Vec::new();
        ciborium::into_writer(
            &Fed::Advert {
                advert: third_advert,
            },
            &mut buf,
        )
        .unwrap();
        client_channel.send_frame(&buf).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let after = metrics::ADVERT_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            after > before,
            "ADVERT_REJECTED must bump for a third-party node_id"
        );
        let stored = d
            .store
            .lock()
            .unwrap()
            .list_peer_adverts(Utc::now())
            .unwrap();
        assert!(
            stored
                .iter()
                .all(|(nid, _, _)| nid != &third_party.node_id()),
            "a third-party advert must never be stored: {stored:?}"
        );
    }

    #[tokio::test]
    async fn advert_name_with_control_chars_is_sanitized_not_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (d, peer_key, peer_id, node_id) = advert_test_daemon_and_peer(dir.path());
        let mut client_channel =
            connect_for_advert_test(&d, dir.path(), "phoenix", &peer_key, &peer_id).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame())
            .await
            .unwrap()
            .unwrap();

        let mut events_rx = d.events.subscribe();
        let malicious_name = "\x1b[31mRED\x1b[0m\nline2\x00null";
        let advert = advert::sign(
            test_advert(
                &node_id,
                malicious_name,
                (Utc::now() + ChronoDuration::hours(1)).timestamp(),
            ),
            &peer_id,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&Fed::Advert { advert }, &mut buf).unwrap();
        client_channel.send_frame(&buf).await.unwrap();

        // NOT rejected: the SSE event fires (only happens on a successful
        // upsert) carrying the SANITIZED name -- no ANSI escape, no
        // newline, no NUL, matching `sanitize_advert_name`'s output
        // exactly.
        let ev = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
            .await
            .expect("timed out waiting for the Advert SSE event")
            .unwrap();
        match ev {
            Event::Advert {
                node_id: got_node,
                name,
                ..
            } => {
                assert_eq!(got_node, node_id);
                assert_eq!(name, sanitize_advert_name(malicious_name));
                assert!(
                    !name.contains('\x1b') && !name.contains('\n') && !name.contains('\0'),
                    "sanitized name must carry no control characters: {name:?}"
                );
            }
            other => panic!("expected Advert, got {other:?}"),
        }

        // The stored advert_cbor is a fresh CBOR re-encode of the verified
        // struct (Store::upsert_peer_advert's contract), not the literal
        // wire bytes -- but still independently re-verifiable, since the
        // signature covers canonical_bytes(advert), not this particular
        // CBOR encoding. Proving Task 3's planned "verify on serve"
        // re-check will succeed against it.
        let stored = d
            .store
            .lock()
            .unwrap()
            .list_peer_adverts(Utc::now())
            .unwrap();
        assert_eq!(stored.len(), 1);
        let decoded: Advert = ciborium::from_reader(stored[0].1.as_slice()).unwrap();
        assert_eq!(
            decoded.name, malicious_name,
            "advert_cbor's re-encode must preserve the original (unsanitized) name content"
        );
        assert!(
            advert::verify(&decoded).is_ok(),
            "stored advert_cbor must remain independently re-verifiable"
        );
    }

    #[tokio::test]
    async fn oversized_advert_is_rejected_before_verification() {
        let dir = tempfile::tempdir().unwrap();
        let (d, peer_key, peer_id, node_id) = advert_test_daemon_and_peer(dir.path());
        let mut client_channel =
            connect_for_advert_test(&d, dir.path(), "phoenix", &peer_key, &peer_id).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame())
            .await
            .unwrap()
            .unwrap();

        let huge_name = "x".repeat(20_000); // well over ADVERT_MAX_BYTES once CBOR-encoded
        let advert = advert::sign(
            test_advert(
                &node_id,
                &huge_name,
                (Utc::now() + ChronoDuration::hours(1)).timestamp(),
            ),
            &peer_id,
        );
        let before = metrics::ADVERT_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        let mut buf = Vec::new();
        ciborium::into_writer(&Fed::Advert { advert }, &mut buf).unwrap();
        client_channel.send_frame(&buf).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let after = metrics::ADVERT_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            after > before,
            "ADVERT_REJECTED must bump for an oversized advert"
        );
        assert!(d
            .store
            .lock()
            .unwrap()
            .list_peer_adverts(Utc::now())
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn stale_expires_advert_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (d, peer_key, peer_id, node_id) = advert_test_daemon_and_peer(dir.path());
        let mut client_channel =
            connect_for_advert_test(&d, dir.path(), "phoenix", &peer_key, &peer_id).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame())
            .await
            .unwrap()
            .unwrap();

        let advert = advert::sign(
            test_advert(
                &node_id,
                "stale",
                (Utc::now() - ChronoDuration::seconds(10)).timestamp(),
            ),
            &peer_id,
        );
        let before = metrics::ADVERT_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        let mut buf = Vec::new();
        ciborium::into_writer(&Fed::Advert { advert }, &mut buf).unwrap();
        client_channel.send_frame(&buf).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let after = metrics::ADVERT_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            after > before,
            "ADVERT_REJECTED must bump for an already-expired advert"
        );
        assert!(d
            .store
            .lock()
            .unwrap()
            .list_peer_adverts(Utc::now())
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn far_future_expires_is_clamped_not_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (d, peer_key, peer_id, node_id) = advert_test_daemon_and_peer(dir.path());
        let mut client_channel =
            connect_for_advert_test(&d, dir.path(), "phoenix", &peer_key, &peer_id).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame())
            .await
            .unwrap()
            .unwrap();

        let advert = advert::sign(
            test_advert(
                &node_id,
                "far-future",
                (Utc::now() + ChronoDuration::days(30)).timestamp(),
            ),
            &peer_id,
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&Fed::Advert { advert }, &mut buf).unwrap();
        client_channel.send_frame(&buf).await.unwrap();

        let mut found = false;
        for _ in 0..100 {
            if !d
                .store
                .lock()
                .unwrap()
                .list_peer_adverts(Utc::now())
                .unwrap()
                .is_empty()
            {
                found = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            found,
            "a far-future-expiring advert must be accepted (clamped), not rejected"
        );

        // Clamped to now + 24h: still present just under that horizon,
        // gone just past it -- proving the real 30-day claim was NOT
        // honored verbatim.
        assert_eq!(
            d.store
                .lock()
                .unwrap()
                .list_peer_adverts(Utc::now() + ChronoDuration::hours(23))
                .unwrap()
                .len(),
            1,
            "must still be unexpired just under the 24h clamp"
        );
        assert_eq!(
            d.store
                .lock()
                .unwrap()
                .list_peer_adverts(Utc::now() + ChronoDuration::hours(25))
                .unwrap()
                .len(),
            0,
            "must be expired just past the 24h clamp -- the 30-day claim was not honored"
        );
    }

    // ---- refresh timer, fake-clock (design §2: advert_ttl_secs / 2) -------

    /// Advances the (paused) tokio clock in `TICK`-sized steps rather than
    /// one big jump. `run_conn`'s housekeeping `tick.tick()` fires (and
    /// re-arms the `DEAD_AFTER` recv timeout, a fresh future each loop
    /// iteration) every `TICK`; stepping virtual time at that SAME
    /// granularity is the faithful way to drive a fake-clock test spanning
    /// many tick periods, rather than trusting one huge `advance()` jump to
    /// correctly fast-forward through every intermediate timer firing along
    /// the way -- a real flake was observed with a single 151s jump under
    /// full-suite parallel load (525-test run) that never reproduced with
    /// this stepped approach.
    async fn advance_in_ticks(total: Duration) {
        let mut remaining = total;
        while remaining > Duration::ZERO {
            let step = remaining.min(TICK);
            tokio::time::advance(step).await;
            remaining -= step;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn advert_refresh_timer_resends_after_ttl_over_two() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        let mut cfg = fed_cfg(vec![], vec![]);
        cfg.peers = vec![PeerConfig {
            name: "phoenix".into(),
            node_id: node_id.clone(),
            addr: "10.0.0.2:47000".into(),
            trust: "verified".into(),
            messages_per_minute: 0,
            sealed_key: None,
        }];
        let d = Arc::new(test_daemon_with_federation(dir.path(), cfg));
        set_discovery(&d, "federation", 300); // minimum allowed TTL -> 150s refresh interval

        let mut client_channel =
            connect_for_advert_test(&d, dir.path(), "phoenix", &peer_key, &peer_id).await;

        let first = tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            ciborium::from_reader::<Fed, _>(first.as_slice()).unwrap(),
            Fed::AdvertReq {}
        ));

        // Advance in PING_INTERVAL-sized steps (< DEAD_AFTER) toward the
        // 150s refresh point, replying to each server Ping with a Pong --
        // this test's own silence would otherwise trip the (correct, Task
        // 2 review fix round 1) dead-timer at 90s, well before the 150s
        // refresh ever gets a chance to fire.
        let mut refreshed = None;
        for _ in 0..10 {
            advance_in_ticks(PING_INTERVAL).await;
            let frame = tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame())
                .await
                .expect("timed out waiting for a frame")
                .unwrap();
            match ciborium::from_reader::<Fed, _>(frame.as_slice()).unwrap() {
                Fed::Advert { advert } => {
                    refreshed = Some(advert);
                    break;
                }
                Fed::Ping {} => {
                    let mut pong = Vec::new();
                    ciborium::into_writer(&Fed::Pong {}, &mut pong).unwrap();
                    client_channel.send_frame(&pong).await.unwrap();
                }
                other => panic!("unexpected frame while waiting for the refresh: {other:?}"),
            }
        }
        let advert = refreshed.expect("must have received a refreshed Advert within 10 rounds");
        assert_eq!(advert.node_id, d.node_id);
        assert!(advert::verify(&advert).is_ok());
    }

    // ---- dead timer (Task 2 review fix round 1: DEAD_AFTER regression) ----

    /// A peer that completes the Noise handshake and then sends nothing at
    /// all must be dropped once `last_activity` (untouched since connect)
    /// reaches `DEAD_AFTER`, checked from the `tick` branch -- NOT left
    /// alive indefinitely (the bug: a per-recv `timeout(DEAD_AFTER, ..)`
    /// alone can never elapse while the 5s housekeeping tick keeps
    /// recreating it first every iteration). Proves the FULL teardown
    /// chain: `conns` empties, the SSE `Federation{up:false}` event fires,
    /// and the client side observes the connection actually close.
    #[tokio::test(start_paused = true)]
    async fn silent_peer_is_torn_down_after_dead_after_with_no_recv_activity() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_cfg(vec![], vec![]),
        ));
        let mut events = d.events.subscribe();

        let (a, b) = tokio::io::duplex(1 << 16);
        let (daemon_static, daemon_identity) = keypair(dir.path());
        let responder = tokio::spawn(async move {
            noise::handshake_responder(b, &daemon_static, &daemon_identity).await
        });
        let mut client_channel = handshake_initiator(a, &peer_key, &peer_id, None)
            .await
            .unwrap();
        let (server_channel, server_node_id) = responder.await.unwrap().unwrap();
        assert_eq!(server_node_id, node_id);

        let conn_registration_key = node_id.clone();
        let d2 = d.clone();
        let conn_task = tokio::spawn(async move {
            admit_and_run(d2, server_channel, conn_registration_key, node_id).await;
        });

        let up = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("timed out waiting for the up event")
            .unwrap();
        assert!(
            matches!(up, Event::Federation { up: true, .. }),
            "expected Federation up, got {up:?}"
        );
        for _ in 0..100 {
            if d.fed.as_ref().unwrap().conns.lock().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            d.fed.as_ref().unwrap().conns.lock().unwrap().len(),
            1,
            "must be registered first"
        );

        // The client sends NOTHING from here on -- only the housekeeping
        // tick (which never itself counts as recv activity) drives virtual
        // time forward, stepped so as not to rely on one huge `advance()`
        // jump (see `advance_in_ticks`'s doc comment).
        advance_in_ticks(DEAD_AFTER + TICK + Duration::from_secs(1)).await;

        let result = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        assert!(
            result.is_ok(),
            "a silent peer must be torn down, not held forever"
        );
        assert!(
            d.fed.as_ref().unwrap().conns.lock().unwrap().is_empty(),
            "a dead-timed-out connection must deregister"
        );

        let down = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("timed out waiting for the down event")
            .unwrap();
        match down {
            Event::Federation { up, .. } => assert!(!up),
            other => panic!("expected Federation down event, got {other:?}"),
        }

        // The server sent a handful of pings before tearing down (none of
        // which the client read); drain past them to observe the real EOF.
        let mut observed_close = false;
        for _ in 0..20 {
            match tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame()).await {
                Ok(Err(_)) => {
                    observed_close = true;
                    break;
                }
                Ok(Ok(_)) => continue,
                Err(_) => panic!("timed out waiting to observe the connection close"),
            }
        }
        assert!(
            observed_close,
            "the client side must observe the connection close"
        );
    }

    /// The counterpart to the silent-peer test above: a peer that sends
    /// SOMETHING within every `DEAD_AFTER` window must NOT be dropped, even
    /// though the CUMULATIVE elapsed time across several such windows is
    /// well past `DEAD_AFTER` -- proving `last_activity` genuinely resets
    /// on each recv rather than the dead-check being a one-shot "time since
    /// connect" measurement.
    #[tokio::test(start_paused = true)]
    async fn active_peer_recv_within_each_window_is_not_dropped_by_dead_after() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_cfg(vec![], vec![]),
        ));

        let (a, b) = tokio::io::duplex(1 << 16);
        let (daemon_static, daemon_identity) = keypair(dir.path());
        let responder = tokio::spawn(async move {
            noise::handshake_responder(b, &daemon_static, &daemon_identity).await
        });
        let mut client_channel = handshake_initiator(a, &peer_key, &peer_id, None)
            .await
            .unwrap();
        let (server_channel, server_node_id) = responder.await.unwrap().unwrap();
        assert_eq!(server_node_id, node_id);

        let conn_registration_key = node_id.clone();
        let d2 = d.clone();
        let conn_task = tokio::spawn(async move {
            admit_and_run(d2, server_channel, conn_registration_key, node_id).await;
        });
        for _ in 0..100 {
            if d.fed.as_ref().unwrap().conns.lock().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut ping_buf = Vec::new();
        ciborium::into_writer(&Fed::Ping {}, &mut ping_buf).unwrap();

        // Three rounds of 40s (< DEAD_AFTER = 90s each), sending activity
        // every round -- cumulative elapsed time (120s) comfortably
        // exceeds DEAD_AFTER, but no SINGLE window between two consecutive
        // sends ever does.
        for round in 0..3 {
            advance_in_ticks(Duration::from_secs(40)).await;
            client_channel.send_frame(&ping_buf).await.unwrap();
            // Reading anything back proves the server's task actually
            // polled and processed this round's send -- the real
            // synchronization point (recv_frame blocks until the server
            // produces output), not a guess at how many scheduler passes
            // are enough.
            let frame = tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for a server reply in round {round}"))
                .unwrap();
            ciborium::from_reader::<Fed, _>(frame.as_slice())
                .unwrap_or_else(|_| panic!("undecodable frame in round {round}"));
        }

        assert!(
            !conn_task.is_finished(),
            "an active peer must not be torn down by the dead timer"
        );
        assert_eq!(
            d.fed.as_ref().unwrap().conns.lock().unwrap().len(),
            1,
            "an active peer's connection must remain registered"
        );
    }

    // ---- 8h rekey, fake-clock (carried from cycle F) -----------------------

    /// Carried from cycle F (design §1 "connections are torn down and
    /// re-handshaken every 8h"): the `started.elapsed() > REKEY_INTERVAL`
    /// teardown already exists in `run_conn` -- this proves it actually
    /// fires, mirroring `stalled_write_is_torn_down_within_send_timeout_
    /// not_wedged_forever`'s fake-clock methodology. Tearing the connection
    /// down (deregistering it from `FedState.conns`) is what lets
    /// `spawn_outbound`'s own redial loop re-handshake on the next attempt
    /// -- this test proves the teardown half; the redial loop itself is
    /// exercised elsewhere (`spawn_outbound`'s own tests).
    #[tokio::test(start_paused = true)]
    async fn connection_is_torn_down_after_the_8h_rekey_interval() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        let d = Arc::new(test_daemon_with_federation(
            dir.path(),
            fed_cfg(vec![], vec![]),
        ));

        let (a, b) = tokio::io::duplex(1 << 16);
        let (daemon_static, daemon_identity) = keypair(dir.path());
        let responder = tokio::spawn(async move {
            noise::handshake_responder(b, &daemon_static, &daemon_identity).await
        });
        let mut client_channel = handshake_initiator(a, &peer_key, &peer_id, None)
            .await
            .unwrap();
        let (server_channel, server_node_id) = responder.await.unwrap().unwrap();
        assert_eq!(server_node_id, node_id);

        let conn_registration_key = node_id.clone();
        let d2 = d.clone();
        let conn_task = tokio::spawn(async move {
            admit_and_run(d2, server_channel, conn_registration_key, node_id).await;
        });

        for _ in 0..100 {
            if d.fed.as_ref().unwrap().conns.lock().unwrap().len() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            d.fed.as_ref().unwrap().conns.lock().unwrap().len(),
            1,
            "must be registered first"
        );

        // Stay ACTIVE throughout (reply Pong to every server Ping) so the
        // dead timer (DEAD_AFTER = 90s, Task 2 review fix round 1) never
        // fires first -- this test exercises REKEY_INTERVAL specifically,
        // not the (separately fake-clock-tested) dead timer.
        let mut pong = Vec::new();
        ciborium::into_writer(&Fed::Pong {}, &mut pong).unwrap();
        let rounds = REKEY_INTERVAL.as_secs() / PING_INTERVAL.as_secs() + 5;
        let mut torn_down = false;
        for _ in 0..rounds {
            advance_in_ticks(PING_INTERVAL).await;
            match tokio::time::timeout(Duration::from_secs(2), client_channel.recv_frame()).await {
                Ok(Ok(_)) => {
                    let _ = client_channel.send_frame(&pong).await;
                }
                Ok(Err(_)) => {
                    torn_down = true;
                    break;
                } // EOF: rekey teardown reached
                Err(_) => panic!("timed out waiting for a frame or the connection to close"),
            }
        }
        assert!(
            torn_down,
            "the connection must be torn down at the 8h rekey deadline, not wedged"
        );

        let result = tokio::time::timeout(Duration::from_secs(5), conn_task).await;
        assert!(
            result.is_ok(),
            "the connection task must complete once torn down"
        );
        assert!(d.fed.as_ref().unwrap().conns.lock().unwrap().is_empty(),
            "a rekeyed connection must deregister, so spawn_outbound's redial loop can re-handshake");
    }
}
