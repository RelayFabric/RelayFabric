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
use crate::fed::noise::{self, FedChannel, StaticKey};
use crate::fed::wire::Fed;
use crate::fed::short_node_id;
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
        Self { tx, node_id, connected_at, instance }
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
    let key_path = d.cfg_snapshot(|c| c.node.data_dir.clone()).join("fed_static.key");
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
    accept_loop_with_cap(d, listener, static_key, MAX_INBOUND_CONNS).await
}

/// Accepts connections up to `max_inbound` concurrently active at once
/// (a `tokio::sync::Semaphore` permit held for the FULL lifetime of each
/// accepted connection's task, not just its handshake -- design §1, Task
/// 4 review fix round 1): once every permit is taken, a newly-accepted
/// socket is dropped IMMEDIATELY, before any Noise handshake is even
/// attempted -- an attacker at the cap doesn't get to spend this daemon's
/// CPU on a handshake it was always going to refuse.
async fn accept_loop_with_cap(
    d: Arc<Daemon>, listener: TcpListener, static_key: Arc<StaticKey>, max_inbound: usize,
) {
    let permits = Arc::new(Semaphore::new(max_inbound));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    warn!(cap = max_inbound, "federation inbound connection cap reached, dropping");
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
                    match noise::handshake_responder(stream, &static_key, &d.identity).await {
                        Ok((channel, node_id)) => {
                            // A configured peer that dials US is still keyed
                            // by its config `name` (matching whatever a live
                            // OUTBOUND connection to the same peer would use)
                            // -- see `deliveries_for_fed_ack`'s doc comment
                            // for why this matters.
                            let peer_key =
                                configured_peer_name(&d, &node_id).unwrap_or_else(|| node_id.clone());
                            admit_and_run(d, channel, peer_key, node_id).await;
                        }
                        Err(e) => warn!(error = %e, "federation inbound handshake failed"),
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
        c.federation
            .as_ref()
            .and_then(|f| f.peers.iter().find(|p| p.node_id == node_id).map(|p| p.name.clone()))
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
    d.fed.as_ref().is_some_and(|fed| fed.conns.lock().unwrap().contains_key(peer_key))
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
                match noise::handshake_initiator(stream, &static_key, &d.identity, Some(&peer.node_id))
                    .await
                {
                    Ok(channel) => {
                        admit_and_run(d.clone(), channel, peer.name.clone(), peer.node_id.clone())
                            .await;
                        true
                    }
                    Err(e) => {
                        warn!(peer = %peer.name, error = %e, "federation outbound handshake failed");
                        false
                    }
                }
            }
            Err(e) => {
                warn!(peer = %peer.name, error = %e, "federation outbound connect failed");
                false
            }
        };
        backoff = if handshake_ok { Duration::from_secs(1) } else { (backoff * 2).min(Duration::from_secs(60)) };
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
    let blocked =
        d.store.lock().unwrap().trust_level(&node_id).unwrap_or(None).as_deref() == Some("blocked");
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
    d: &Daemon, peer_key: &str, node_id: &str, now: DateTime<Utc>, tx: mpsc::Sender<Fed>,
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
    d.emit_event(|| Event::Federation { peer: label.clone(), up: true, ts: now });
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
    d.emit_event(|| Event::Federation { peer: label.clone(), up: false, ts: Utc::now() });
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
/// I/O TIMEOUTS (Task 4 review fix round 1, DoS hardening): EVERY
/// production channel I/O call is bounded -- `channel.recv_frame()` is
/// wrapped in `tokio::time::timeout(DEAD_AFTER, ..)` (this IS the dead
/// timer now, not a separate `last_rx`-elapsed check: a peer that's gone
/// silent for `DEAD_AFTER` fails this timeout directly), and every
/// `send_fed` call (ping, an Ack/Pong reply, or a frame handed in via
/// `rx`) is bounded by `SEND_TIMEOUT` inside `send_fed` itself. Either
/// timing out is treated exactly like a stream error: the loop breaks,
/// `admit_and_run` deregisters, and (for an outbound connection)
/// `spawn_outbound`'s redial loop resumes -- see `SEND_TIMEOUT`'s doc
/// comment for the wedge this closes.
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
    let mut tick = tokio::time::interval(TICK);
    tick.tick().await; // interval fires immediately on creation; consume that first tick

    loop {
        tokio::select! {
            frame = tokio::time::timeout(DEAD_AFTER, channel.recv_frame()) => {
                match frame {
                    Ok(Ok(bytes)) => {
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
                    Ok(Err(_)) => break, // stream error: EOF, decrypt failure, etc.
                    Err(_) => {
                        warn!(peer = %peer_key, "federation connection silent for {DEAD_AFTER:?}, closing");
                        break;
                    }
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(f) => { if send_fed(&mut channel, &f).await.is_err() { break; } }
                    None => break, // PeerConn's tx was dropped (deregistered)
                }
            }
            _ = tick.tick() => {
                if started.elapsed() > REKEY_INTERVAL {
                    info!(peer = %peer_key, "federation connection reached its rekey interval, closing");
                    break;
                }
                if last_ping.elapsed() >= PING_INTERVAL {
                    last_ping = Instant::now();
                    if send_fed(&mut channel, &Fed::Ping {}).await.is_err() { break; }
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
    channel: &mut FedChannel<S>, f: &Fed,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    ciborium::into_writer(f, &mut buf).map_err(std::io::Error::other)?;
    match tokio::time::timeout(SEND_TIMEOUT, channel.send_frame(&buf)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "federation send timed out")),
    }
}

/// Dispatches one decoded frame (design §5): `Ping` -> `Pong` reply;
/// `Pong` -> nothing (keepalive reply, no further action); `Ack{id}` ->
/// resolves and marks the acknowledged delivery row(s) delivered
/// (`handle_fed_ack`), no reply; `Envelope{env, target_route}` ->
/// `engine::fed_ingress`, replying `Ack{id}` only on `Accepted` (design
/// §5: rejections are never acked, so a misbehaving/rejected sender's
/// retry machinery eventually gives up via its own TTL rather than being
/// told "yes" for something that was actually dropped); `Unknown` ->
/// nothing (design §5 additive versioning: an unrecognized frame type
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
        Fed::Unknown => None,
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
    let rows = store.deliveries_for_fed_ack(message_id, peer_key).unwrap_or_default();
    let mut delivered: Vec<(uuid::Uuid, String)> = Vec::new();
    for row in &rows {
        if row.state != "attempting" {
            continue; // already terminal (e.g. a replayed Ack) -- inert
        }
        match store.mark_delivered(row.id) {
            Ok(()) => delivered.push((row.message_id, row.route.clone())),
            Err(e) => warn!(delivery = row.id, error = %e, "failed to persist federation delivery ack"),
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
        let identity =
            crate::node_identity::NodeIdentity::load_or_create(&dir.join(format!("peer-identity-{n}")))
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
            let client = handshake_initiator(a, &peer_key, &peer_id, None).await.unwrap();
            let (server_channel, server_node_id) = responder.await.unwrap().unwrap();
            let d2 = d.clone();
            tokio::spawn(async move {
                admit_and_run(d2, server_channel, node_id.clone(), node_id).await;
            });
            (client, server_node_id)
        };

        assert!(d.fed.as_ref().unwrap().conns.lock().unwrap().is_empty(),
            "a blocked peer must never be registered");

        // The blocked side returns immediately without entering run_conn,
        // dropping the stream -- the client's next read must therefore
        // fail (EOF/reset), a deterministic completion signal.
        let mut client_channel = client_channel;
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), client_channel.recv_frame()).await;
        assert!(result.is_ok(), "must not hang");
        assert!(result.unwrap().is_err(), "blocked peer's connection must be closed, not idle");
    }

    // ---- SEEN recorded on successful handshake -----------------------------

    #[tokio::test]
    async fn unconfigured_peer_handshake_records_seen_and_emits_up_then_down() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        // No peers/trusted/blocked entry at all for this node_id.
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![])));
        assert_eq!(d.store.lock().unwrap().trust_level(&node_id).unwrap(), None);

        let mut rx = d.events.subscribe();
        let (a, b) = tokio::io::duplex(1 << 16);
        let (daemon_static, daemon_identity) = keypair(dir.path());
        let responder = tokio::spawn(async move {
            noise::handshake_responder(b, &daemon_static, &daemon_identity).await
        });
        let mut client_channel = handshake_initiator(a, &peer_key, &peer_id, None).await.unwrap();
        let (server_channel, server_node_id) = responder.await.unwrap().unwrap();
        assert_eq!(server_node_id, node_id);

        let d2 = d.clone();
        let conn_task =
            tokio::spawn(async move { admit_and_run(d2, server_channel, node_id.clone(), node_id).await });

        let up = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await.expect("timed out waiting for the up event").unwrap();
        match up {
            Event::Federation { up, .. } => assert!(up),
            other => panic!("expected Federation, got {other:?}"),
        }

        assert_eq!(d.store.lock().unwrap().trust_level(&peer_id.node_id()).unwrap().as_deref(),
            Some("seen"), "a successful handshake from an unconfigured node must record 'seen'");

        // Close the client side so the server's run_conn sees EOF and ends.
        let _ = client_channel.send_frame(b"").await; // best-effort, don't care if it errors
        drop(client_channel);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), conn_task).await;

        let down = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await.expect("timed out waiting for the down event").unwrap();
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
        assert!(register_up(&d, "phoenix", &node_id, now, tx1).is_some(),
            "first registration must succeed");
        assert!(register_up(&d, "phoenix", &node_id, now, tx2).is_none(),
            "second registration for a live key must be refused");

        let conns = d.fed.as_ref().unwrap().conns.lock().unwrap();
        assert_eq!(conns.len(), 1);
        conns.get("phoenix").unwrap().tx.try_send(Fed::Ping {}).unwrap();
        drop(conns);
        assert!(rx1.try_recv().is_ok(),
            "the registered connection must still be the FIRST one -- \
             a crossed second registration must not displace a live conn");
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
        d.fed.as_ref().unwrap().conns.lock().unwrap().remove("phoenix");
        let (tx2, _rx2) = mpsc::channel::<Fed>(4);
        let live = register_up(&d, "phoenix", &node_id, now, tx2)
            .expect("successor registration must succeed once the key is free");
        assert_ne!(stale, live, "each registration must get its own instance token");

        let mut events = d.events.subscribe();
        register_down(&d, "phoenix", stale);
        assert!(d.fed.as_ref().unwrap().conns.lock().unwrap().contains_key("phoenix"),
            "a stale teardown must not evict the live successor");
        assert!(events.try_recv().is_err(),
            "a stale teardown must not emit a Federation down event");

        register_down(&d, "phoenix", live);
        assert!(d.fed.as_ref().unwrap().conns.lock().unwrap().is_empty(),
            "the live instance's own teardown must still remove the entry");
        match events.try_recv().expect("the live teardown must emit the down event") {
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
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![])));

        // First connection: full handshake, then parked in run_conn.
        let (peer1_key, peer1_id) = keypair(dir.path());
        let (a1, b1) = tokio::io::duplex(1 << 16);
        let (ds1, di1) = keypair(dir.path());
        let responder =
            tokio::spawn(async move { noise::handshake_responder(b1, &ds1, &di1).await });
        let _client1 = handshake_initiator(a1, &peer1_key, &peer1_id, None).await.unwrap();
        let (server1, node1) = responder.await.unwrap().unwrap();
        let d2 = d.clone();
        tokio::spawn(async move { admit_and_run(d2, server1, "phoenix".to_string(), node1).await });
        // Wait until the first connection is actually registered.
        for _ in 0..100 {
            if d.fed.as_ref().unwrap().conns.lock().unwrap().contains_key("phoenix") { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let first_instance =
            d.fed.as_ref().unwrap().conns.lock().unwrap().get("phoenix").unwrap().instance;

        // Second connection, same peer key (the crossed dial).
        let mut events = d.events.subscribe();
        let (peer2_key, peer2_id) = keypair(dir.path());
        let (a2, b2) = tokio::io::duplex(1 << 16);
        let (ds2, di2) = keypair(dir.path());
        let responder =
            tokio::spawn(async move { noise::handshake_responder(b2, &ds2, &di2).await });
        let mut client2 = handshake_initiator(a2, &peer2_key, &peer2_id, None).await.unwrap();
        let (server2, node2) = responder.await.unwrap().unwrap();
        let d3 = d.clone();
        let second = tokio::spawn(async move {
            admit_and_run(d3, server2, "phoenix".to_string(), node2).await
        });

        // The second admit_and_run must return promptly (refused, not run) --
        // its client sees the channel closed rather than a live idle conn.
        tokio::time::timeout(std::time::Duration::from_secs(2), second)
            .await.expect("the crossed second connection must be dropped promptly, not kept running")
            .unwrap();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), client2.recv_frame()).await;
        assert!(result.is_ok(), "must not hang");
        assert!(result.unwrap().is_err(), "the second connection must be closed, not idle");

        let conns = d.fed.as_ref().unwrap().conns.lock().unwrap();
        assert_eq!(conns.get("phoenix").map(|c| c.instance), Some(first_instance),
            "the FIRST connection must still be the registered one");
        drop(conns);
        assert!(events.try_recv().is_err(),
            "dropping the refused second connection must not emit any Federation down event");
    }

    // ---- ack exactly-once (state-guard replay) -----------------------------

    fn dest() -> Endpoint {
        Endpoint { protocol: "fed".into(), endpoint: "phoenix/general".into() }
    }

    fn seed_attempting_fed_delivery(d: &Daemon) -> (uuid::Uuid, i64) {
        let now = Utc::now();
        let env = relay_core::Envelope::new(
            "mock:chan".parse().unwrap(), Sender { native_ref: "!a".into() },
            "text".into(), "hello".into(), now, now + chrono::Duration::hours(1), 8,
        );
        let store = d.store.lock().unwrap();
        store.insert_message(&env).unwrap();
        let delivery_id =
            store.insert_delivery(env.id, "general", &dest(), now, env.expires_at, 2).unwrap();
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

        let after_first = d.store.lock().unwrap().deliveries_for_id(delivery_id).unwrap();
        assert_eq!(after_first.state, "delivered");
        let ev = rx.try_recv().expect("first Ack must emit a Delivery(delivered) event");
        match ev {
            Event::Delivery { state, .. } => assert_eq!(state, "delivered"),
            other => panic!("expected Delivery, got {other:?}"),
        }

        // Replay: same Ack again -- must not error, must not change
        // updated_at/state again, and must not emit a second event.
        let before_replay = after_first.updated_at;
        handle_fed_ack(&d, "phoenix", &message_id.to_string());
        let after_replay = d.store.lock().unwrap().deliveries_for_id(delivery_id).unwrap();
        assert_eq!(after_replay.state, "delivered");
        assert_eq!(after_replay.updated_at, before_replay,
            "a replayed Ack must not touch an already-delivered row");
        assert!(rx.try_recv().is_err(), "a replayed Ack must not emit a second Delivery event");
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

        let after = d.store.lock().unwrap().deliveries_for_id(delivery_id).unwrap();
        assert_eq!(after.state, "attempting", "an Ack from the wrong peer must not resolve the row");
    }

    // ---- full wire round-trip: Fed::Envelope in, Fed::Ack out (duplex) ----

    #[tokio::test]
    async fn envelope_frame_over_the_wire_is_ingressed_and_acked() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        let mut cfg = fed_cfg(vec![], vec![]);
        cfg.peers = vec![PeerConfig {
            name: "phoenix".into(), node_id: node_id.clone(),
            addr: "10.0.0.2:47000".into(), trust: "verified".into(),
        }];
        let d = Arc::new(test_daemon_with_federation(dir.path(), cfg));

        let (a, b) = tokio::io::duplex(1 << 16);
        let (daemon_static, daemon_identity) = keypair(dir.path());
        let responder = tokio::spawn(async move {
            noise::handshake_responder(b, &daemon_static, &daemon_identity).await
        });
        let mut client_channel = handshake_initiator(a, &peer_key, &peer_id, None).await.unwrap();
        let (server_channel, server_node_id) = responder.await.unwrap().unwrap();

        let d2 = d.clone();
        tokio::spawn(
            async move { admit_and_run(d2, server_channel, "phoenix".to_string(), server_node_id).await },
        );

        let now = Utc::now();
        let mut env = relay_core::Envelope::new(
            "mock:origin".parse().unwrap(), Sender { native_ref: "!remote".into() },
            "text".into(), "hi from phoenix".into(), now, now + chrono::Duration::hours(1), 8,
        );
        env.origin = Some(crate::fed::sign::sign_origin(&env, &peer_id));
        let env_id = env.id;
        let frame = Fed::Envelope { env: Box::new(env), target_route: "general".into() };
        let mut buf = Vec::new();
        ciborium::into_writer(&frame, &mut buf).unwrap();
        client_channel.send_frame(&buf).await.unwrap();

        let reply_bytes =
            tokio::time::timeout(std::time::Duration::from_secs(2), client_channel.recv_frame())
                .await.expect("timed out waiting for an Ack").unwrap();
        let reply: Fed = ciborium::from_reader(reply_bytes.as_slice()).unwrap();
        match reply {
            Fed::Ack { id } => assert_eq!(id, env_id.to_string()),
            other => panic!("expected Ack, got {other:?}"),
        }

        let store = d.store.lock().unwrap();
        assert_eq!(store.queue_counts().unwrap(), vec![("pending".to_string(), 2)]);
    }

    // ---- TCP listener smoke test (design says: not exhaustive timing,
    // just "bind :0" wiring) ------------------------------------------------

    #[tokio::test]
    async fn federation_listener_binds_accepts_and_registers_over_real_tcp() {
        let dir = tempfile::tempdir().unwrap();
        let (peer_key, peer_id) = keypair(dir.path());
        let node_id = peer_id.node_id();
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![])));
        let mut rx = d.events.subscribe();

        let (daemon_static, _daemon_identity) = keypair(dir.path());
        let daemon_static = Arc::new(daemon_static);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let d2 = d.clone();
        tokio::spawn(async move { accept_loop(d2, listener, daemon_static).await });

        let stream = TcpStream::connect(addr).await.unwrap();
        let _client_channel = handshake_initiator(stream, &peer_key, &peer_id, None).await.unwrap();

        let up = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await.expect("timed out waiting for the up event over real TCP").unwrap();
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
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![])));
        let (daemon_static, _daemon_identity) = keypair(dir.path());
        let daemon_static = Arc::new(daemon_static);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Cap forced to 1 for this test (the production constant is 64).
        tokio::spawn(async move { accept_loop_with_cap(d, listener, daemon_static, 1).await });

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
        assert!(result.is_ok(), "an over-cap connection must be closed promptly, not left hanging");
        assert_eq!(result.unwrap().unwrap(), 0,
            "an over-cap connection must be closed with EOF and zero bytes (no handshake attempted)");
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
            self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for StallWritesAfterHandshake<S> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.stall_writes.load(Ordering::Relaxed) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut this.inner).poll_write(cx, buf)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.stall_writes.load(Ordering::Relaxed) {
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut this.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
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
        let d = Arc::new(test_daemon_with_federation(dir.path(), fed_cfg(vec![], vec![])));

        let (a, b) = tokio::io::duplex(1 << 16);
        let stall = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let wrapped_b = StallWritesAfterHandshake { inner: b, stall_writes: stall.clone() };

        let responder = tokio::spawn(async move {
            noise::handshake_responder(wrapped_b, &daemon_static, &daemon_identity).await
        });
        let client_channel = handshake_initiator(a, &peer_key, &peer_id, None).await.unwrap();
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
        assert!(result.is_ok(), "the connection must be torn down, not wedged forever on a stalled write");
        assert!(d.fed.as_ref().unwrap().conns.lock().unwrap().is_empty(),
            "a send-timed-out connection must deregister, exactly like any other closed connection");
    }
}
