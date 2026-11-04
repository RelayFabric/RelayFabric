use crate::engine::{self, Daemon, PluginHandle};
use crate::events::Event;
use chrono::Utc;
use relay_ipc::{read_frame, write_frame, DaemonToPlugin, PluginToDaemon, PROTOCOL_VERSION};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Monotonic connection-id source. Each accepted plugin connection takes a
/// fresh id so a stale teardown can tell whether a newer connection has since
/// replaced it in the handle map (see the reconnect-race guard below).
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// How often the daemon sends a heartbeat Ping to each connected plugin.
const PING_INTERVAL: Duration = Duration::from_secs(20);
/// How stale a plugin's `last_seen` may get before `supervise` treats it as
/// wedged and restarts the process. Comfortably above PING_INTERVAL (several
/// missed pings) and above the ~30s a synchronous plugin can spend inside one
/// blocking send, so a slow-but-healthy plugin is never falsely killed.
/// Also the read loop's per-frame deadline in `handle_conn`, which is what
/// recovers a wedged plugin the daemon did NOT spawn (the `peer_uid` /
/// systemd deployment has no `monitor_child`): dropping the socket gives the
/// plugin EOF, and its own supervisor restarts it.
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(90);
/// How often `supervise` re-checks a running child's liveness.
const LIVENESS_POLL: Duration = Duration::from_secs(15);
/// How long a spawned child gets to connect and complete Hello before
/// `monitor_child` treats it as wedged. Generous, since Python plugins
/// import heavy native stacks first -- but the SDK runner Hellos before any
/// bridge init, so a healthy plugin is well inside this.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
/// Deadline for a connecting peer's Hello: a process that attaches but never
/// completes the handshake would otherwise hold an fd and a task forever.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// How often `supervise` re-reads config while its plugin is disabled.
const DISABLED_RECHECK: Duration = Duration::from_secs(5);
/// Grace between SIGTERM and SIGKILL when killing a plugin's process group.
const KILL_GRACE: Duration = Duration::from_secs(5);

/// A plugin is wedged when it is connected but no frame (not even a Pong to
/// our heartbeat) has arrived within the liveness window -- or when it is
/// NOT connected and has had CONNECT_TIMEOUT both since spawn and since its
/// last frame (so a fresh spawn gets that long to attach, and a plugin that
/// dropped its connection without exiting gets the same grace to come back
/// before it is restarted). Pure so the decision is unit-tested without
/// spawning a process or waiting on a clock.
fn is_wedged(connected: bool, since_last_seen: Duration, since_spawn: Duration) -> bool {
    if connected {
        since_last_seen > LIVENESS_TIMEOUT
    } else {
        since_spawn > CONNECT_TIMEOUT && since_last_seen > CONNECT_TIMEOUT
    }
}

/// Monitor a running plugin child until it exits on its own OR goes
/// unresponsive (see `is_wedged`), in which case kill it so the supervise
/// loop restarts it. This is what recovers a process-alive-but-wedged plugin
/// -- a failure the bare `child.wait()` can never see. Returns once the
/// child has exited (naturally or killed).
async fn monitor_child(
    d: &Arc<Daemon>,
    name: &str,
    child: &mut tokio::process::Child,
    started: Instant,
) {
    let mut poll = tokio::time::interval(LIVENESS_POLL);
    poll.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = child.wait() => return, // exited on its own
            _ = poll.tick() => {
                let since_spawn = started.elapsed();
                let wedged = match d.plugins.lock().unwrap().get(name) {
                    Some(h) => is_wedged(h.connected, h.last_seen.lock().unwrap().elapsed(), since_spawn),
                    None => is_wedged(false, since_spawn, since_spawn), // never connected
                };
                if wedged {
                    warn!(
                        plugin = name,
                        "plugin unresponsive (no frame within liveness window); killing for restart"
                    );
                    kill_group(child).await;
                    return;
                }
            }
        }
    }
}

/// Signal a plugin's whole process group (its id is the child's pid, see
/// `process_group(0)` in `supervise`). Errors (ESRCH once everyone is gone)
/// are deliberately ignored.
fn signal_group(pid: u32, sig: libc::c_int) {
    // SAFETY: killpg has no memory-safety preconditions; a stale pgid can
    // only yield ESRCH (a pid number stays reserved while it is any live
    // process's pgid).
    unsafe {
        libc::killpg(pid as libc::pid_t, sig);
    }
}

/// Terminate a plugin child AND everything it spawned. `sh -c` leaves a
/// compound command's real plugin (`cd x && python ...`, pipes) as a
/// grandchild that `child.kill()` alone would orphan: it survives the
/// liveness kill and the restart then runs a duplicate. SIGTERM the group,
/// SIGKILL it after a short grace, then reap.
async fn kill_group(child: &mut tokio::process::Child) {
    let Some(pid) = child.id() else {
        return; // already reaped
    };
    signal_group(pid, libc::SIGTERM);
    if tokio::time::timeout(KILL_GRACE, child.wait())
        .await
        .is_err()
    {
        signal_group(pid, libc::SIGKILL);
        let _ = child.wait().await;
    }
    // stragglers in the group that outlived `sh` itself
    signal_group(pid, libc::SIGKILL);
}

/// The group-wide counterpart of `kill_on_drop` (which only signals `sh`):
/// when the runtime tears down the supervise task on daemon exit, take the
/// child's grandchildren with it instead of orphaning them. Disarmed once
/// the child has been reaped, so a recycled pid is never signalled.
struct GroupKillOnDrop(Option<u32>);

impl Drop for GroupKillOnDrop {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            signal_group(pid, libc::SIGKILL);
        }
    }
}

/// Whether an inherited daemon environment variable may reach a plugin
/// process. Plugins start from a cleared environment plus this allowlist:
/// a `${env:NAME}` secret source meant for plugin A must not be readable
/// by plugin B (or a GPL sidecar) via /proc/self/environ. `RELAYFABRIC_*`
/// is deliberately NOT a prefix rule here -- the daemon's own spawn-time
/// vars are set explicitly after the clear, and anything else under that
/// prefix is exactly the kind of secret this protects.
fn env_allowed(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "TZ",
        "TMPDIR",
        "RUST_LOG",
        "RUST_BACKTRACE",
        "VIRTUAL_ENV",
        "LD_LIBRARY_PATH",
        "NO_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "no_proxy",
        "http_proxy",
        "https_proxy",
    ];
    const PREFIXES: &[&str] = &["LC_", "PYTHON", "XDG_", "SSL_CERT_"];
    EXACT.contains(&name) || PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The daemon's environment filtered through `env_allowed`.
fn inherited_env() -> impl Iterator<Item = (OsString, OsString)> {
    std::env::vars_os().filter(|(k, _)| k.to_str().is_some_and(env_allowed))
}

/// The command `supervise` spawns for a plugin: `sh -c <command>` in its
/// own process group, with a scrubbed environment plus the spawn contract.
fn plugin_command(
    command: &str,
    socket: &std::path::Path,
    name: &str,
    cfg_json: &str,
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.arg("-c")
        .arg(command)
        .env_clear()
        .envs(inherited_env())
        .env("RELAYFABRIC_SOCKET", socket)
        .env("RELAYFABRIC_PLUGIN_NAME", name)
        .env("RELAYFABRIC_PLUGIN_CONFIG", cfg_json)
        // Python block-buffers stdout when it's a pipe (not a tty), so a
        // long-running plugin's diagnostic logs (e.g. the LXMF plugin's
        // RNS.log lines) never reach the inherited daemon log until the
        // process exits -- they simply vanish in production. Force
        // unbuffered so plugin logs surface live. Harmless for the Rust
        // plugins, which don't read it.
        .env("PYTHONUNBUFFERED", "1")
        // Own process group so `kill_group` can reach a compound command's
        // grandchildren, not just `sh`.
        .process_group(0)
        // Kill the child if this supervise task's Child handle is dropped
        // -- e.g. when the runtime shuts down on daemon exit. Without it a
        // standalone (non-systemd) run orphans every plugin subprocess on
        // exit/restart, leaving duplicate plugins holding devices/sockets.
        .kill_on_drop(true);
    cmd
}

/// The plugin's CURRENT `config:` block as JSON, or None while it is not an
/// enabled configured plugin. Read fresh on every spawn so a restart after a
/// live `apply_config` comes up on the new config, and a plugin disabled
/// live stays down instead of respawning into a refused-Hello loop.
fn spawn_config(d: &Daemon, name: &str) -> Option<String> {
    d.cfg_snapshot(|c| {
        c.plugins
            .get(name)
            .filter(|p| p.enabled)
            .map(|p| serde_json::to_string(&p.config).unwrap_or_default())
    })
}
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// One listener per enabled plugin (v0.4 cycle B): the daemon binds
/// `<data_dir>/plugins.d/<name>.sock` for each and passes the name down, so
/// a connection can only ever become the plugin its socket is bound to.
pub async fn listen(d: Arc<Daemon>, listener: UnixListener, plugin_name: String) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let d = d.clone();
                let name = plugin_name.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(d, stream, name).await {
                        warn!(error = %e, "plugin connection ended");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "plugin accept failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn handle_conn(
    d: Arc<Daemon>,
    stream: tokio::net::UnixStream,
    bound_plugin: String,
) -> std::io::Result<()> {
    // Peer-credential gate (v0.4 cycle B), BEFORE any frame is parsed: an
    // unauthorized peer's bytes never reach the codec. With `peer_uid`
    // configured, EXACTLY that uid may attach (fail closed -- the daemon's
    // own uid is deliberately not grandfathered in, so a misconfigured
    // same-user process can't slip past an explicit isolation policy);
    // without it, only the daemon's own euid may (the pre-v0.4 same-user
    // posture, now enforced rather than implied by file modes).
    let cred = stream.peer_cred()?;
    let expected_uid = d.cfg_snapshot(|c| c.plugins.get(&bound_plugin).and_then(|p| p.peer_uid));
    let uid_ok = match expected_uid {
        Some(uid) => cred.uid() == uid,
        None => cred.uid() == unsafe { libc::geteuid() },
    };
    if !uid_ok {
        return Err(std::io::Error::other(format!(
            "refused peer uid {} on socket for plugin '{bound_plugin}'",
            cred.uid()
        )));
    }

    let (mut r, mut w) = stream.into_split();
    let hello: PluginToDaemon = tokio::time::timeout(HELLO_TIMEOUT, read_frame(&mut r))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "no Hello within deadline")
        })??;
    let PluginToDaemon::Hello {
        plugin,
        protocol_version,
        capabilities,
        ..
    } = hello
    else {
        return Err(std::io::Error::other("first frame must be Hello"));
    };
    // trust boundary: the hello must claim the name this socket is bound
    // to, and that name must still be a configured+enabled plugin.
    let name_ok = plugin == bound_plugin;
    let allowed =
        name_ok && d.cfg_snapshot(|c| c.plugins.get(&plugin).map(|p| p.enabled).unwrap_or(false));
    if !allowed || protocol_version != PROTOCOL_VERSION {
        let err = if !name_ok {
            "plugin name does not match socket"
        } else if !allowed {
            "unknown plugin"
        } else {
            "unsupported protocol version"
        };
        write_frame(
            &mut w,
            &DaemonToPlugin::HelloAck {
                protocol_version: PROTOCOL_VERSION,
                error: Some(err.into()),
            },
        )
        .await?;
        return Err(std::io::Error::other(format!("{plugin}: {err}")));
    }
    write_frame(
        &mut w,
        &DaemonToPlugin::HelloAck {
            protocol_version: PROTOCOL_VERSION,
            error: None,
        },
    )
    .await?;

    // bounded outbound channel: backpressure instead of unbounded memory (§45)
    let (tx, mut rx) = mpsc::channel::<DaemonToPlugin>(256);
    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    let last_seen = Arc::new(std::sync::Mutex::new(Instant::now()));
    let replaced_live = d
        .plugins
        .lock()
        .unwrap()
        .insert(
            plugin.clone(),
            PluginHandle {
                tx: tx.clone(),
                capabilities,
                connected: true,
                conn_id,
                last_seen: last_seen.clone(),
            },
        )
        .is_some_and(|old| old.connected);
    if replaced_live {
        // A crashed plugin's stale handle is `connected: false` by the time
        // its restart reconnects; a LIVE one being displaced means a second
        // process (a duplicate, or something else claiming this name) --
        // the peer gate let it in, so make it visible rather than silent.
        warn!(
            plugin,
            "new connection displaced a still-connected one (duplicate plugin process?)"
        );
    }
    info!(plugin, "plugin connected");
    d.emit_event(|| Event::Plugin {
        name: plugin.clone(),
        up: true,
        ts: Utc::now(),
    });

    let writer = {
        let plugin = plugin.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match write_frame(&mut w, &msg).await {
                    Ok(()) => {}
                    // The one frame's fault (encodes past MAX_FRAME), not the
                    // socket's: drop it and keep the connection, or every
                    // later send would fail with a closed channel.
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                        warn!(plugin, error = %e, "dropping oversize outbound frame");
                    }
                    Err(_) => break,
                }
            }
        })
    };

    // Heartbeat: probe an idle plugin so `last_seen` reflects liveness, not
    // just traffic. A healthy plugin answers Ping with Pong (refreshing
    // last_seen in the read loop); a wedged one never does, and `supervise`
    // restarts it once last_seen goes stale. try_send (not send().await) so a
    // full outbound buffer -- itself a sign the plugin is behind -- doesn't
    // block the heartbeat; liveness will catch it either way.
    let heartbeat = {
        let hb_tx = tx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PING_INTERVAL);
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                match hb_tx.try_send(DaemonToPlugin::Ping) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
        })
    };

    let result = loop {
        // Per-frame deadline: a healthy plugin answers each heartbeat, so
        // silence past the liveness window is a wedge. Breaking drops the
        // socket, which is the only lever the daemon has over a plugin it
        // didn't spawn (peer_uid / systemd), and what `monitor_child` sees
        // as "not connected" for one it did.
        let read = tokio::time::timeout(LIVENESS_TIMEOUT, read_frame::<_, PluginToDaemon>(&mut r))
            .await
            .unwrap_or_else(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no frame within liveness window",
                ))
            });
        match read {
            Ok(frame) => {
                // Any received frame proves the plugin is alive; refresh the
                // liveness deadline before dispatching.
                *last_seen.lock().unwrap() = Instant::now();
                match frame {
                    PluginToDaemon::Inbound {
                        endpoint,
                        sender,
                        kind,
                        body,
                        created_at,
                        attachments,
                        priority,
                    } => {
                        engine::handle_inbound(
                            &d,
                            &plugin,
                            endpoint,
                            sender,
                            kind,
                            body,
                            created_at,
                            attachments,
                            priority,
                        );
                    }
                    PluginToDaemon::DeliveryResult {
                        corr,
                        delivered,
                        detail,
                    } => {
                        engine::handle_result(&d, &plugin, corr, delivered, detail);
                    }
                    PluginToDaemon::Gauges { gauges } => {
                        d.gauges.record(&plugin, gauges);
                    }
                    PluginToDaemon::Pong => {} // liveness refresh only (done above)
                    PluginToDaemon::Hello { .. } => {} // ignore repeat hello
                    // a newer plugin's frame this build doesn't know: ignored
                    // by contract (docs/plugin-authors.md §3), never fatal
                    PluginToDaemon::Unknown => debug!(plugin, "ignoring frame with unknown tag"),
                }
            }
            Err(e) => break e,
        }
    };
    heartbeat.abort();
    writer.abort();
    // Reconnect-race guard: only clear `connected` (and emit "down") if THIS
    // connection is still the installed one. If a fresh connection already
    // replaced us in the map (crash->restart->reconnect), its handle carries
    // a newer conn_id and must be left alone -- otherwise this stale teardown
    // would flip the live new connection to "down" and black-hole its routes.
    let still_current = {
        match d.plugins.lock().unwrap().get_mut(&plugin) {
            Some(h) if h.conn_id == conn_id => {
                h.connected = false;
                true
            }
            _ => false,
        }
    };
    if still_current {
        info!(plugin, "plugin disconnected");
        d.emit_event(|| Event::Plugin {
            name: plugin.clone(),
            up: false,
            ts: Utc::now(),
        });
    } else {
        info!(plugin, "stale plugin connection closed (already replaced)");
    }
    Err(result)
}

pub async fn supervise(d: Arc<Daemon>, name: String, command: String, socket: PathBuf) {
    let backoffs = [1u64, 5, 30, 120]; // spec §69
    let mut strikes = 0usize;
    loop {
        let Some(cfg_json) = spawn_config(&d, &name) else {
            // disabled (or removed) live: park, re-check, never spawn
            tokio::time::sleep(DISABLED_RECHECK).await;
            continue;
        };
        info!(plugin = name, "starting plugin process");
        let child = plugin_command(&command, &socket, &name, &cfg_json).spawn();
        let started = Instant::now();
        match child {
            Ok(mut c) => {
                let mut group = GroupKillOnDrop(c.id());
                monitor_child(&d, &name, &mut c, started).await;
                group.0 = None; // reaped: the pid may now be recycled
            }
            Err(e) => warn!(plugin = name, error = %e, "spawn failed"),
        }
        if started.elapsed() > Duration::from_secs(60) {
            strikes = 0; // a healthy run resets the backoff ladder
        }
        let delay = backoffs[strikes.min(backoffs.len() - 1)];
        strikes += 1;
        warn!(
            plugin = name,
            delay, "plugin exited; restarting after backoff"
        );
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::tests_support::test_daemon;
    use relay_core::Capabilities;
    use std::collections::BTreeMap;
    use tokio::net::UnixStream;

    /// End-to-end (minus process spawn): a plugin's Gauges frame, sent over
    /// a real `handle_conn` connection after Hello/HelloAck, lands in
    /// `Daemon::gauges` sanitized and ready to render — the daemon-side half
    /// of design §3's Gauges frame handling.
    #[tokio::test]
    async fn gauges_frame_is_recorded_into_daemon_gauges_store() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();

        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(
            &mut w,
            &PluginToDaemon::Hello {
                plugin: "mocka".into(),
                version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities::default(),
            },
        )
        .await
        .unwrap();
        let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
        assert!(
            matches!(ack, DaemonToPlugin::HelloAck { error: None, .. }),
            "hello must be accepted: {ack:?}"
        );

        let mut gauges = BTreeMap::new();
        gauges.insert("RSSI".to_string(), -71.0);
        write_frame(&mut w, &PluginToDaemon::Gauges { gauges })
            .await
            .unwrap();

        // Dropping both halves closes the plugin side of the socket, so
        // handle_conn's next read hits EOF and the spawned task returns —
        // a deterministic completion signal instead of a sleep-based poll.
        drop(w);
        drop(r);
        let _ = conn.await;

        let rendered = d.gauges.render(std::time::Instant::now());
        assert_eq!(
            rendered, "relayfabric_plugin_gauge{plugin=\"mocka\",name=\"rssi\"} -71\n",
            "name must be sanitized (lowercased) and the value preserved"
        );
    }

    /// design §4's two `plugins.rs` emission points: `up: true` right after
    /// a successful `HelloAck` (before this connection does anything else),
    /// `up: false` once the read loop exits and `connected` is flipped back
    /// off. Subscribes BEFORE spawning `handle_conn` -- `emit_event` only
    /// sends when a subscriber is already attached, so a subscription
    /// registered any later could race the connect event.
    #[tokio::test]
    async fn handle_conn_emits_plugin_up_on_connect_and_down_on_disconnect() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let mut rx = d.events.subscribe();
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();

        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(
            &mut w,
            &PluginToDaemon::Hello {
                plugin: "mocka".into(),
                version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities::default(),
            },
        )
        .await
        .unwrap();
        let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
        assert!(
            matches!(ack, DaemonToPlugin::HelloAck { error: None, .. }),
            "hello must be accepted: {ack:?}"
        );

        let up_ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for the connect event")
            .expect("connect must emit a Plugin event");
        match up_ev {
            Event::Plugin { name, up, .. } => {
                assert_eq!(name, "mocka");
                assert!(up, "connect must report up: true");
            }
            other => panic!("expected Plugin, got {other:?}"),
        }

        // Dropping both halves closes the plugin side of the socket, so
        // handle_conn's next read hits EOF and the spawned task returns —
        // a deterministic completion signal instead of a sleep-based poll.
        drop(w);
        drop(r);
        let _ = conn.await;

        let down_ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for the disconnect event")
            .expect("disconnect must emit a Plugin event");
        match down_ev {
            Event::Plugin { name, up, .. } => {
                assert_eq!(name, "mocka");
                assert!(!up, "disconnect must report up: false");
            }
            other => panic!("expected Plugin, got {other:?}"),
        }
    }

    #[test]
    fn is_wedged_when_connected_and_past_the_liveness_window() {
        let long_ago = Duration::from_secs(3600);
        assert!(
            is_wedged(true, Duration::from_secs(91), long_ago),
            "stale + connected = wedged"
        );
        assert!(
            !is_wedged(true, Duration::from_secs(89), long_ago),
            "fresh = not wedged"
        );
    }

    /// A child that never attaches (or dropped its connection and never
    /// came back) is wedged too -- but only once it has had CONNECT_TIMEOUT
    /// both since spawn and since its last frame, so a fresh restart and a
    /// just-dropped connection each get their grace.
    #[test]
    fn is_wedged_when_unconnected_past_the_connect_timeout() {
        let fresh = Duration::from_secs(5);
        let late = Duration::from_secs(61);
        assert!(
            !is_wedged(false, fresh, fresh),
            "a just-spawned child is still connecting"
        );
        assert!(
            !is_wedged(false, late, fresh),
            "a restart whose stale handle has an old last_seen gets the full grace"
        );
        assert!(
            !is_wedged(false, fresh, late),
            "a long-running child that just dropped its connection gets grace to return"
        );
        assert!(
            is_wedged(false, late, late),
            "never connected (or gone) past the deadline = wedged"
        );
    }

    /// The env allowlist (secret isolation): the daemon's own `${env:NAME}`
    /// secret sources -- and anything else not needed to run a plugin --
    /// must not be inherited; `RELAYFABRIC_*` is explicitly not a prefix
    /// rule, since the spawn-contract vars are set after the clear.
    #[test]
    fn env_allowlist_passes_runtime_basics_and_blocks_everything_else() {
        for ok in [
            "PATH",
            "HOME",
            "LANG",
            "LC_ALL",
            "TZ",
            "TMPDIR",
            "RUST_LOG",
            "PYTHONPATH",
            "VIRTUAL_ENV",
            "XDG_RUNTIME_DIR",
            "SSL_CERT_FILE",
            "HTTPS_PROXY",
        ] {
            assert!(env_allowed(ok), "{ok} must be inherited");
        }
        for no in [
            "RELAYFABRIC_MQTT_TOKEN",
            "RELAYFABRIC_PLUGIN_CONFIG",
            "RELAYFABRIC_SOCKET",
            "AWS_SECRET_ACCESS_KEY",
            "DATABASE_URL",
            "CARGO_MANIFEST_DIR",
        ] {
            assert!(!env_allowed(no), "{no} must NOT be inherited");
        }
    }

    /// End-to-end: the spawned process sees the spawn contract and PATH,
    /// and does NOT see the daemon's own unlisted variables (cargo sets
    /// CARGO_PKG_NAME on the test process, which stands in for a secret).
    #[tokio::test]
    async fn plugin_command_spawns_with_a_scrubbed_environment() {
        if std::env::var_os("CARGO_PKG_NAME").is_none() {
            return; // not run under cargo: nothing to prove the scrub against
        }
        let out = plugin_command("env", std::path::Path::new("/tmp/x.sock"), "mocka", "{}")
            .output()
            .await
            .expect("spawn sh");
        let env = String::from_utf8_lossy(&out.stdout);
        assert!(env.contains("RELAYFABRIC_PLUGIN_NAME=mocka\n"), "{env}");
        assert!(env.contains("RELAYFABRIC_PLUGIN_CONFIG={}\n"), "{env}");
        assert!(env.contains("PYTHONUNBUFFERED=1\n"), "{env}");
        assert!(env.contains("PATH="), "{env}");
        assert!(!env.contains("CARGO_PKG_NAME="), "leaked: {env}");
    }

    /// Every spawn reads the plugin's CURRENT config: a live config change
    /// reaches the next restart, and a plugin disabled live is not spawned.
    #[test]
    fn spawn_config_tracks_live_config_and_enabled_flag() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        let before = spawn_config(&d, "mocka").expect("enabled plugin spawns");

        if let Some(p) = d.cfg.write().unwrap().plugins.get_mut("mocka") {
            p.config = serde_norway::from_str("{token: new}").unwrap();
        }
        let after = spawn_config(&d, "mocka").expect("still enabled");
        assert_ne!(before, after, "a changed config must reach the next spawn");
        assert!(after.contains("\"token\":\"new\""), "{after}");

        if let Some(p) = d.cfg.write().unwrap().plugins.get_mut("mocka") {
            p.enabled = false;
        }
        assert_eq!(spawn_config(&d, "mocka"), None, "disabled: must not spawn");
        assert_eq!(spawn_config(&d, "nope"), None, "unknown: must not spawn");
    }

    /// A peer that attaches but never sends Hello is dropped at the
    /// deadline instead of holding an fd and a task forever.
    #[tokio::test(start_paused = true)]
    async fn a_connection_that_never_hellos_is_dropped_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();
        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));
        // say nothing; virtual time runs out the HELLO_TIMEOUT
        let res = conn.await.unwrap();
        let err = res.expect_err("must give up on a silent peer");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        assert!(
            !d.plugins.lock().unwrap().contains_key("mocka"),
            "no handle may be installed without a Hello"
        );
        drop(plugin_side);
    }

    /// Liveness without a supervisor (the peer_uid / systemd deployment):
    /// a connected plugin that goes silent past the liveness window is
    /// disconnected by the read loop itself.
    #[tokio::test(start_paused = true)]
    async fn a_silent_plugin_is_disconnected_by_the_read_loop_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();
        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(
            &mut w,
            &PluginToDaemon::Hello {
                plugin: "mocka".into(),
                version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities::default(),
            },
        )
        .await
        .unwrap();
        let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
        assert!(matches!(ack, DaemonToPlugin::HelloAck { error: None, .. }));

        // never answer the heartbeat; the deadline must end the connection
        let res = conn.await.unwrap();
        let err = res.expect_err("silence must end the connection");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        assert!(
            !d.plugins.lock().unwrap().get("mocka").unwrap().connected,
            "the handle must be marked down"
        );
    }

    /// An unknown-tag frame (a newer plugin) is ignored, not fatal: the
    /// connection stays up and later frames are still processed.
    #[tokio::test]
    async fn unknown_frame_is_ignored_and_the_connection_survives() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();
        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(
            &mut w,
            &PluginToDaemon::Hello {
                plugin: "mocka".into(),
                version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities::default(),
            },
        )
        .await
        .unwrap();
        let _ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();

        // {"t": "future-frame", "x": 1}, hand-framed
        let body: Vec<u8> = vec![
            0xa2, 0x61, b't', 0x6c, b'f', b'u', b't', b'u', b'r', b'e', b'-', b'f', b'r', b'a',
            b'm', b'e', 0x61, b'x', 0x01,
        ];
        use tokio::io::AsyncWriteExt;
        w.write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        w.write_all(&body).await.unwrap();
        // a real frame after it must still land
        let mut gauges = BTreeMap::new();
        gauges.insert("rssi".to_string(), -60.0);
        write_frame(&mut w, &PluginToDaemon::Gauges { gauges })
            .await
            .unwrap();
        drop(w);
        drop(r);
        let _ = conn.await;
        assert_eq!(
            d.gauges.render(std::time::Instant::now()),
            "relayfabric_plugin_gauge{plugin=\"mocka\",name=\"rssi\"} -60\n"
        );
    }

    /// An outbound frame that encodes past MAX_FRAME is dropped on its own,
    /// not allowed to kill the writer: a later, sane frame still arrives.
    #[tokio::test]
    async fn oversize_outbound_frame_is_dropped_without_closing_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();
        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(
            &mut w,
            &PluginToDaemon::Hello {
                plugin: "mocka".into(),
                version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities::default(),
            },
        )
        .await
        .unwrap();
        let _ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();

        let tx = d.plugins.lock().unwrap().get("mocka").unwrap().tx.clone();
        tx.send(DaemonToPlugin::Send {
            corr: 1,
            endpoint: "chan".into(),
            kind: "text".into(),
            body: String::new(),
            attachments: vec![relay_ipc::IpcAttachment {
                filename: "big.bin".into(),
                mime: "application/octet-stream".into(),
                data: vec![0u8; relay_ipc::MAX_FRAME as usize + 1],
            }],
        })
        .await
        .unwrap();
        tx.send(DaemonToPlugin::Ping).await.unwrap();

        let got: DaemonToPlugin = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut r))
            .await
            .expect("the writer must still be alive")
            .unwrap();
        assert!(matches!(got, DaemonToPlugin::Ping), "got {got:?}");
        drop(w);
        drop(r);
        let _ = conn.await;
    }

    /// Any received frame must refresh the connection's liveness deadline, or
    /// a busy-but-healthy plugin would be killed as wedged. Proves the
    /// last_seen wiring feeds the supervisor's is_wedged check.
    #[tokio::test]
    async fn a_received_frame_refreshes_last_seen() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();
        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(
            &mut w,
            &PluginToDaemon::Hello {
                plugin: "mocka".into(),
                version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities::default(),
            },
        )
        .await
        .unwrap();
        let _ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();

        let before = *d
            .plugins
            .lock()
            .unwrap()
            .get("mocka")
            .unwrap()
            .last_seen
            .lock()
            .unwrap();
        // a small gap so the refreshed instant is strictly later
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let mut gauges = std::collections::BTreeMap::new();
        gauges.insert("rssi".to_string(), -70.0);
        write_frame(&mut w, &PluginToDaemon::Gauges { gauges })
            .await
            .unwrap();

        // wait until the daemon has processed the frame and advanced last_seen
        let mut advanced = false;
        for _ in 0..200 {
            let now = *d
                .plugins
                .lock()
                .unwrap()
                .get("mocka")
                .unwrap()
                .last_seen
                .lock()
                .unwrap();
            if now > before {
                advanced = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(advanced, "receiving a frame must advance last_seen");

        drop(w);
        drop(r);
        let _ = conn.await;
    }

    /// Reconnect race (audit finding): after a plugin crashes and a fresh
    /// connection reconnects (overwriting the handle), the OLD connection's
    /// delayed EOF teardown must NOT flip the live new connection to "down".
    #[tokio::test]
    async fn stale_teardown_does_not_clobber_a_reconnected_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));

        async fn connect(
            d: &Arc<Daemon>,
        ) -> (
            tokio::task::JoinHandle<std::io::Result<()>>,
            tokio::net::unix::OwnedReadHalf,
            tokio::net::unix::OwnedWriteHalf,
        ) {
            let (plugin_side, daemon_side) = UnixStream::pair().unwrap();
            let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));
            let (mut r, mut w) = plugin_side.into_split();
            write_frame(
                &mut w,
                &PluginToDaemon::Hello {
                    plugin: "mocka".into(),
                    version: "0.1.0".into(),
                    protocol_version: PROTOCOL_VERSION,
                    capabilities: Capabilities::default(),
                },
            )
            .await
            .unwrap();
            let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
            assert!(matches!(ack, DaemonToPlugin::HelloAck { error: None, .. }));
            (conn, r, w)
        }

        // Connection A connects, then B reconnects for the same plugin.
        let (conn_a, ra, wa) = connect(&d).await;
        let (_conn_b, _rb, _wb) = connect(&d).await;
        let b_conn_id = d.plugins.lock().unwrap().get("mocka").unwrap().conn_id;

        // A now tears down (its socket closes -> EOF in its read loop).
        drop(wa);
        drop(ra);
        let _ = conn_a.await;

        // B must still be installed, live, and unchanged by A's stale teardown.
        let h = d.plugins.lock().unwrap();
        let handle = h.get("mocka").expect("B's handle must remain installed");
        assert!(handle.connected, "reconnected plugin must stay connected");
        assert_eq!(
            handle.conn_id, b_conn_id,
            "B's handle must not be replaced or cleared"
        );
    }

    /// A Hello claiming a name other than the one this socket is bound to
    /// is impersonation and must be rejected before any state is touched --
    /// per-plugin sockets make the daemon, not the connector, the authority
    /// on which plugin a connection can be.
    #[tokio::test]
    async fn hello_name_must_match_the_socket_binding() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();

        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(
            &mut w,
            &PluginToDaemon::Hello {
                plugin: "mockb".into(),
                version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities::default(),
            },
        )
        .await
        .unwrap();
        let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
        assert!(
            matches!(&ack, DaemonToPlugin::HelloAck { error: Some(e), .. }
                     if e == "plugin name does not match socket"),
            "a cross-name hello must be rejected: {ack:?}"
        );
        let _ = conn.await;
    }

    /// A socket bound to a name that is no longer an enabled configured
    /// plugin (live config change after bind) still refuses the hello.
    #[tokio::test]
    async fn hello_from_unknown_plugin_is_rejected_before_any_gauges_handling() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();

        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "not-configured".into()));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(
            &mut w,
            &PluginToDaemon::Hello {
                plugin: "not-configured".into(),
                version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities::default(),
            },
        )
        .await
        .unwrap();
        let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
        assert!(
            matches!(&ack, DaemonToPlugin::HelloAck { error: Some(e), .. } if e == "unknown plugin"),
            "an unconfigured plugin name must be rejected: {ack:?}"
        );
        let _ = conn.await;
    }

    /// With `peer_uid` configured to a uid that is NOT the connecting
    /// process's, the connection is refused before a single frame is read
    /// (no HelloAck, just EOF) -- unauthorized peers don't get their bytes
    /// parsed.
    #[tokio::test]
    async fn mismatched_peer_uid_is_refused_before_reading_any_frame() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let self_uid = unsafe { libc::geteuid() };
        if let Some(p) = d.cfg.write().unwrap().plugins.get_mut("mocka") {
            p.peer_uid = Some(self_uid + 1);
        }
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();

        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));

        let (mut r, mut w) = plugin_side.into_split();
        // The refusal may close the connection before this write lands --
        // a BrokenPipe here IS the refusal, so the write result is ignored.
        let _ = write_frame(
            &mut w,
            &PluginToDaemon::Hello {
                plugin: "mocka".into(),
                version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities::default(),
            },
        )
        .await;
        let refused = read_frame::<_, DaemonToPlugin>(&mut r).await;
        assert!(refused.is_err(), "must close without an ack: {refused:?}");
        let res = conn.await.unwrap();
        assert!(res.is_err(), "handle_conn must report the refusal");
    }

    /// A configured `peer_uid` that matches the connecting process is
    /// accepted (and the daemon's own uid always is).
    #[tokio::test]
    async fn matching_peer_uid_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let self_uid = unsafe { libc::geteuid() };
        if let Some(p) = d.cfg.write().unwrap().plugins.get_mut("mocka") {
            p.peer_uid = Some(self_uid);
        }
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();

        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(
            &mut w,
            &PluginToDaemon::Hello {
                plugin: "mocka".into(),
                version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities::default(),
            },
        )
        .await
        .unwrap();
        let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
        assert!(
            matches!(ack, DaemonToPlugin::HelloAck { error: None, .. }),
            "matching peer_uid must be accepted: {ack:?}"
        );
        drop(w);
        drop(r);
        let _ = conn.await;
    }
}
