use crate::engine::{self, Daemon, PluginHandle};
use crate::events::Event;
use chrono::Utc;
use relay_ipc::{read_frame, write_frame, DaemonToPlugin, PluginToDaemon, PROTOCOL_VERSION};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Monotonic connection-id source. Each accepted plugin connection takes a
/// fresh id so a stale teardown can tell whether a newer connection has since
/// replaced it in the handle map (see the reconnect-race guard below).
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tracing::{info, warn};

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
    let hello: PluginToDaemon = read_frame(&mut r).await?;
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
    d.plugins.lock().unwrap().insert(
        plugin.clone(),
        PluginHandle {
            tx,
            capabilities,
            connected: true,
            conn_id,
        },
    );
    info!(plugin, "plugin connected");
    d.emit_event(|| Event::Plugin {
        name: plugin.clone(),
        up: true,
        ts: Utc::now(),
    });

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_frame(&mut w, &msg).await.is_err() {
                break;
            }
        }
    });

    let result = loop {
        match read_frame::<_, PluginToDaemon>(&mut r).await {
            Ok(PluginToDaemon::Inbound {
                endpoint,
                sender,
                kind,
                body,
                created_at,
                attachments,
                priority,
            }) => {
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
            Ok(PluginToDaemon::DeliveryResult {
                corr,
                delivered,
                detail,
            }) => {
                engine::handle_result(&d, corr, delivered, detail);
            }
            Ok(PluginToDaemon::Gauges { gauges }) => {
                d.gauges.record(&plugin, gauges);
            }
            Ok(PluginToDaemon::Hello { .. }) => {} // ignore repeat hello
            Err(e) => break e,
        }
    };
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
    let cfg_json = d.cfg_snapshot(|c| {
        c.plugins
            .get(&name)
            .map(|p| serde_json::to_string(&p.config).unwrap_or_default())
            .unwrap_or_default()
    });
    let backoffs = [1u64, 5, 30, 120]; // spec §69
    let mut strikes = 0usize;
    loop {
        info!(plugin = name, "starting plugin process");
        let child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .env("RELAYFABRIC_SOCKET", &socket)
            .env("RELAYFABRIC_PLUGIN_NAME", &name)
            .env("RELAYFABRIC_PLUGIN_CONFIG", &cfg_json)
            // Python block-buffers stdout when it's a pipe (not a tty), so a
            // long-running plugin's diagnostic logs (e.g. the LXMF plugin's
            // RNS.log lines) never reach the inherited daemon log until the
            // process exits -- they simply vanish in production. Force
            // unbuffered so plugin logs surface live. Harmless for the Rust
            // plugins, which don't read it.
            .env("PYTHONUNBUFFERED", "1")
            .spawn();
        let started = Instant::now();
        match child {
            Ok(mut c) => {
                let _ = c.wait().await;
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

    /// Reconnect race (audit finding): after a plugin crashes and a fresh
    /// connection reconnects (overwriting the handle), the OLD connection's
    /// delayed EOF teardown must NOT flip the live new connection to "down".
    #[tokio::test]
    async fn stale_teardown_does_not_clobber_a_reconnected_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));

        async fn connect(d: &Arc<Daemon>) -> (tokio::task::JoinHandle<std::io::Result<()>>,
                                              tokio::net::unix::OwnedReadHalf,
                                              tokio::net::unix::OwnedWriteHalf) {
            let (plugin_side, daemon_side) = UnixStream::pair().unwrap();
            let conn = tokio::spawn(handle_conn(d.clone(), daemon_side, "mocka".into()));
            let (mut r, mut w) = plugin_side.into_split();
            write_frame(&mut w, &PluginToDaemon::Hello {
                plugin: "mocka".into(), version: "0.1.0".into(),
                protocol_version: PROTOCOL_VERSION, capabilities: Capabilities::default(),
            }).await.unwrap();
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
        assert_eq!(handle.conn_id, b_conn_id, "B's handle must not be replaced or cleared");
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
