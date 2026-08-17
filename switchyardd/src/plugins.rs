use crate::engine::{self, Daemon, PluginHandle};
use crate::events::Event;
use chrono::Utc;
use relay_ipc::{read_frame, write_frame, DaemonToPlugin, PluginToDaemon, PROTOCOL_VERSION};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub async fn listen(d: Arc<Daemon>, listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let d = d.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(d, stream).await {
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
) -> std::io::Result<()> {
    let (mut r, mut w) = stream.into_split();
    let hello: PluginToDaemon = read_frame(&mut r).await?;
    let PluginToDaemon::Hello { plugin, protocol_version, capabilities, .. } = hello else {
        return Err(std::io::Error::other("first frame must be Hello"));
    };
    // trust boundary: only configured+enabled plugin names may attach
    let allowed = d.cfg_snapshot(|c| c.plugins.get(&plugin).map(|p| p.enabled).unwrap_or(false));
    if !allowed || protocol_version != PROTOCOL_VERSION {
        let err = if allowed { "unsupported protocol version" } else { "unknown plugin" };
        write_frame(&mut w, &DaemonToPlugin::HelloAck {
            protocol_version: PROTOCOL_VERSION, error: Some(err.into()),
        }).await?;
        return Err(std::io::Error::other(format!("{plugin}: {err}")));
    }
    write_frame(&mut w, &DaemonToPlugin::HelloAck {
        protocol_version: PROTOCOL_VERSION, error: None,
    }).await?;

    // bounded outbound channel: backpressure instead of unbounded memory (§45)
    let (tx, mut rx) = mpsc::channel::<DaemonToPlugin>(256);
    d.plugins.lock().unwrap().insert(plugin.clone(), PluginHandle {
        tx, capabilities, connected: true,
    });
    info!(plugin, "plugin connected");
    d.emit_event(|| Event::Plugin { name: plugin.clone(), up: true, ts: Utc::now() });

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
                endpoint, sender, kind, body, created_at, attachments, priority,
            }) => {
                engine::handle_inbound(
                    &d, &plugin, endpoint, sender, kind, body, created_at, attachments, priority);
            }
            Ok(PluginToDaemon::DeliveryResult { corr, delivered, detail }) => {
                engine::handle_result(&d, corr, delivered, detail);
            }
            Ok(PluginToDaemon::Gauges { gauges }) => {
                d.gauges.record(&plugin, gauges);
            }
            Ok(PluginToDaemon::Hello { .. }) => {} // ignore repeat hello
            Err(e) => break e,
        }
    };
    if let Some(h) = d.plugins.lock().unwrap().get_mut(&plugin) {
        h.connected = false;
    }
    writer.abort();
    info!(plugin, "plugin disconnected");
    d.emit_event(|| Event::Plugin { name: plugin.clone(), up: false, ts: Utc::now() });
    Err(result)
}

pub async fn supervise(d: Arc<Daemon>, name: String, command: String, socket: PathBuf) {
    let cfg_json = d.cfg_snapshot(|c| c.plugins.get(&name)
        .map(|p| serde_json::to_string(&p.config).unwrap_or_default())
        .unwrap_or_default());
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
            Ok(mut c) => { let _ = c.wait().await; }
            Err(e) => warn!(plugin = name, error = %e, "spawn failed"),
        }
        if started.elapsed() > Duration::from_secs(60) {
            strikes = 0; // a healthy run resets the backoff ladder
        }
        let delay = backoffs[strikes.min(backoffs.len() - 1)];
        strikes += 1;
        warn!(plugin = name, delay, "plugin exited; restarting after backoff");
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

        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(&mut w, &PluginToDaemon::Hello {
            plugin: "mocka".into(),
            version: "0.1.0".into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: Capabilities::default(),
        }).await.unwrap();
        let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
        assert!(matches!(ack, DaemonToPlugin::HelloAck { error: None, .. }),
            "hello must be accepted: {ack:?}");

        let mut gauges = BTreeMap::new();
        gauges.insert("RSSI".to_string(), -71.0);
        write_frame(&mut w, &PluginToDaemon::Gauges { gauges }).await.unwrap();

        // Dropping both halves closes the plugin side of the socket, so
        // handle_conn's next read hits EOF and the spawned task returns —
        // a deterministic completion signal instead of a sleep-based poll.
        drop(w);
        drop(r);
        let _ = conn.await;

        let rendered = d.gauges.render(std::time::Instant::now());
        assert_eq!(rendered, "relayfabric_plugin_gauge{plugin=\"mocka\",name=\"rssi\"} -71\n",
            "name must be sanitized (lowercased) and the value preserved");
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

        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(&mut w, &PluginToDaemon::Hello {
            plugin: "mocka".into(),
            version: "0.1.0".into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: Capabilities::default(),
        }).await.unwrap();
        let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
        assert!(matches!(ack, DaemonToPlugin::HelloAck { error: None, .. }),
            "hello must be accepted: {ack:?}");

        let up_ev = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await.expect("timed out waiting for the connect event")
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
            .await.expect("timed out waiting for the disconnect event")
            .expect("disconnect must emit a Plugin event");
        match down_ev {
            Event::Plugin { name, up, .. } => {
                assert_eq!(name, "mocka");
                assert!(!up, "disconnect must report up: false");
            }
            other => panic!("expected Plugin, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hello_from_unknown_plugin_is_rejected_before_any_gauges_handling() {
        let dir = tempfile::tempdir().unwrap();
        let d = Arc::new(test_daemon(dir.path()));
        let (plugin_side, daemon_side) = UnixStream::pair().unwrap();

        let conn = tokio::spawn(handle_conn(d.clone(), daemon_side));

        let (mut r, mut w) = plugin_side.into_split();
        write_frame(&mut w, &PluginToDaemon::Hello {
            plugin: "not-configured".into(),
            version: "0.1.0".into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: Capabilities::default(),
        }).await.unwrap();
        let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
        assert!(matches!(&ack, DaemonToPlugin::HelloAck { error: Some(e), .. } if e == "unknown plugin"),
            "an unconfigured plugin name must be rejected: {ack:?}");
        let _ = conn.await;
    }
}
