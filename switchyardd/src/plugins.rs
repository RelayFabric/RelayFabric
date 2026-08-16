use crate::engine::{self, Daemon, PluginHandle};
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
    let allowed = d.cfg.plugins.get(&plugin).map(|p| p.enabled).unwrap_or(false);
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

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_frame(&mut w, &msg).await.is_err() {
                break;
            }
        }
    });

    let result = loop {
        match read_frame::<_, PluginToDaemon>(&mut r).await {
            Ok(PluginToDaemon::Inbound { endpoint, sender, kind, body, created_at, .. }) => {
                engine::handle_inbound(&d, &plugin, endpoint, sender, kind, body, created_at);
            }
            Ok(PluginToDaemon::DeliveryResult { corr, delivered, detail }) => {
                engine::handle_result(&d, corr, delivered, detail);
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
    Err(result)
}

pub async fn supervise(d: Arc<Daemon>, name: String, command: String, socket: PathBuf) {
    let cfg_json = d.cfg.plugins.get(&name)
        .map(|p| serde_json::to_string(&p.config).unwrap_or_default())
        .unwrap_or_default();
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
