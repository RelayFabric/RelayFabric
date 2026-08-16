mod admin;
mod alias;
mod cas;
mod config;
mod dedup;
mod engine;
mod metrics;
mod plugins;
mod policy;
mod queue;
mod routes;
mod storage;
mod transform;

use std::sync::Arc;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut config_path = String::from("/etc/relayfabric/relayfabric.yaml");
    let mut check_only = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config_path = args.next().expect("--config needs a path"),
            "--check-config" => check_only = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let cfg = match config::load(std::path::Path::new(&config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
    if check_only {
        println!("configuration valid: {} route(s), {} plugin(s)",
                 cfg.routes.len(), cfg.plugins.len());
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let data_dir = cfg.node.data_dir.clone();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let daemon = Arc::new(engine::Daemon::new(cfg, &data_dir).expect("daemon init"));
        let plugin_sock = data_dir.join("plugins.sock");
        let _ = std::fs::remove_file(&plugin_sock);
        let listener = tokio::net::UnixListener::bind(&plugin_sock).expect("bind plugin socket");
        tokio::spawn(plugins::listen(daemon.clone(), listener));
        for (name, pc) in &daemon.cfg.plugins {
            if pc.enabled {
                if let Some(cmd) = &pc.command {
                    tokio::spawn(plugins::supervise(
                        daemon.clone(), name.clone(), cmd.clone(), plugin_sock.clone()));
                }
            }
        }
        tokio::spawn(engine::pump(daemon.clone()));
        let admin_sock = data_dir.join("admin.sock");
        let _ = std::fs::remove_file(&admin_sock);
        let admin_listener =
            tokio::net::UnixListener::bind(&admin_sock).expect("bind admin socket");
        tokio::spawn(admin::serve(daemon.clone(), admin_listener));
        tracing::info!(node = daemon.cfg.node.name, "switchyardd running");
        tokio::signal::ctrl_c().await.expect("ctrl_c");
        tracing::info!("shutting down");
    });
}
