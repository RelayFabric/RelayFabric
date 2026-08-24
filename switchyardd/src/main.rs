mod admin;
mod alerts;
mod alias;
mod backup;
mod cas;
mod config;
mod dedup;
mod engine;
mod events;
mod fed;
mod identity_links;
mod keyfile;
mod limits;
mod metrics;
mod node_identity;
mod plugins;
mod policy;
mod queue;
mod routes;
mod secrets;
mod storage;
mod transform;

use std::path::Path;
use std::sync::Arc;

/// Locks a just-bound unix-socket file down to owner-only (0600). The
/// parent `data_dir` is already created (and, if pre-existing with looser
/// permissions, tightened) to `0700` by `engine::create_data_dir`, and that
/// directory is the primary access gate -- but `UnixListener::bind` leaves
/// the socket file's own mode umask-derived (typically 0644/0755, not
/// tightened), so a future slip in the directory's permissions (a
/// misconfigured parent, a bind-mount, a restore from an older install)
/// would otherwise leave the socket file itself connectable beyond the
/// owning UID. This is a second belt, not a new gate: it does not add
/// authentication and does not change the same-UID access model (see
/// docs/api-reference.md's "Access control & security model"). A failure
/// here fails startup loudly rather than silently continuing with a
/// world-accessible socket.
fn harden_socket(path: &Path) -> std::io::Result<()> {
    set_socket_mode(path, 0o600)
}

/// v0.4 cycle B: a plugin socket with a configured `peer_uid` must be
/// connectable by that foreign uid, so it opens to 0666 -- the
/// `SO_PEERCRED` check in `plugins::handle_conn` is the gate there, not
/// the file mode. Without `peer_uid` the socket stays 0600.
fn set_socket_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// `switchyardd backup --out <dir>` / `restore --in <dir>`, both accepting an
/// optional `--config <path>` (default `/etc/relayfabric/relayfabric.yaml`) to
/// locate the node's `data_dir`.
fn run_subcommand(sub: &str, args: &[String]) {
    let mut config_path = String::from("/etc/relayfabric/relayfabric.yaml");
    let mut dir: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => config_path = it.next().cloned().unwrap_or_default(),
            "--out" | "--in" => dir = it.next().cloned(),
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let Some(dir) = dir else {
        eprintln!(
            "usage: switchyardd {sub} {} <dir> [--config <path>]",
            if sub == "backup" { "--out" } else { "--in" }
        );
        std::process::exit(2);
    };
    let result = if sub == "backup" {
        backup::run_backup(&config_path, std::path::Path::new(&dir))
    } else {
        backup::run_restore(&config_path, std::path::Path::new(&dir))
    };
    if let Err(e) = result {
        eprintln!("{sub} failed: {e}");
        std::process::exit(1);
    }
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    // Subcommands (backup/restore) operate on a node's state offline and then
    // exit; they share the --config flag but not the daemon run loop.
    if let Some(sub) = raw.first().map(String::as_str) {
        if sub == "backup" || sub == "restore" {
            run_subcommand(sub, &raw[1..]);
            return;
        }
    }
    let mut args = raw.into_iter();
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
        println!(
            "configuration valid: {} route(s), {} plugin(s)",
            cfg.routes.len(),
            cfg.plugins.len()
        );
        return;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let data_dir = cfg.node.data_dir.clone();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let daemon = Arc::new(engine::Daemon::new(cfg, &data_dir).expect("daemon init"));
        // Per-plugin sockets (v0.4 cycle B): every enabled plugin gets its
        // own listener at <data_dir>/plugins.d/<name>.sock, bound to its
        // name -- a connection can only become the plugin its socket is
        // for, and each socket carries its own peer-uid policy.
        let plugin_sock_dir = data_dir.join("plugins.d");
        engine::create_data_dir(&plugin_sock_dir).expect("create plugin socket dir");
        let plugin_configs = daemon.cfg_snapshot(|c| c.plugins.clone());
        // Isolation deployments (any peer_uid configured) need the foreign
        // plugin uid to TRAVERSE into the socket dir: 0711 grants search
        // only -- non-owner processes still can't list it, and each socket
        // keeps its own mode + the SO_PEERCRED gate. The data_dir itself
        // must then also be traversable (0711); see
        // deploy/systemd/switchyardd.service.
        if plugin_configs
            .values()
            .any(|p| p.enabled && p.peer_uid.is_some())
        {
            set_socket_mode(&plugin_sock_dir, 0o711).expect("open plugin socket dir for traversal");
        }
        for (name, pc) in &plugin_configs {
            if !pc.enabled {
                continue;
            }
            let sock = plugin_sock_dir.join(format!("{name}.sock"));
            let _ = std::fs::remove_file(&sock);
            let listener = tokio::net::UnixListener::bind(&sock).expect("bind plugin socket");
            let mode = if pc.peer_uid.is_some() { 0o666 } else { 0o600 };
            set_socket_mode(&sock, mode).expect("harden plugin socket permissions");
            tokio::spawn(plugins::listen(daemon.clone(), listener, name.clone()));
            if let Some(cmd) = &pc.command {
                tokio::spawn(plugins::supervise(
                    daemon.clone(),
                    name.clone(),
                    cmd.clone(),
                    sock.clone(),
                ));
            }
        }
        // Supervise the delivery pump: a transient panic must not silently
        // halt all delivery for the life of the process (see engine::supervise).
        tokio::spawn(engine::supervise(
            "delivery-pump",
            std::time::Duration::from_secs(1),
            {
                let d = daemon.clone();
                move || engine::pump(d.clone())
            },
        ));
        if let Some(fed_cfg) = daemon.cfg_snapshot(|c| c.federation.clone()) {
            fed::conn::spawn_federation(daemon.clone(), fed_cfg);
        }
        // Operator self-alerting: watches the event stream and notifies over a
        // configured plugin when `alerts:` is set (read live; no-op otherwise).
        alerts::spawn_alerter(daemon.clone());
        let admin_sock = data_dir.join("admin.sock");
        let _ = std::fs::remove_file(&admin_sock);
        let admin_listener =
            tokio::net::UnixListener::bind(&admin_sock).expect("bind admin socket");
        harden_socket(&admin_sock).expect("harden admin socket permissions");
        tokio::spawn(admin::serve(
            daemon.clone(),
            std::path::PathBuf::from(config_path),
            admin_listener,
        ));
        tracing::info!(
            node = daemon.cfg_snapshot(|c| c.node.name.clone()),
            "switchyardd running"
        );
        // Shut down on SIGINT (ctrl-c) OR SIGTERM (systemd `stop`, docker
        // stop). Previously only ctrl_c was awaited, so under systemd a
        // SIGTERM took the default disposition -- immediate death, skipping
        // the graceful plugin shutdown below.
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
            tokio::select! {
                r = tokio::signal::ctrl_c() => { r.expect("ctrl_c"); }
                _ = term.recv() => {}
            }
        }
        tracing::info!("shutting down");
        // Best-effort graceful plugin shutdown: let each plugin release its
        // resources (radios, sockets) before we exit and kill_on_drop reaps
        // whatever remains.
        let signalled = daemon.request_plugin_shutdown();
        if signalled > 0 {
            tracing::info!(plugins = signalled, "sent shutdown to plugins");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn harden_socket_locks_a_bound_socket_file_to_0600() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        // Bind leaves the file's mode umask-derived (typically 0644/0755,
        // never as tight as 0600 under a normal umask) -- this is the
        // pre-condition harden_socket exists to fix.
        let _listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
        let before = std::fs::metadata(&sock_path).unwrap().permissions().mode() & 0o777;
        assert_ne!(
            before, 0o600,
            "test assumption: a fresh bind isn't already 0600"
        );

        harden_socket(&sock_path).unwrap();

        let after = std::fs::metadata(&sock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            after, 0o600,
            "harden_socket must lock the socket file to owner-only 0600"
        );
    }
}
