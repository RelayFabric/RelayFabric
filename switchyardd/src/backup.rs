//! `switchyardd backup` / `restore`: snapshot and restore a node's full state
//! (SQLite queue/DB, identity keys, and the CAS attachment store) so a
//! self-hoster can protect or migrate a node. The config file's own `.prev`
//! rotation already covers the config; this covers everything else in
//! `data_dir`.
//!
//! The backup is a plain DIRECTORY (rsync/tar it yourself) rather than an
//! archive, so no compression/archive dependency is pulled in. The live
//! SQLite database is copied with `VACUUM INTO`, which produces a consistent
//! single-file snapshot even while the daemon is running (WAL mode allows a
//! concurrent reader); every other file is either static (keys) or written
//! atomically (CAS write-then-rename), so a plain copy is safe. For a
//! guaranteed-quiescent backup, stop the daemon first.

use crate::config;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

const DB_FILE: &str = "relayfabric.db";
const MANIFEST: &str = "BACKUP_MANIFEST";

/// Names under `data_dir` that must NOT be copied: the live DB (snapshotted
/// separately via VACUUM), its transient WAL/SHM sidecars, and the runtime
/// sockets (recreated by the daemon on start).
fn is_excluded(name: &str) -> bool {
    matches!(
        name,
        DB_FILE | "relayfabric.db-wal" | "relayfabric.db-shm" | "admin.sock" | "plugins.d"
    )
}

/// Recursively copy `src` into `dst` (created if missing), skipping excluded
/// top-level names and any Unix socket/FIFO/device special files. File
/// permission bits are preserved (`fs::copy` copies mode on Unix), so 0600
/// key files stay 0600.
fn copy_tree(src: &Path, dst: &Path, top_level: bool) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
    for entry in fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if top_level && is_excluded(&name_str) {
            continue;
        }
        let ft = entry.file_type().map_err(|e| e.to_string())?;
        // Never copy sockets/FIFOs/devices — a backup is data, not runtime.
        if ft.is_socket() || ft.is_fifo() || ft.is_block_device() || ft.is_char_device() {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        if ft.is_dir() {
            copy_tree(&from, &to, false)?;
        } else {
            fs::copy(&from, &to).map_err(|e| format!("copy {}: {e}", from.display()))?;
        }
    }
    Ok(())
}

/// Core backup: snapshot `data_dir` into `out` (a fresh or empty directory).
/// The DB goes through `VACUUM INTO` for a consistent copy; everything else
/// is copied verbatim minus the exclusions. Testable without a full config.
pub fn snapshot(data_dir: &Path, out: &Path) -> Result<(), String> {
    if !data_dir.is_dir() {
        return Err(format!("data_dir {} does not exist", data_dir.display()));
    }
    fs::create_dir_all(out).map_err(|e| format!("create {}: {e}", out.display()))?;
    // Owner-only, same posture as data_dir itself.
    let _ = fs::set_permissions(out, std::os::unix::fs::PermissionsExt::from_mode(0o700));

    let db = data_dir.join(DB_FILE);
    if db.is_file() {
        // Open read-only and VACUUM INTO a fresh file in `out`. A concurrent
        // running daemon (WAL) is fine: VACUUM INTO takes a consistent copy.
        let conn = rusqlite::Connection::open_with_flags(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| format!("open db {}: {e}", db.display()))?;
        let out_db = out.join(DB_FILE);
        // rusqlite has no typed VACUUM INTO; use execute with the path bound
        // as a literal (path is operator-supplied, not attacker input).
        conn.execute("VACUUM INTO ?1", [out_db.to_string_lossy().as_ref()])
            .map_err(|e| format!("vacuum into {}: {e}", out_db.display()))?;
    }

    copy_tree(data_dir, out, true)?;

    let manifest = format!(
        "relayfabric backup v1\ncreated_at={}\nsource_data_dir={}\n",
        chrono::Utc::now().to_rfc3339(),
        data_dir.display()
    );
    fs::write(out.join(MANIFEST), manifest).map_err(|e| format!("write manifest: {e}"))?;
    Ok(())
}

/// Core restore: copy a backup directory's contents back into `data_dir`
/// (created if missing). Overwrites existing files. Testable directly.
pub fn restore_into(input: &Path, data_dir: &Path) -> Result<(), String> {
    if !input.join(MANIFEST).is_file() {
        return Err(format!(
            "{} does not look like a relayfabric backup (no {MANIFEST})",
            input.display()
        ));
    }
    fs::create_dir_all(data_dir).map_err(|e| format!("create {}: {e}", data_dir.display()))?;
    let _ = fs::set_permissions(
        data_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    );
    for entry in fs::read_dir(input).map_err(|e| format!("read {}: {e}", input.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        if name == MANIFEST {
            continue; // metadata, not restored into data_dir
        }
        let from = entry.path();
        let to = data_dir.join(&name);
        let ft = entry.file_type().map_err(|e| e.to_string())?;
        if ft.is_dir() {
            copy_tree(&from, &to, false)?;
        } else {
            fs::copy(&from, &to).map_err(|e| format!("copy {}: {e}", from.display()))?;
        }
    }
    Ok(())
}

/// Whether a daemon appears to be running against `data_dir` — a connectable
/// `admin.sock`. Restore refuses in that case (a live daemon would overwrite
/// or corrupt the restored DB). ENOENT/refused means safe to proceed.
fn daemon_running(data_dir: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(data_dir.join("admin.sock")).is_ok()
}

/// `switchyardd backup --config <path> --out <dir>`.
pub fn run_backup(config_path: &str, out: &Path) -> Result<(), String> {
    let cfg = config::load(Path::new(config_path)).map_err(|e| format!("config error: {e}"))?;
    snapshot(&cfg.node.data_dir, out)?;
    println!(
        "backed up {} to {}",
        cfg.node.data_dir.display(),
        out.display()
    );
    Ok(())
}

/// `switchyardd restore --config <path> --in <dir>`.
pub fn run_restore(config_path: &str, input: &Path) -> Result<(), String> {
    let cfg = config::load(Path::new(config_path)).map_err(|e| format!("config error: {e}"))?;
    if daemon_running(&cfg.node.data_dir) {
        return Err(format!(
            "a daemon appears to be running against {} (admin.sock is live); \
             stop it before restoring",
            cfg.node.data_dir.display()
        ));
    }
    restore_into(input, &cfg.node.data_dir)?;
    println!(
        "restored {} into {}",
        input.display(),
        cfg.node.data_dir.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn seed_data_dir(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        // a real SQLite DB with a row we can read back after restore
        let conn = rusqlite::Connection::open(dir.join(DB_FILE)).unwrap();
        conn.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t(v) VALUES('hello-backup');")
            .unwrap();
        drop(conn);
        // a 0600 key file, a CAS blob, transient WAL/SHM, and a socket
        fs::write(dir.join("node.key"), b"secretkey").unwrap();
        fs::set_permissions(dir.join("node.key"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::create_dir_all(dir.join("attachments")).unwrap();
        fs::write(dir.join("attachments").join("ab12"), b"blobdata").unwrap();
        fs::write(dir.join("relayfabric.db-wal"), b"transient").unwrap();
        std::os::unix::net::UnixListener::bind(dir.join("admin.sock")).unwrap();
        fs::create_dir_all(dir.join("plugins.d")).unwrap();
    }

    #[test]
    fn snapshot_copies_state_and_excludes_runtime_files() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        seed_data_dir(src.path());

        snapshot(src.path(), &out.path().join("snap")).unwrap();
        let snap = out.path().join("snap");

        assert!(snap.join(DB_FILE).is_file(), "DB must be snapshotted");
        assert!(snap.join("node.key").is_file(), "keys must be backed up");
        assert_eq!(
            fs::read(snap.join("attachments").join("ab12")).unwrap(),
            b"blobdata",
            "CAS blobs must be backed up"
        );
        assert!(snap.join(MANIFEST).is_file(), "manifest must be written");
        // excluded: WAL sidecar, sockets, plugins.d
        assert!(
            !snap.join("relayfabric.db-wal").exists(),
            "WAL must be excluded"
        );
        assert!(
            !snap.join("admin.sock").exists(),
            "sockets must be excluded"
        );
        assert!(
            !snap.join("plugins.d").exists(),
            "plugins.d must be excluded"
        );
        // key perms preserved
        let mode = fs::metadata(snap.join("node.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "key file mode must be preserved");
    }

    #[test]
    fn restore_roundtrips_the_db_and_keys_into_a_fresh_data_dir() {
        let src = tempfile::tempdir().unwrap();
        let snapdir = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        seed_data_dir(src.path());
        let snap = snapdir.path().join("snap");
        snapshot(src.path(), &snap).unwrap();

        let data_dir = dest.path().join("data");
        restore_into(&snap, &data_dir).unwrap();

        // DB row survives the VACUUM-INTO -> restore roundtrip
        let conn = rusqlite::Connection::open(data_dir.join(DB_FILE)).unwrap();
        let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "hello-backup");
        assert_eq!(fs::read(data_dir.join("node.key")).unwrap(), b"secretkey");
        assert_eq!(
            fs::read(data_dir.join("attachments").join("ab12")).unwrap(),
            b"blobdata"
        );
    }

    #[test]
    fn restore_rejects_a_non_backup_directory() {
        let notbackup = tempfile::tempdir().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let err = restore_into(notbackup.path(), &dest.path().join("d")).unwrap_err();
        assert!(
            err.contains("does not look like a relayfabric backup"),
            "{err}"
        );
    }
}
