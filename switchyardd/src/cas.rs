use crate::engine::create_data_dir;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Content-addressed store for attachment bytes: each blob is written once
/// under its sha256 hex digest as the filename. Reuses `create_data_dir`'s
/// 0700 hardening — attachment bytes are message content and must not be
/// world/group readable, same rationale as the top-level data dir.
pub struct Cas {
    dir: PathBuf,
    /// 0 = unlimited (config `limits.global.cas_max_bytes`, spec §45 disk
    /// limits).
    budget_bytes: u64,
    /// Running total of live blob bytes under `dir`. Seeded by a dir-walk in
    /// `new` (so a restart picks up whatever's already on disk) and kept
    /// current by `put` (add) and `remove` (subtract) — the subtract half
    /// matters as much as the add half: without it, GC'd/purged blobs would
    /// never free up budget, and a long-running daemon would eventually
    /// refuse every `put` regardless of how much disk `purge_terminal` had
    /// actually reclaimed. `Relaxed` ordering throughout: this is a
    /// best-effort budget, not a linearizable allocator, the same trade-off
    /// as every other counter in `metrics.rs`.
    total_bytes: AtomicU64,
}

/// True iff `e` is the specific error `put` returns when a write would push
/// `total_bytes` over `budget_bytes` — discriminated by `ErrorKind`, not by
/// message text. `engine::handle_inbound` uses this to give a budget
/// refusal its own drop note (`cas budget exceeded`) instead of the generic
/// "attachment unavailable" one used for every other I/O failure.
pub fn is_budget_exceeded(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::QuotaExceeded
}

/// Sums the size of every regular file directly under `dir`. Used once, at
/// `Cas::new`, to recover `total_bytes` after a restart; a directory entry
/// that vanishes mid-walk (e.g. a concurrent GC pass) or whose metadata
/// can't be read is skipped rather than failing the whole walk.
///
/// Known ceiling, not fixed here: this counts every regular file, including
/// a `.<sha>.<pid>.tmp` staging file orphaned by a crash between `put`'s
/// `write` and its atomic `rename` (nothing currently cleans those up). An
/// orphaned tmp file therefore inflates the recovered `total_bytes` above
/// what's actually reachable as a real blob, shrinking effective budget
/// until the file is removed by hand.
fn existing_bytes(dir: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        if let Ok(meta) = entry.metadata() {
            if meta.is_file() {
                total += meta.len();
            }
        }
    }
    Ok(total)
}

/// True iff `sha` is exactly 64 lowercase hex characters. This is the sole
/// gate between caller-supplied strings and filesystem paths in `get`/
/// `remove`: a sha that fails this check is rejected before it ever touches
/// `Path::join`, so `../../etc/passwd` (or any string containing `/`, `.`,
/// or uppercase hex) can never be used to escape `dir`.
fn is_valid_sha(sha: &str) -> bool {
    sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Cas {
    pub fn new(dir: &Path, budget_bytes: u64) -> io::Result<Cas> {
        create_data_dir(dir)?;
        let total_bytes = existing_bytes(dir)?;
        Ok(Cas { dir: dir.to_path_buf(), budget_bytes, total_bytes: AtomicU64::new(total_bytes) })
    }

    /// Writes `data` under its sha256 hex digest and returns that digest.
    /// Write-if-absent via temp-file-then-rename: the rename is atomic, so a
    /// crash mid-write never leaves a reader observing a partial blob, and a
    /// repeat `put` of identical bytes is a no-op past the existence check
    /// (idempotent) — including past the budget check below, since it adds
    /// no new bytes to disk.
    ///
    /// Refuses (an `is_budget_exceeded` error, never touching disk) when a
    /// *new* blob would push `total_bytes` over a configured `budget_bytes`.
    /// The load-then-add below isn't a compare-and-swap, so two concurrent
    /// `put`s can both pass the check and both add — a benign, bounded
    /// overshoot rather than a hard guarantee, matching the "best-effort
    /// budget" note on `total_bytes`.
    pub fn put(&self, data: &[u8]) -> io::Result<String> {
        let sha = hex::encode(Sha256::digest(data));
        let dest = self.dir.join(&sha);
        if dest.exists() {
            return Ok(sha);
        }
        let size = data.len() as u64;
        if self.budget_bytes > 0
            && self.total_bytes.load(Ordering::Relaxed) + size > self.budget_bytes
        {
            return Err(io::Error::new(io::ErrorKind::QuotaExceeded, "cas budget exceeded"));
        }
        let tmp = self.dir.join(format!(".{sha}.{}.tmp", std::process::id()));
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &dest)?;
        self.total_bytes.fetch_add(size, Ordering::Relaxed);
        Ok(sha)
    }

    fn path_for(&self, sha: &str) -> io::Result<PathBuf> {
        if !is_valid_sha(sha) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sha256 must be exactly 64 lowercase hex characters",
            ));
        }
        Ok(self.dir.join(sha))
    }

    /// Rehydrates a blob's bytes for egress (`engine::load_attachments`
    /// reads accepted attachments back out here to build an outgoing Send).
    pub fn get(&self, sha: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.path_for(sha)?)
    }

    /// Idempotent: removing a sha that is already gone (e.g. a duplicate GC
    /// pass) is not an error, only a missing-on-disk blob for a sha that
    /// still fails validation is. Frees the removed blob's bytes back to the
    /// budget (see `total_bytes`) — stat-then-remove rather than
    /// remove-then-trust-the-old-size, so a size read that fails (already
    /// gone) simply skips the decrement instead of risking an underflow.
    ///
    /// The decrement itself is a saturating subtract (via `fetch_update`,
    /// not a plain `fetch_sub`): if `total_bytes` were ever undercounted —
    /// e.g. `existing_bytes`'s startup dir-walk missed a blob, or two
    /// `remove`s raced on the same size — a bare `fetch_sub` could wrap a
    /// `u64` counter around to a huge value, and every `put` would then
    /// refuse until the next restart. Saturating at zero instead just
    /// under-accounts (the budget looks emptier than it is), which is the
    /// safe direction to be wrong in.
    pub fn remove(&self, sha: &str) -> io::Result<()> {
        let path = self.path_for(sha)?;
        let size = std::fs::metadata(&path).ok().map(|m| m.len());
        match std::fs::remove_file(path) {
            Ok(()) => {
                if let Some(size) = size {
                    let _ = self.total_bytes.fetch_update(
                        Ordering::Relaxed, Ordering::Relaxed,
                        |cur| Some(cur.saturating_sub(size)),
                    );
                }
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn cas() -> (tempfile::TempDir, Cas) {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::new(&dir.path().join("attachments"), 0).unwrap();
        (dir, cas)
    }

    #[test]
    fn put_get_roundtrip() {
        let (_d, c) = cas();
        let sha = c.put(b"hello world").unwrap();
        assert_eq!(sha, hex::encode(Sha256::digest(b"hello world")));
        assert_eq!(c.get(&sha).unwrap(), b"hello world");
    }

    #[test]
    fn put_is_idempotent() {
        let (_d, c) = cas();
        let sha1 = c.put(b"same content").unwrap();
        let sha2 = c.put(b"same content").unwrap();
        assert_eq!(sha1, sha2);
        assert_eq!(c.get(&sha1).unwrap(), b"same content");
    }

    #[test]
    fn remove_deletes_the_blob() {
        let (_d, c) = cas();
        let sha = c.put(b"gone soon").unwrap();
        c.remove(&sha).unwrap();
        assert!(c.get(&sha).is_err());
    }

    #[test]
    fn remove_of_missing_sha_is_a_noop_not_an_error() {
        let (_d, c) = cas();
        let never_written = "a".repeat(64);
        assert!(c.remove(&never_written).is_ok());
    }

    #[test]
    fn get_rejects_anything_that_is_not_64_lowercase_hex_chars() {
        let (_d, c) = cas();
        assert!(c.get("../../etc/passwd").is_err(), "traversal string must be rejected");
        assert!(c.get("short").is_err(), "too-short sha must be rejected");
        assert!(c.get(&"A".repeat(64)).is_err(), "uppercase hex must be rejected");
        assert!(c.get(&"g".repeat(64)).is_err(), "non-hex char must be rejected");
        // exactly 64 chars but with a traversal separator baked in
        let crafted = format!("{}/{}", "a".repeat(31), "b".repeat(32));
        assert_eq!(crafted.len(), 64);
        assert!(c.get(&crafted).is_err(), "embedded '/' must be rejected");
    }

    #[test]
    fn remove_rejects_invalid_sha_too() {
        let (_d, c) = cas();
        assert!(c.remove("../evil").is_err());
    }

    #[test]
    fn new_creates_dir_with_owner_only_perms() {
        let base = tempfile::tempdir().unwrap();
        let cas_dir = base.path().join("attachments");
        let _c = Cas::new(&cas_dir, 0).unwrap();
        let mode = std::fs::metadata(&cas_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "CAS dir must be owner-only");
    }

    #[test]
    fn zero_budget_is_unlimited() {
        let (_d, c) = cas();
        c.put(&[0u8; 1_000_000]).unwrap();
    }

    #[test]
    fn put_refuses_a_new_blob_that_would_exceed_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cas::new(&dir.path().join("attachments"), 10).unwrap();
        c.put(&[1u8; 6]).unwrap();
        let err = c.put(&[2u8; 6]).unwrap_err(); // 6 + 6 > 10
        assert!(is_budget_exceeded(&err), "err was: {err}");
    }

    #[test]
    fn put_of_an_already_stored_blob_is_exempt_from_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cas::new(&dir.path().join("attachments"), 6).unwrap();
        let sha = c.put(&[1u8; 6]).unwrap(); // fills the budget exactly
        // re-putting the same bytes adds nothing new, so it must not refuse
        // even though the budget is already exhausted.
        assert_eq!(c.put(&[1u8; 6]).unwrap(), sha);
    }

    #[test]
    fn remove_frees_budget_for_a_later_put() {
        let dir = tempfile::tempdir().unwrap();
        let c = Cas::new(&dir.path().join("attachments"), 10).unwrap();
        let sha = c.put(&[1u8; 10]).unwrap(); // fills the budget exactly
        assert!(is_budget_exceeded(&c.put(&[2u8; 5]).unwrap_err()));
        c.remove(&sha).unwrap();
        // budget is free again, so a new (differently-shaped) blob now fits.
        c.put(&[2u8; 5]).unwrap();
    }

    #[test]
    fn new_recovers_total_bytes_from_a_dir_walk_so_a_restart_honors_prior_usage() {
        let dir = tempfile::tempdir().unwrap();
        let cas_dir = dir.path().join("attachments");
        {
            let c = Cas::new(&cas_dir, 0).unwrap(); // unlimited, to seed the blob
            c.put(&[9u8; 6]).unwrap();
        }
        // fresh Cas over the same directory, this time budgeted: it must
        // dir-walk and see the 6 bytes already on disk from the line above,
        // not start from zero.
        let c = Cas::new(&cas_dir, 10).unwrap();
        let err = c.put(&[8u8; 6]).unwrap_err(); // 6 (existing) + 6 > 10
        assert!(is_budget_exceeded(&err), "err was: {err}");
    }
}
