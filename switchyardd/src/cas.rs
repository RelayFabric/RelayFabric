use crate::engine::create_data_dir;
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// Content-addressed store for attachment bytes: each blob is written once
/// under its sha256 hex digest as the filename. Reuses `create_data_dir`'s
/// 0700 hardening — attachment bytes are message content and must not be
/// world/group readable, same rationale as the top-level data dir.
pub struct Cas {
    dir: PathBuf,
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
    pub fn new(dir: &Path) -> io::Result<Cas> {
        create_data_dir(dir)?;
        Ok(Cas { dir: dir.to_path_buf() })
    }

    /// Writes `data` under its sha256 hex digest and returns that digest.
    /// Write-if-absent via temp-file-then-rename: the rename is atomic, so a
    /// crash mid-write never leaves a reader observing a partial blob, and a
    /// repeat `put` of identical bytes is a no-op past the existence check
    /// (idempotent).
    pub fn put(&self, data: &[u8]) -> io::Result<String> {
        let sha = hex::encode(Sha256::digest(data));
        let dest = self.dir.join(&sha);
        if dest.exists() {
            return Ok(sha);
        }
        let tmp = self.dir.join(format!(".{sha}.{}.tmp", std::process::id()));
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &dest)?;
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

    // Not yet called from production code: egress (rehydrating attachments
    // to send to a plugin) is a later task. Kept `pub` now because it's part
    // of the CAS interface contract and is exercised by this module's own
    // tests plus the engine ingress test (put-then-get roundtrip).
    #[allow(dead_code)]
    pub fn get(&self, sha: &str) -> io::Result<Vec<u8>> {
        std::fs::read(self.path_for(sha)?)
    }

    /// Idempotent: removing a sha that is already gone (e.g. a duplicate GC
    /// pass) is not an error, only a missing-on-disk blob for a sha that
    /// still fails validation is.
    pub fn remove(&self, sha: &str) -> io::Result<()> {
        let path = self.path_for(sha)?;
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
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
        let cas = Cas::new(&dir.path().join("attachments")).unwrap();
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
        let _c = Cas::new(&cas_dir).unwrap();
        let mode = std::fs::metadata(&cas_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "CAS dir must be owner-only");
    }
}
