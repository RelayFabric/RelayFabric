//! The one "create-if-absent, 0600, 32-byte-hex secret file" loader shared
//! by every key call site (alias, fed static, sealed-routing, node
//! identity) that used to carry a byte-identical copy of this body.

use std::io;
use std::path::Path;

/// Loads `path` as 32 bytes of hex if it exists, else generates a fresh key
/// and persists it (0600, `create_new` -- fails rather than silently
/// overwriting a concurrently-created file) before reading it back. `what`
/// names the key in the malformed-file error.
pub fn load_or_create_key32(path: &Path, what: &str) -> io::Result<[u8; 32]> {
    if !path.exists() {
        let mut key: [u8; 32] = rand::random();
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let write_result = f.write_all(hex::encode(key).as_bytes());
        // Zero the transient generation buffer rather than letting it
        // linger until the frame unwinds, on both the success and the
        // (disk-full-class) error path -- defense-in-depth carried from
        // the sealed-key loader; callers re-derive from the file below.
        use zeroize::Zeroize;
        key.zeroize();
        write_result?;
    }
    let raw = std::fs::read_to_string(path)?;
    let bytes = hex::decode(raw.trim()).map_err(io::Error::other)?;
    bytes
        .try_into()
        .map_err(|_| io::Error::other(format!("{what} must be 32 bytes of hex")))
}
