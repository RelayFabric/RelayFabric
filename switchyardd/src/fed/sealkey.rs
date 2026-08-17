//! Sealed keypair (design doc §1, SPEC §113.3: "keys anchor to §112.6 node
//! identities"): a per-node X25519 keypair used as the sealed-routing
//! RECIPIENT key -- distinct from the Ed25519 node identity
//! (`node_identity::NodeIdentity`) and from the rotating Noise transit
//! static key (`fed::noise::StaticKey`, `data_dir/fed_static.key`). This one
//! is STABLE for this cycle (no rotation story yet -- documented, not
//! hidden): a peer that learns this node's `sealed_key` today can keep
//! encrypting to it indefinitely.
//!
//! Persisted `data_dir/sealed.key` (0600, raw 32-byte hex) -- exactly the
//! `fed_static.key`/`alias.key` on-disk shape (`fed::noise::StaticKey`/
//! `alias::Aliaser` precedent): only the raw random scalar is written; the
//! public key is re-derived on every load.
//!
//! Type choice (Task 1 review binding note, carried into Task 2): the
//! secret is a `crypto_box::SecretKey`, not a raw `[u8; 32]` or an
//! `x25519_dalek::StaticSecret` -- `crypto_box::ChaChaBox::new` (the AEAD
//! Task 2's `fed::seal` builds on) takes a `crypto_box::SecretKey`/
//! `crypto_box::PublicKey` pair directly, so storing that exact type here
//! means Task 2's `unseal` never has to convert between crate-specific key
//! representations. `SecretKey::from_bytes` clamps internally (RFC 7748,
//! same `clamp_integer` construction `curve25519-dalek` uses for
//! `fed::noise::StaticKey`'s own derivation), so the raw bytes on disk need
//! no clamping of their own before being written or after being read.
//!
//! Consumed by `fed::advert::build_from_config` (this task: publishes
//! `public()` as the advert's `security.sealed_key`) and by Task 2's
//! `fed::seal::unseal` (the raw `secret()` handle this module exposes).

use crypto_box::SecretKey;
use std::io;
use std::path::Path;

/// A node's persisted sealed-routing X25519 static keypair.
pub struct SealedKey {
    secret: SecretKey,
}

impl SealedKey {
    /// Loads `path` if it exists, else generates a fresh key and persists it
    /// (0600, create_new -- fails rather than silently overwriting a
    /// concurrently-created file) before reading it back. Mirrors
    /// `fed::noise::StaticKey::load_or_create`/`alias::Aliaser::
    /// load_or_create` byte-for-byte: `path` names the key FILE directly
    /// (not a directory), unlike `node_identity::NodeIdentity::
    /// load_or_create`.
    pub fn load_or_create(path: &Path) -> io::Result<SealedKey> {
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
            // Final-review polish (defense-in-depth, cycle H): this
            // transient generation buffer is a SEPARATE stack copy of the
            // raw secret scalar from the one `SecretKey::from_bytes` holds
            // below (re-derived from the file we just read back) -- zero
            // it here rather than letting it linger until the frame
            // unwinds, on both the success and the (disk-full-class)
            // error path. This closes only the LOCAL transient-copy gap;
            // `crypto_box::SecretKey` itself not zeroizing on drop is a
            // documented, out-of-scope, upstream crate gap, not something
            // this change attempts to fix.
            use zeroize::Zeroize;
            key.zeroize();
            write_result?;
        }
        let raw = std::fs::read_to_string(path)?;
        let bytes = hex::decode(raw.trim()).map_err(io::Error::other)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| io::Error::other("sealed key must be 32 bytes of hex"))?;
        Ok(SealedKey { secret: SecretKey::from_bytes(bytes) })
    }

    /// The raw 32-byte X25519 public key -- what `fed::advert::
    /// build_from_config` hex-encodes into `SecurityCaps::sealed_key`.
    pub fn public(&self) -> [u8; 32] {
        self.secret.public_key().to_bytes()
    }

    /// The static secret key, for Task 2's `ChaChaBox::new(&epk,
    /// &sealed_key.secret())`-shaped unseal. Not exposed as owned/cloned --
    /// `crypto_box::SecretKey` is not `Copy` and zeroizes on drop, so
    /// callers borrow it for the duration of a single seal/unseal call.
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_generates_a_new_key_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealed.key");
        assert!(!path.exists());
        let key = SealedKey::load_or_create(&path).unwrap();
        assert!(path.exists());
        // A real X25519 public key: 32 bytes, not all-zero.
        assert_eq!(key.public().len(), 32);
        assert_ne!(key.public(), [0u8; 32]);
    }

    #[test]
    fn load_or_create_persists_and_reloads_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealed.key");
        let a = SealedKey::load_or_create(&path).unwrap();
        let b = SealedKey::load_or_create(&path).unwrap();
        assert_eq!(a.public(), b.public());
    }

    #[test]
    fn distinct_paths_get_distinct_keys() {
        let dir = tempfile::tempdir().unwrap();
        let a = SealedKey::load_or_create(&dir.path().join("a.key")).unwrap();
        let b = SealedKey::load_or_create(&dir.path().join("b.key")).unwrap();
        assert_ne!(a.public(), b.public());
    }

    #[test]
    fn key_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealed.key");
        SealedKey::load_or_create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn on_disk_format_is_64_lowercase_hex_chars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealed.key");
        SealedKey::load_or_create(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(raw.len(), 64);
        assert!(raw.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn public_key_matches_the_persisted_secret_scalar() {
        // Same on-disk secret bytes, loaded independently, must derive an
        // identical public key every time -- not just "some" stable value
        // (the previous test), but the specific X25519 base-point
        // multiplication `crypto_box::SecretKey::public_key` performs.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sealed.key");
        let key = SealedKey::load_or_create(&path).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let bytes: [u8; 32] = hex::decode(raw.trim()).unwrap().try_into().unwrap();
        let expected = crypto_box::SecretKey::from_bytes(bytes).public_key().to_bytes();
        assert_eq!(key.public(), expected);
    }

    #[test]
    fn secret_round_trips_through_a_chachabox_seal_open() {
        // Exercises the exact type Task 2's `fed::seal` will use
        // (`crypto_box::ChaChaBox`), proving `SealedKey::secret()` hands
        // back a key usable for a real X25519 + XChaCha20-Poly1305
        // operation, not just a type that happens to compile.
        use crypto_box::aead::{Aead, AeadCore};
        use crypto_box::ChaChaBox;

        let dir = tempfile::tempdir().unwrap();
        let recipient = SealedKey::load_or_create(&dir.path().join("recipient.key")).unwrap();

        let ephemeral = crypto_box::SecretKey::generate(&mut rand::rngs::OsRng);
        let recipient_pub = crypto_box::PublicKey::from(recipient.public());
        let sender_box = ChaChaBox::new(&recipient_pub, &ephemeral);
        let nonce = ChaChaBox::generate_nonce(&mut rand::rngs::OsRng);
        let ct = sender_box.encrypt(&nonce, b"hello sealed routing".as_ref()).unwrap();

        let recipient_box = ChaChaBox::new(&ephemeral.public_key(), recipient.secret());
        let pt = recipient_box.decrypt(&nonce, ct.as_ref()).unwrap();
        assert_eq!(pt, b"hello sealed routing");
    }
}
