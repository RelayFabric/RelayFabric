use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use std::io;
use std::path::Path;

pub struct NodeIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl NodeIdentity {
    pub fn load_or_create(identity_dir: &Path) -> io::Result<Self> {
        // Same owner-only (0700) directory hardening every other data_dir
        // subdirectory gets — see `engine::create_data_dir`'s doc comment
        // for why both the mode and the post-hoc set_permissions matter.
        crate::engine::create_data_dir(identity_dir)?;

        let key_path = identity_dir.join("node.key");

        let seed_bytes = crate::keyfile::load_or_create_key32(&key_path, "node.key")?;

        let signing_key = SigningKey::from_bytes(&seed_bytes);
        let verifying_key = signing_key.verifying_key();

        Ok(NodeIdentity {
            signing_key,
            verifying_key,
        })
    }

    pub fn node_id(&self) -> String {
        let bytes = self.verifying_key.to_bytes();
        format!("rf:{}", hex::encode(bytes))
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing_key.sign(msg).to_bytes().to_vec()
    }
}

pub fn verify(node_id: &str, msg: &[u8], sig: &[u8]) -> bool {
    // Parse node_id of form "rf:..." where ... is 64 hex chars (32 bytes)
    let Some(hex_part) = node_id.strip_prefix("rf:") else {
        return false;
    };

    let Ok(bytes) = hex::decode(hex_part) else {
        return false;
    };

    let Ok(verifying_key_bytes): Result<[u8; 32], _> = bytes.try_into() else {
        return false;
    };

    let Ok(verifying_key) = VerifyingKey::from_bytes(&verifying_key_bytes) else {
        return false;
    };

    let Ok(signature) = ed25519_dalek::Signature::try_from(sig) else {
        return false;
    };

    verifying_key.verify_strict(msg, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_create_creates_new_identity() {
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_create(dir.path()).unwrap();
        let node_id = identity.node_id();
        assert!(node_id.starts_with("rf:"));
        // node_id should be "rf:" + 64 hex chars (32 bytes in hex)
        assert_eq!(node_id.len(), 3 + 64);
    }

    #[test]
    fn load_or_create_persists_and_reloads_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let identity1 = NodeIdentity::load_or_create(dir.path()).unwrap();
        let node_id1 = identity1.node_id();

        let identity2 = NodeIdentity::load_or_create(dir.path()).unwrap();
        let node_id2 = identity2.node_id();

        assert_eq!(node_id1, node_id2);
    }

    #[test]
    fn directory_permissions_are_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let identity_dir = dir.path().join("identity");
        NodeIdentity::load_or_create(&identity_dir).unwrap();
        let mode = std::fs::metadata(&identity_dir)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn key_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        NodeIdentity::load_or_create(dir.path()).unwrap();
        let key_path = dir.path().join("node.key");
        let mode = std::fs::metadata(&key_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn sign_and_verify_valid_message() {
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_create(dir.path()).unwrap();
        let node_id = identity.node_id();

        let msg = b"hello world";
        let sig = identity.sign(msg);

        assert!(verify(&node_id, msg, &sig));
    }

    #[test]
    fn verify_fails_for_tampered_message() {
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_create(dir.path()).unwrap();
        let node_id = identity.node_id();

        let msg = b"hello world";
        let sig = identity.sign(msg);

        let tampered = b"hello world!";
        assert!(!verify(&node_id, tampered, &sig));
    }

    #[test]
    fn verify_fails_for_wrong_node_id() {
        let dir = tempfile::tempdir().unwrap();
        let identity1 = NodeIdentity::load_or_create(&dir.path().join("id1")).unwrap();
        let identity2 = NodeIdentity::load_or_create(&dir.path().join("id2")).unwrap();

        let msg = b"hello world";
        let sig = identity1.sign(msg);
        let node_id2 = identity2.node_id();

        assert!(!verify(&node_id2, msg, &sig));
    }

    #[test]
    fn verify_fails_for_invalid_node_id_format() {
        let msg = b"hello world";
        let sig = [0u8; 64];

        assert!(!verify("invalid", msg, &sig));
        assert!(!verify("rf:", msg, &sig));
        assert!(!verify("rf:zz", msg, &sig));
    }
}
