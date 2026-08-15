use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io;
use std::path::Path;

pub struct Aliaser {
    pub(crate) key: [u8; 32],
}

impl Aliaser {
    pub fn load_or_create(path: &Path) -> io::Result<Aliaser> {
        if !path.exists() {
            let key: [u8; 32] = rand::random();
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(hex::encode(key).as_bytes())?;
        }
        let raw = std::fs::read_to_string(path)?;
        let bytes = hex::decode(raw.trim()).map_err(io::Error::other)?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| io::Error::other("alias key must be 32 bytes of hex"))?;
        Ok(Aliaser { key })
    }

    pub fn alias(&self, protocol: &str, native_ref: &str, scope: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("hmac accepts any key len");
        mac.update(format!("{protocol}|{native_ref}|{scope}").as_bytes());
        let out = mac.finalize().into_bytes();
        let prefix: String = protocol.chars().take(4).collect::<String>().to_uppercase();
        // ponytail: 16-bit alias space; collisions merge personas within a
        // scope. Widen to 6 hex chars if a deployment ever grows past ~hundreds
        // of senders per route.
        format!("{prefix}-{:02X}{:02X}", out[0], out[1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aliaser() -> Aliaser {
        Aliaser { key: [7u8; 32] }
    }

    #[test]
    fn alias_is_stable_within_scope() {
        let a = aliaser();
        assert_eq!(
            a.alias("meshtastic", "!abcd1234", "route-a"),
            a.alias("meshtastic", "!abcd1234", "route-a"),
        );
    }

    #[test]
    fn alias_differs_across_scopes_and_senders() {
        let a = aliaser();
        let base = a.alias("meshtastic", "!abcd1234", "route-a");
        assert_ne!(base, a.alias("meshtastic", "!abcd1234", "route-b"));
        assert_ne!(base, a.alias("meshtastic", "!ffff0000", "route-a"));
    }

    #[test]
    fn alias_format_is_prefix_dash_4hex() {
        let alias = aliaser().alias("meshtastic", "!abcd1234", "r");
        let (prefix, hexpart) = alias.split_once('-').unwrap();
        assert_eq!(prefix, "MESH");
        assert_eq!(hexpart.len(), 4);
        assert!(hexpart.chars().all(|c| c.is_ascii_hexdigit() && !c.is_lowercase()));
        // short protocol names keep their full name
        assert!(aliaser().alias("mqtt", "x", "r").starts_with("MQTT-"));
    }

    #[test]
    fn secret_file_roundtrip_and_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alias.key");
        let a = Aliaser::load_or_create(&path).unwrap();
        let b = Aliaser::load_or_create(&path).unwrap();
        assert_eq!(a.alias("p", "n", "s"), b.alias("p", "n", "s"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
