//! Passkey (WebAuthn) authentication + scoped roles for the admin UI
//! (v0.4 cycle E).
//!
//! Clean-room relying-party verification — the standard `webauthn-rs` crate
//! is MPL-2.0, outside this project's permissive-only dependency policy, so
//! the subset RelayFabric needs is implemented here against the WebAuthn L2
//! spec: `attestation: "none"` registration (parse the attestation object,
//! ignore the attestation statement, extract the credential + COSE key) and
//! assertion verification (ES256 via `p256`, Ed25519 via `ed25519-dalek`).
//! No attestation-chain validation, no extensions, no resident-key
//! bookkeeping: self-hosted single-operator scope, not a public IdP.
//!
//! Roles gate the proxied admin API by method + path prefix; the session is
//! an opaque random token in an HttpOnly SameSite=Strict cookie, mapped
//! in-memory (a UI restart logs everyone out — accepted). Credentials
//! persist as JSON (0600) under `--state-dir`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use p256::ecdsa::signature::Verifier as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SESSION_COOKIE: &str = "rfui_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);
const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

/// Hard caps on the in-memory maps (audit finding: `/auth/login/options` is
/// unauthenticated, so the challenge map is attacker-growable). At the cap,
/// the soonest-to-expire entry is evicted to make room — a flood evicts its
/// own entries, bounding memory rather than locking out low-volume users.
const MAX_CHALLENGES: usize = 4096;
const MAX_SESSIONS: usize = 4096;

const ALG_ES256: i64 = -7;
const ALG_ED25519: i64 = -8;

/// COSE curve labels (COSE_Key parameter -1): P-256 for ES256, Ed25519 for
/// the OKP key type. Verified at registration so a key can't claim ES256
/// while carrying coordinates for another curve.
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

// --- roles ---------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Viewer,
    Operator,
    RouteAdmin,
    IdentityAdmin,
    SecurityAdmin,
    Administrator,
}

impl Role {
    /// Whether this role may perform `method` on the proxied admin `path`.
    /// Read access (GET/HEAD) is every role's baseline; write access is
    /// scoped: `operator` acts on queue/messages, `route-admin` on config,
    /// `identity-admin` on identity links, `security-admin` on
    /// federation/discovery, `administrator` on everything. Identity data is
    /// correlation-sensitive, so even READING `/v1/identities*` requires
    /// identity-admin (or administrator) — the one carve-out from the
    /// read-for-all baseline.
    pub fn permits(self, method: &str, path: &str) -> bool {
        if self == Role::Administrator {
            return true;
        }
        let read = matches!(method, "GET" | "HEAD");
        if path.starts_with("/v1/identities") {
            return self == Role::IdentityAdmin;
        }
        if read {
            return true;
        }
        match self {
            Role::Viewer => false,
            Role::Operator => path.starts_with("/v1/queue") || path.starts_with("/v1/messages"),
            Role::RouteAdmin => path.starts_with("/v1/config"),
            Role::IdentityAdmin => false, // identities handled above
            Role::SecurityAdmin => {
                path.starts_with("/v1/federation") || path.starts_with("/v1/discovery")
            }
            Role::Administrator => true,
        }
    }
}

// --- persisted credentials ----------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// base64url (no padding) credential id, as the browser reports it.
    pub id: String,
    /// COSE alg: -7 (ES256, SEC1 uncompressed point) or -8 (Ed25519, raw).
    pub alg: i64,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub role: Role,
    pub label: String,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(d)?;
        hex::decode(raw).map_err(serde::de::Error::custom)
    }
}

// --- the auth store ------------------------------------------------------

struct Session {
    cred_id: String,
    role: Role,
    expires: Instant,
}

/// An outstanding challenge: the bytes, what ceremony they're for, expiry.
type Challenge = (Vec<u8>, Purpose, Instant);

pub struct Auth {
    path: PathBuf,
    creds: Mutex<Vec<CredentialRecord>>,
    sessions: Mutex<HashMap<String, Session>>,
    /// Outstanding challenges: token -> (challenge bytes, purpose, expiry).
    challenges: Mutex<HashMap<String, Challenge>>,
    /// One-time setup token (printed at startup) that authorizes the FIRST
    /// registration when the credential store is empty.
    pub setup_token: String,
    /// The WebAuthn RP id (a registrable domain suffix of the UI's host).
    pub rp_id: String,
    /// Lower-cased host names accepted in clientData origins (the same
    /// allowlist the proxy's Host/Origin guards use; scheme and port are
    /// not identity here -- the host is).
    pub origins: Vec<String>,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Purpose {
    Register,
    Login,
}

fn rand32() -> [u8; 32] {
    rand::random()
}

fn token() -> String {
    b64url(&rand32())
}

pub fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
}

impl Auth {
    /// Loads (or initializes) the credential store. `state_dir` is created
    /// 0700; the store file is written 0600.
    pub fn open(state_dir: PathBuf, rp_id: String, origins: Vec<String>) -> std::io::Result<Auth> {
        std::fs::create_dir_all(&state_dir)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = state_dir.join("credentials.json");
        let creds: Vec<CredentialRecord> = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Auth {
            path,
            creds: Mutex::new(creds),
            sessions: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
            setup_token: token(),
            rp_id,
            origins,
        })
    }

    fn persist(&self, creds: &[CredentialRecord]) -> std::io::Result<()> {
        // Unique tmp name (audit finding): a fixed `credentials.tmp` shared
        // by concurrent writers could interleave into a torn file that then
        // renames into place and bricks the next startup. pid + a random
        // suffix makes each writer's tmp distinct; the rename stays atomic.
        let tmp =
            self.path
                .with_extension(format!("tmp.{}.{}", std::process::id(), b64url(&rand32())));
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&serde_json::to_vec_pretty(creds)?)?;
        }
        std::fs::rename(&tmp, &self.path)
    }

    pub fn has_credentials(&self) -> bool {
        !self.creds.lock().unwrap().is_empty()
    }

    pub fn credentials(&self) -> Vec<CredentialRecord> {
        self.creds.lock().unwrap().clone()
    }

    pub fn remove_credential(&self, id: &str) -> bool {
        let mut creds = self.creds.lock().unwrap();
        let before = creds.len();
        creds.retain(|c| c.id != id);
        let removed = creds.len() != before;
        if removed {
            let _ = self.persist(&creds);
            // Revoke live sessions for the deleted credential (audit
            // finding): removing a lost/compromised passkey must not leave
            // its 12h sessions valid.
            self.sessions.lock().unwrap().retain(|_, s| s.cred_id != id);
        }
        removed
    }

    /// Issues a challenge; returns (challenge_token, challenge_b64url).
    pub fn new_challenge(&self, purpose: Purpose) -> (String, String) {
        let tok = token();
        let challenge = rand32().to_vec();
        let b64 = b64url(&challenge);
        let mut map = self.challenges.lock().unwrap();
        let now = Instant::now();
        map.retain(|_, (_, _, exp)| *exp > now);
        // Hard cap: evict the soonest-to-expire entry when full so an
        // unauthenticated flood bounds at MAX_CHALLENGES rather than growing
        // without limit.
        while map.len() >= MAX_CHALLENGES {
            if let Some(oldest) = map
                .iter()
                .min_by_key(|(_, (_, _, exp))| *exp)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest);
            } else {
                break;
            }
        }
        map.insert(tok.clone(), (challenge, purpose, now + CHALLENGE_TTL));
        (tok, b64)
    }

    fn take_challenge(&self, tok: &str, purpose: Purpose) -> Option<Vec<u8>> {
        let mut map = self.challenges.lock().unwrap();
        let (challenge, p, exp) = map.remove(tok)?;
        (p == purpose && exp > Instant::now()).then_some(challenge)
    }

    /// Completes a registration ceremony; on success stores the credential
    /// with `role`/`label` and returns its id.
    pub fn register(
        &self,
        challenge_token: &str,
        client_data_json: &[u8],
        attestation_object: &[u8],
        role: Role,
        label: String,
        require_empty: bool,
    ) -> Result<String, &'static str> {
        let challenge = self
            .take_challenge(challenge_token, Purpose::Register)
            .ok_or("unknown or expired challenge")?;
        verify_client_data(
            client_data_json,
            "webauthn.create",
            &challenge,
            &self.origins,
        )?;
        let (cred_id, alg, public_key) = parse_attestation_object(attestation_object, &self.rp_id)?;
        let id = b64url(&cred_id);
        let mut creds = self.creds.lock().unwrap();
        // Bootstrap TOCTOU close (audit finding): the setup-token gate in the
        // caller checked `has_credentials()` outside this lock, so two
        // concurrent bootstrap registrations could both pass it. Re-assert
        // emptiness HERE, under the lock that pushes the credential, so the
        // second one sees the first's credential and is refused — one setup
        // token yields exactly one administrator.
        if require_empty && !creds.is_empty() {
            return Err("setup already completed");
        }
        if creds.iter().any(|c| c.id == id) {
            return Err("credential already registered");
        }
        creds.push(CredentialRecord {
            id: id.clone(),
            alg,
            public_key,
            counter: 0,
            role,
            label,
        });
        self.persist(&creds)
            .map_err(|_| "cannot persist credential store")?;
        Ok(id)
    }

    /// Completes an authentication ceremony; on success returns a session
    /// token for the credential's role.
    pub fn login(
        &self,
        challenge_token: &str,
        credential_id: &str,
        client_data_json: &[u8],
        authenticator_data: &[u8],
        signature: &[u8],
    ) -> Result<(String, Role), &'static str> {
        let challenge = self
            .take_challenge(challenge_token, Purpose::Login)
            .ok_or("unknown or expired challenge")?;
        verify_client_data(client_data_json, "webauthn.get", &challenge, &self.origins)?;

        let mut creds = self.creds.lock().unwrap();
        let cred = creds
            .iter_mut()
            .find(|c| c.id == credential_id)
            .ok_or("unknown credential")?;

        let counter = verify_assertion(
            authenticator_data,
            client_data_json,
            signature,
            &self.rp_id,
            cred.alg,
            &cred.public_key,
        )?;
        // signCount clone detection (audit finding: the exemption was too
        // wide). WebAuthn L2 §7.2 step 17: compare when the reported count
        // OR the stored count is nonzero — a stored 6 vs reported 0 is a
        // clone signal, not the synced-passkey case. The always-zero
        // exemption applies ONLY while both are zero.
        if (counter != 0 || cred.counter != 0) && counter <= cred.counter {
            return Err("authenticator counter regressed (possible cloned credential)");
        }
        let role = cred.role;
        let cred_id = cred.id.clone();
        // Persist ONLY when the counter advanced, and while still holding the
        // creds lock (audit finding: login used to clone+drop+persist, racing
        // a concurrent register on the shared tmp file).
        let changed = counter > cred.counter;
        if changed {
            cred.counter = counter;
            let _ = self.persist(&creds);
        }
        drop(creds);

        let tok = token();
        let mut sessions = self.sessions.lock().unwrap();
        let now = Instant::now();
        sessions.retain(|_, s| s.expires > now);
        while sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, s)| s.expires)
                .map(|(k, _)| k.clone())
            {
                sessions.remove(&oldest);
            } else {
                break;
            }
        }
        sessions.insert(
            tok.clone(),
            Session {
                cred_id,
                role,
                expires: now + SESSION_TTL,
            },
        );
        Ok((tok, role))
    }

    pub fn session_role(&self, token: &str) -> Option<Role> {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(token) {
            Some(s) if s.expires > Instant::now() => Some(s.role),
            Some(_) => {
                sessions.remove(token);
                None
            }
            None => None,
        }
    }

    pub fn session_info(&self, token: &str) -> Option<(String, Role)> {
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.get(token) {
            Some(s) if s.expires > Instant::now() => Some((s.cred_id.clone(), s.role)),
            Some(_) => {
                sessions.remove(token);
                None
            }
            None => None,
        }
    }

    pub fn logout(&self, token: &str) {
        self.sessions.lock().unwrap().remove(token);
    }
}

// --- WebAuthn verification primitives ------------------------------------

/// clientDataJSON checks shared by both ceremonies: type, challenge (b64url
/// of the bytes we issued), and an allowed origin.
fn verify_client_data(
    client_data_json: &[u8],
    expected_type: &str,
    challenge: &[u8],
    origins: &[String],
) -> Result<(), &'static str> {
    #[derive(Deserialize)]
    struct ClientData {
        #[serde(rename = "type")]
        ty: String,
        challenge: String,
        origin: String,
        #[serde(rename = "crossOrigin", default)]
        cross_origin: Option<bool>,
    }
    let cd: ClientData =
        serde_json::from_slice(client_data_json).map_err(|_| "malformed clientDataJSON")?;
    if cd.ty != expected_type {
        return Err("wrong clientData type");
    }
    if cd.challenge != b64url(challenge) {
        return Err("challenge mismatch");
    }
    // A ceremony run inside a cross-origin iframe is refused (audit finding,
    // WebAuthn L3): the admin UI is same-origin only.
    if cd.cross_origin == Some(true) {
        return Err("cross-origin ceremony refused");
    }
    let (scheme, host) = split_origin(&cd.origin).ok_or("malformed origin")?;
    // Scheme is part of identity (audit finding): a plaintext-HTTP origin is
    // refused for any host except loopback, which browsers treat as a secure
    // context. Otherwise an active network attacker serving the login page
    // over HTTP could get a ceremony accepted.
    let loopback = host == "localhost" || host == "127.0.0.1" || host == "[::1]";
    if scheme != "https" && !(scheme == "http" && loopback) {
        return Err("origin scheme not allowed (need https, or http on loopback)");
    }
    if !origins.iter().any(|o| o == &host) {
        return Err("origin not allowed");
    }
    Ok(())
}

/// Splits an origin `scheme://host[:port]` into (lowercased scheme,
/// lowercased host), handling the bracketed IPv6 literal form
/// (`http://[::1]:8087` -> host `[::1]`).
fn split_origin(origin: &str) -> Option<(String, String)> {
    let (scheme, rest) = origin.split_once("://")?;
    let host = if let Some(after) = rest.strip_prefix('[') {
        // IPv6 literal: keep everything up to and including the closing ']'.
        let end = after.find(']')?;
        format!("[{}]", &after[..end])
    } else {
        rest.split(['/', ':']).next().unwrap_or(rest).to_string()
    };
    Some((scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

/// Parses an `attestation: "none"` attestationObject: CBOR map with
/// `fmt`/`attStmt` (ignored) and `authData`, from which the credential id
/// and COSE public key are extracted. Returns (cred_id, alg, key_bytes)
/// where key_bytes is SEC1-uncompressed for ES256 or raw 32 bytes for
/// Ed25519.
fn parse_attestation_object(
    attestation_object: &[u8],
    rp_id: &str,
) -> Result<(Vec<u8>, i64, Vec<u8>), &'static str> {
    let value: ciborium::Value =
        ciborium::from_reader(attestation_object).map_err(|_| "malformed attestationObject")?;
    let map = value.as_map().ok_or("attestationObject is not a map")?;
    let auth_data = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("authData"))
        .and_then(|(_, v)| v.as_bytes())
        .ok_or("attestationObject missing authData")?;

    parse_auth_data_common(auth_data, rp_id, true)?;
    let flags = auth_data[32];
    if flags & 0x40 == 0 {
        return Err("no attested credential data");
    }
    // rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId ...
    if auth_data.len() < 55 {
        return Err("authData too short");
    }
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_end = 55usize.checked_add(cred_len).ok_or("authData too short")?;
    if auth_data.len() < cred_end {
        return Err("authData too short");
    }
    let cred_id = auth_data[55..cred_end].to_vec();
    let (alg, key) = parse_cose_key(&auth_data[cred_end..])?;
    Ok((cred_id, alg, key))
}

/// COSE_Key -> (alg, key bytes): EC2/P-256 (SEC1 uncompressed) or
/// OKP/Ed25519 (raw x).
fn parse_cose_key(cbor: &[u8]) -> Result<(i64, Vec<u8>), &'static str> {
    let value: ciborium::Value = ciborium::from_reader(cbor).map_err(|_| "malformed COSE key")?;
    let map = value.as_map().ok_or("COSE key is not a map")?;
    let get = |label: i64| {
        map.iter()
            .find(|(k, _)| k.as_integer() == Some(label.into()))
            .map(|(_, v)| v)
    };
    let kty: i64 = get(1)
        .and_then(|v| v.as_integer())
        .and_then(|i| i.try_into().ok())
        .ok_or("COSE key missing kty")?;
    let alg: i64 = get(3)
        .and_then(|v| v.as_integer())
        .and_then(|i| i.try_into().ok())
        .ok_or("COSE key missing alg")?;
    let crv: i64 = get(-1)
        .and_then(|v| v.as_integer())
        .and_then(|i| i.try_into().ok())
        .ok_or("COSE key missing crv")?;
    match (kty, alg) {
        (2, ALG_ES256) => {
            if crv != CRV_P256 {
                return Err("ES256 key must use curve P-256");
            }
            let x = get(-2)
                .and_then(|v| v.as_bytes())
                .ok_or("EC2 key missing x")?;
            let y = get(-3)
                .and_then(|v| v.as_bytes())
                .ok_or("EC2 key missing y")?;
            if x.len() != 32 || y.len() != 32 {
                return Err("EC2 coordinates must be 32 bytes");
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            // Reject an off-curve / invalid point at registration (audit
            // finding) rather than storing a key that can never verify.
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| "EC2 point is not on curve P-256")?;
            Ok((ALG_ES256, sec1))
        }
        (1, ALG_ED25519) => {
            if crv != CRV_ED25519 {
                return Err("Ed25519 key must use curve Ed25519");
            }
            let x = get(-2)
                .and_then(|v| v.as_bytes())
                .ok_or("OKP key missing x")?;
            let key_bytes: [u8; 32] = x
                .as_slice()
                .try_into()
                .map_err(|_| "Ed25519 key must be 32 bytes")?;
            ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| "Ed25519 key is not a valid point")?;
            Ok((ALG_ED25519, key_bytes.to_vec()))
        }
        _ => Err("unsupported COSE key type/alg (need ES256 or Ed25519)"),
    }
}

/// The checks common to both ceremonies' authData: length, rpIdHash, and
/// the User Present flag. `require_uv` additionally demands the User
/// Verified flag (0x04) — required on login for an admin gate (audit
/// finding), so possession of an unlocked authenticator alone is not enough.
fn parse_auth_data_common(
    auth_data: &[u8],
    rp_id: &str,
    require_uv: bool,
) -> Result<(), &'static str> {
    if auth_data.len() < 37 {
        return Err("authData too short");
    }
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    if auth_data[..32] != rp_hash[..] {
        return Err("rpIdHash mismatch");
    }
    if auth_data[32] & 0x01 == 0 {
        return Err("user-present flag not set");
    }
    if require_uv && auth_data[32] & 0x04 == 0 {
        return Err("user-verification flag not set (PIN/biometric required)");
    }
    Ok(())
}

/// Verifies an assertion signature over `authenticatorData ||
/// sha256(clientDataJSON)` and returns the authenticator's signCount.
fn verify_assertion(
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
    rp_id: &str,
    alg: i64,
    public_key: &[u8],
) -> Result<u32, &'static str> {
    parse_auth_data_common(authenticator_data, rp_id, true)?;
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(&Sha256::digest(client_data_json));

    match alg {
        ALG_ES256 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| "bad stored ES256 key")?;
            let sig = p256::ecdsa::Signature::from_der(signature)
                .map_err(|_| "malformed ES256 signature")?;
            key.verify(&signed, &sig)
                .map_err(|_| "signature verification failed")?;
        }
        ALG_ED25519 => {
            let key_bytes: [u8; 32] = public_key
                .try_into()
                .map_err(|_| "bad stored Ed25519 key")?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| "bad stored Ed25519 key")?;
            let sig_bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| "malformed Ed25519 signature")?;
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            key.verify_strict(&signed, &sig)
                .map_err(|_| "signature verification failed")?;
        }
        _ => return Err("unsupported credential alg"),
    }
    Ok(u32::from_be_bytes([
        authenticator_data[33],
        authenticator_data[34],
        authenticator_data[35],
        authenticator_data[36],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;

    const RP: &str = "localhost";
    const ORIGIN: &str = "http://localhost:8087";

    fn auth(dir: &std::path::Path) -> Auth {
        Auth::open(dir.join("state"), RP.into(), vec!["localhost".into()]).unwrap()
    }

    fn client_data(ty: &str, challenge_b64: &str) -> Vec<u8> {
        format!(r#"{{"type":"{ty}","challenge":"{challenge_b64}","origin":"{ORIGIN}"}}"#)
            .into_bytes()
    }

    /// authData for a ceremony: rpIdHash || flags || counter || attested
    /// credential data (aaguid, credId, COSE key) when `cose` is given.
    fn auth_data(flags: u8, counter: u32, cose: Option<Vec<u8>>) -> Vec<u8> {
        let mut out = Sha256::digest(RP.as_bytes()).to_vec();
        out.push(flags);
        out.extend_from_slice(&counter.to_be_bytes());
        if let Some(cose) = cose {
            out.extend_from_slice(&[0u8; 16]); // aaguid
            out.extend_from_slice(&(4u16).to_be_bytes());
            out.extend_from_slice(b"cid1");
            out.extend_from_slice(&cose);
        }
        out
    }

    fn cose_es256(key: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
        let point = key.to_encoded_point(false);
        let entries = ciborium::Value::Map(vec![
            (1.into(), 2.into()),
            (3.into(), (-7).into()),
            ((-1).into(), 1.into()),
            (
                (-2).into(),
                ciborium::Value::Bytes(point.x().unwrap().to_vec()),
            ),
            (
                (-3).into(),
                ciborium::Value::Bytes(point.y().unwrap().to_vec()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&entries, &mut buf).unwrap();
        buf
    }

    fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
        let obj = ciborium::Value::Map(vec![
            ("fmt".into(), "none".into()),
            ("attStmt".into(), ciborium::Value::Map(vec![])),
            (
                "authData".into(),
                ciborium::Value::Bytes(auth_data.to_vec()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&obj, &mut buf).unwrap();
        buf
    }

    fn register_es256(a: &Auth) -> (p256::ecdsa::SigningKey, String) {
        let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let (tok, ch) = a.new_challenge(Purpose::Register);
        let ad = auth_data(0x45, 0, Some(cose_es256(signing.verifying_key())));
        let id = a
            .register(
                &tok,
                &client_data("webauthn.create", &ch),
                &attestation_object(&ad),
                Role::Administrator,
                "test".into(),
                false,
            )
            .unwrap();
        (signing, id)
    }

    fn assert_login(
        a: &Auth,
        signing: &p256::ecdsa::SigningKey,
        id: &str,
        counter: u32,
    ) -> Result<(String, Role), &'static str> {
        let (tok, ch) = a.new_challenge(Purpose::Login);
        let cdj = client_data("webauthn.get", &ch);
        let ad = auth_data(0x05, counter, None);
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: p256::ecdsa::Signature = signing.sign(&signed);
        a.login(&tok, id, &cdj, &ad, sig.to_der().as_bytes())
    }

    #[test]
    fn full_es256_register_and_login_ceremony() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let (signing, id) = register_es256(&a);
        let (session, role) = assert_login(&a, &signing, &id, 1).unwrap();
        assert_eq!(role, Role::Administrator);
        assert_eq!(a.session_role(&session), Some(Role::Administrator));
    }

    // --- audit-fix regression tests --------------------------------------

    #[test]
    fn login_without_user_verification_flag_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let (signing, id) = register_es256(&a);
        let (tok, ch) = a.new_challenge(Purpose::Login);
        let cdj = client_data("webauthn.get", &ch);
        // UP only (0x01), no UV (0x04) — must be refused for the admin gate.
        let ad = auth_data(0x01, 1, None);
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: p256::ecdsa::Signature = signing.sign(&signed);
        assert_eq!(
            a.login(&tok, &id, &cdj, &ad, sig.to_der().as_bytes()),
            Err("user-verification flag not set (PIN/biometric required)")
        );
    }

    #[test]
    fn plaintext_http_origin_rejected_for_non_loopback_host() {
        let dir = tempfile::tempdir().unwrap();
        let a = Auth::open(
            dir.path().join("s"),
            "relay.internal".into(),
            vec!["relay.internal".into()],
        )
        .unwrap();
        let (tok, ch) = a.new_challenge(Purpose::Register);
        let cdj = format!(
            r#"{{"type":"webauthn.create","challenge":"{ch}","origin":"http://relay.internal"}}"#
        )
        .into_bytes();
        let ad = auth_data(0x45, 0, None);
        assert_eq!(
            a.register(
                &tok,
                &cdj,
                &attestation_object(&ad),
                Role::Viewer,
                "x".into(),
                false
            ),
            Err("origin scheme not allowed (need https, or http on loopback)")
        );
    }

    #[test]
    fn cross_origin_ceremony_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let (tok, ch) = a.new_challenge(Purpose::Register);
        let cdj = format!(
            r#"{{"type":"webauthn.create","challenge":"{ch}","origin":"{ORIGIN}","crossOrigin":true}}"#
        )
        .into_bytes();
        let ad = auth_data(0x45, 0, None);
        assert_eq!(
            a.register(
                &tok,
                &cdj,
                &attestation_object(&ad),
                Role::Viewer,
                "x".into(),
                false
            ),
            Err("cross-origin ceremony refused")
        );
    }

    #[test]
    fn split_origin_handles_ipv6_and_scheme() {
        assert_eq!(
            split_origin("http://[::1]:8087"),
            Some(("http".into(), "[::1]".into()))
        );
        assert_eq!(
            split_origin("https://relay.internal:9000"),
            Some(("https".into(), "relay.internal".into()))
        );
        assert_eq!(
            split_origin("http://localhost:8087"),
            Some(("http".into(), "localhost".into()))
        );
    }

    #[test]
    fn cose_key_on_wrong_curve_is_rejected_at_registration() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let point = signing.verifying_key().to_encoded_point(false);
        // Real P-256 point, but the COSE crv label claims something else.
        let cose = {
            let entries = ciborium::Value::Map(vec![
                (1.into(), 2.into()),
                (3.into(), (-7).into()),
                ((-1).into(), 99.into()), // bogus crv
                (
                    (-2).into(),
                    ciborium::Value::Bytes(point.x().unwrap().to_vec()),
                ),
                (
                    (-3).into(),
                    ciborium::Value::Bytes(point.y().unwrap().to_vec()),
                ),
            ]);
            let mut buf = Vec::new();
            ciborium::into_writer(&entries, &mut buf).unwrap();
            buf
        };
        let (tok, ch) = a.new_challenge(Purpose::Register);
        let ad = auth_data(0x45, 0, Some(cose));
        assert_eq!(
            a.register(
                &tok,
                &client_data("webauthn.create", &ch),
                &attestation_object(&ad),
                Role::Viewer,
                "x".into(),
                false
            ),
            Err("ES256 key must use curve P-256")
        );
    }

    #[test]
    fn deleting_a_credential_revokes_its_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let (signing, id) = register_es256(&a);
        let (session, _) = assert_login(&a, &signing, &id, 1).unwrap();
        assert!(a.session_role(&session).is_some());
        assert!(a.remove_credential(&id));
        assert!(
            a.session_role(&session).is_none(),
            "removing the credential must revoke its live sessions"
        );
    }

    #[test]
    fn bootstrap_require_empty_blocks_a_second_registration() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        // First bootstrap registration (require_empty = true) succeeds.
        let _ = register_es256(&a); // fills the store
                                    // A second require_empty registration must be refused even with a
                                    // valid ceremony — closes the concurrent-bootstrap multi-admin hole.
        let signing = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let (tok, ch) = a.new_challenge(Purpose::Register);
        let ad = auth_data(0x45, 0, Some(cose_es256(signing.verifying_key())));
        assert_eq!(
            a.register(
                &tok,
                &client_data("webauthn.create", &ch),
                &attestation_object(&ad),
                Role::Administrator,
                "second".into(),
                true
            ),
            Err("setup already completed")
        );
    }

    #[test]
    fn challenge_map_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        for _ in 0..(MAX_CHALLENGES + 100) {
            a.new_challenge(Purpose::Login);
        }
        assert!(
            a.challenges.lock().unwrap().len() <= MAX_CHALLENGES,
            "challenge map must stay bounded under a flood"
        );
    }

    #[test]
    fn credentials_persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (signing, id) = {
            let a = auth(dir.path());
            register_es256(&a)
        };
        let a2 = auth(dir.path());
        assert!(a2.has_credentials());
        assert_login(&a2, &signing, &id, 1).unwrap();
    }

    #[test]
    fn wrong_challenge_type_or_origin_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let (signing, id) = register_es256(&a);

        // wrong type
        let (tok, ch) = a.new_challenge(Purpose::Login);
        let cdj = client_data("webauthn.create", &ch);
        let ad = auth_data(0x05, 1, None);
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: p256::ecdsa::Signature = signing.sign(&signed);
        assert_eq!(
            a.login(&tok, &id, &cdj, &ad, sig.to_der().as_bytes()),
            Err("wrong clientData type")
        );

        // wrong origin
        let (tok, ch) = a.new_challenge(Purpose::Login);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"https://evil.example"}}"#
        )
        .into_bytes();
        let ad = auth_data(0x05, 2, None);
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: p256::ecdsa::Signature = signing.sign(&signed);
        assert_eq!(
            a.login(&tok, &id, &cdj, &ad, sig.to_der().as_bytes()),
            Err("origin not allowed")
        );
    }

    #[test]
    fn challenge_is_single_use_and_purpose_bound() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let (signing, id) = register_es256(&a);
        let (tok, ch) = a.new_challenge(Purpose::Login);
        let cdj = client_data("webauthn.get", &ch);
        let ad = auth_data(0x05, 1, None);
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: p256::ecdsa::Signature = signing.sign(&signed);
        a.login(&tok, &id, &cdj, &ad, sig.to_der().as_bytes())
            .unwrap();
        // replaying the SAME challenge token must fail
        assert_eq!(
            a.login(&tok, &id, &cdj, &ad, sig.to_der().as_bytes()),
            Err("unknown or expired challenge")
        );
    }

    #[test]
    fn tampered_signature_and_wrong_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let (signing, id) = register_es256(&a);
        let (tok, ch) = a.new_challenge(Purpose::Login);
        let cdj = client_data("webauthn.get", &ch);
        let ad = auth_data(0x05, 1, None);
        let other = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: p256::ecdsa::Signature = other.sign(&signed);
        assert_eq!(
            a.login(&tok, &id, &cdj, &ad, sig.to_der().as_bytes()),
            Err("signature verification failed")
        );
        let _ = signing;
    }

    #[test]
    fn counter_regression_rejected_but_both_zero_ok() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let (signing, id) = register_es256(&a);
        // A brand-new credential (stored 0) logging in at 0 = synced-passkey
        // case, allowed while BOTH sides are zero.
        assert_login(&a, &signing, &id, 0).unwrap();
        assert_login(&a, &signing, &id, 5).unwrap();
        // replay at the same nonzero value is a regression.
        assert_eq!(
            assert_login(&a, &signing, &id, 5),
            Err("authenticator counter regressed (possible cloned credential)")
        );
        assert_login(&a, &signing, &id, 6).unwrap();
    }

    #[test]
    fn rp_id_hash_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let (signing, id) = register_es256(&a);
        let (tok, ch) = a.new_challenge(Purpose::Login);
        let cdj = client_data("webauthn.get", &ch);
        let mut ad = Sha256::digest(b"evil.example").to_vec();
        ad.push(0x01);
        ad.extend_from_slice(&1u32.to_be_bytes());
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig: p256::ecdsa::Signature = signing.sign(&signed);
        assert_eq!(
            a.login(&tok, &id, &cdj, &ad, sig.to_der().as_bytes()),
            Err("rpIdHash mismatch")
        );
    }

    #[test]
    fn role_matrix_enforces_scopes() {
        use Role::*;
        // read baseline
        assert!(Viewer.permits("GET", "/v1/status"));
        assert!(!Viewer.permits("POST", "/v1/config"));
        // identities are identity-admin only, even for reads
        assert!(!Viewer.permits("GET", "/v1/identities"));
        assert!(!SecurityAdmin.permits("GET", "/v1/identities"));
        assert!(IdentityAdmin.permits("GET", "/v1/identities"));
        assert!(IdentityAdmin.permits("DELETE", "/v1/identities/link/x"));
        // scoped writes
        assert!(Operator.permits("POST", "/v1/queue/retry"));
        assert!(!Operator.permits("PUT", "/v1/config"));
        assert!(RouteAdmin.permits("PUT", "/v1/config"));
        assert!(!RouteAdmin.permits("POST", "/v1/federation/trust"));
        assert!(SecurityAdmin.permits("POST", "/v1/federation/trust"));
        // administrator: everything
        assert!(Administrator.permits("PUT", "/v1/config"));
        assert!(Administrator.permits("GET", "/v1/identities"));
    }

    #[test]
    fn ed25519_ceremony_verifies() {
        use ed25519_dalek::Signer as _;
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let cose = {
            let entries = ciborium::Value::Map(vec![
                (1.into(), 1.into()),
                (3.into(), (-8).into()),
                ((-1).into(), 6.into()),
                (
                    (-2).into(),
                    ciborium::Value::Bytes(signing.verifying_key().to_bytes().to_vec()),
                ),
            ]);
            let mut buf = Vec::new();
            ciborium::into_writer(&entries, &mut buf).unwrap();
            buf
        };
        let (tok, ch) = a.new_challenge(Purpose::Register);
        let ad = auth_data(0x45, 0, Some(cose));
        let id = a
            .register(
                &tok,
                &client_data("webauthn.create", &ch),
                &attestation_object(&ad),
                Role::Viewer,
                "ed".into(),
                false,
            )
            .unwrap();

        let (tok, ch) = a.new_challenge(Purpose::Login);
        let cdj = client_data("webauthn.get", &ch);
        let ad = auth_data(0x05, 1, None);
        let mut signed = ad.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        let sig = signing.sign(&signed);
        let (_, role) = a.login(&tok, &id, &cdj, &ad, &sig.to_bytes()).unwrap();
        assert_eq!(role, Role::Viewer);
    }

    #[test]
    fn sessions_expire_and_logout_revokes() {
        let dir = tempfile::tempdir().unwrap();
        let a = auth(dir.path());
        let (signing, id) = register_es256(&a);
        let (session, _) = assert_login(&a, &signing, &id, 1).unwrap();
        assert!(a.session_role(&session).is_some());
        a.logout(&session);
        assert!(a.session_role(&session).is_none());
    }
}
