//! Noise link (design doc §1): authenticated, encrypted TCP links between
//! switchyardd nodes, bound to Ed25519 node identities so a Noise session
//! can't be established under someone else's `rf:` identity.
//!
//! Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s`. Each side's static X25519
//! keypair is persisted to disk (`StaticKey::load_or_create`, alias.rs
//! precedent). Identity binding rides in the final handshake message each
//! side sends (payload is only encrypted-for-the-sender's-static from that
//! point on): CBOR `{node_id, sig}` where `sig` is an Ed25519 signature (by
//! the node's RelayFabric identity, cycle-A `NodeIdentity`) over
//! `domains::NOISE_STATIC_V1 || <raw 32-byte X25519 static public key just
//! transmitted>` — domain-separated (Task 1 review ruling, `fed/domains.rs`)
//! so this signature can never be confused with a signature made for any
//! other purpose in this codebase (e.g. an envelope origin signature). The
//! receiver checks `get_remote_static()` against that signature before
//! trusting the peer.
//!
//! Consumed by `fed::conn` (Task 4), which owns live connection lifecycle:
//! `handshake_initiator`/`handshake_responder` drive each connection's
//! handshake, and `FedChannel::send_frame`/`recv_frame` move CBOR `wire::Fed`
//! frames once it completes.

use crate::node_identity::{self, NodeIdentity};
use serde::{Deserialize, Serialize};
use snow::params::NoiseParams;
use snow::{Builder, TransportState};
use std::fmt;
use std::io;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Noise_XX_25519_ChaChaPoly_BLAKE2s (design doc §1).
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Noise's hard message-size ceiling (fits the 2-byte BE outer length
/// prefix, which is also the wire-format reason it's a ceiling here).
const MAX_NOISE_MSG: usize = 65535;

/// ChaCha20-Poly1305's AEAD tag length. Not re-exported by `snow` (its
/// `constants` module is private), so it's hardcoded here; the chunking
/// boundary test (exactly 65519 bytes) self-verifies this is correct.
const NOISE_TAG_LEN: usize = 16;

/// Largest plaintext chunk that fits one Noise transport message once the
/// AEAD tag is accounted for.
const MAX_NOISE_PAYLOAD: usize = MAX_NOISE_MSG - NOISE_TAG_LEN;

/// Cap on a single logical fed frame's plaintext size (relay-ipc precedent).
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

fn noise_params() -> NoiseParams {
    NOISE_PARAMS
        .parse()
        .expect("NOISE_PARAMS is a well-formed, statically-known Noise params string")
}

/// A node's persisted Noise static X25519 keypair. Only the 32-byte private
/// scalar is stored on disk (hex file, 0600 — alias.rs/node_identity.rs
/// precedent); the public key is re-derived on load since X25519 public
/// derivation is cheap and this keeps the on-disk format identical to
/// every other raw-hex secret in this codebase.
pub struct StaticKey {
    private: [u8; 32],
}

impl StaticKey {
    pub fn load_or_create(path: &Path) -> io::Result<StaticKey> {
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
        let private: [u8; 32] = bytes
            .try_into()
            .map_err(|_| io::Error::other("fed static key must be 32 bytes of hex"))?;
        Ok(StaticKey { private })
    }

    fn private_bytes(&self) -> [u8; 32] {
        self.private
    }

    /// X25519 public key, derived the same way snow's own default resolver
    /// derives it (`MontgomeryPoint::mul_base_clamped`, RFC 7748 clamping)
    /// so it's guaranteed to match whatever snow transmits for our static.
    fn public_bytes(&self) -> [u8; 32] {
        curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(self.private).0
    }
}

/// Identity-binding payload carried in each side's final handshake message.
#[derive(Debug, Serialize, Deserialize)]
struct IdentityPayload {
    node_id: String,
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
}

/// Handshake/framing failures. Any error here means the caller drops the
/// stream (it's owned by-value by the handshake functions and simply isn't
/// returned on the error path, so it's dropped/closed automatically).
#[derive(Debug)]
pub enum NoiseError {
    Io(io::Error),
    Handshake(snow::Error),
    /// The final-message payload wasn't valid CBOR or didn't match the
    /// `{node_id, sig}` shape.
    Cbor,
    /// The peer's claimed `node_id` and the signature over their static
    /// X25519 public key don't match (wrong key, tampered payload, or an
    /// attacker asserting an identity it doesn't hold).
    BadSignature,
    /// Handshake succeeded and the peer's identity was validly signed, but
    /// it isn't the `expected_node_id` the initiator required.
    IdentityMismatch,
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoiseError::Io(e) => write!(f, "fed noise link I/O error: {e}"),
            NoiseError::Handshake(e) => write!(f, "fed noise handshake error: {e}"),
            NoiseError::Cbor => write!(f, "fed noise identity payload was not valid CBOR"),
            NoiseError::BadSignature => {
                write!(f, "fed noise peer identity signature did not verify")
            }
            NoiseError::IdentityMismatch => {
                write!(f, "fed noise peer node_id did not match expected node_id")
            }
        }
    }
}

impl std::error::Error for NoiseError {}

impl From<io::Error> for NoiseError {
    fn from(e: io::Error) -> Self {
        NoiseError::Io(e)
    }
}

impl From<snow::Error> for NoiseError {
    fn from(e: snow::Error) -> Self {
        NoiseError::Handshake(e)
    }
}

/// Write one Noise message (handshake or transport ciphertext) with its
/// 2-byte BE length prefix (design doc §1).
async fn write_noise_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &[u8]) -> io::Result<()> {
    let len = u16::try_from(msg.len())
        .map_err(|_| io::Error::other("noise message exceeds 65535 bytes"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(msg).await?;
    w.flush().await
}

/// Read one 2-byte-BE-length-prefixed Noise message. EOF/truncation and
/// oversized-claim errors surface as `io::Error`, never a panic — this is
/// the function that has to tolerate garbage/hostile bytes on the wire.
async fn read_noise_msg<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes(hdr) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Domain-separated signing bytes for the identity-binding payload:
/// `domains::NOISE_STATIC_V1 || static_pub` (Task 1 review ruling).
fn domain_separated_static_pub(static_pub: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(super::domains::NOISE_STATIC_V1.len() + static_pub.len());
    msg.extend_from_slice(super::domains::NOISE_STATIC_V1);
    msg.extend_from_slice(static_pub);
    msg
}

fn sign_static_pub(node_identity: &NodeIdentity, static_key: &StaticKey) -> IdentityPayload {
    let pubkey = static_key.public_bytes();
    IdentityPayload {
        node_id: node_identity.node_id(),
        sig: node_identity.sign(&domain_separated_static_pub(&pubkey)),
    }
}

fn verify_peer_payload(payload: &IdentityPayload, remote_static: &[u8]) -> Result<(), NoiseError> {
    let msg = domain_separated_static_pub(remote_static);
    if node_identity::verify(&payload.node_id, &msg, &payload.sig) {
        Ok(())
    } else {
        Err(NoiseError::BadSignature)
    }
}

fn encode_payload(payload: &IdentityPayload) -> Result<Vec<u8>, NoiseError> {
    let mut buf = Vec::new();
    ciborium::into_writer(payload, &mut buf).map_err(|_| NoiseError::Cbor)?;
    Ok(buf)
}

fn decode_payload(bytes: &[u8]) -> Result<IdentityPayload, NoiseError> {
    ciborium::from_reader(bytes).map_err(|_| NoiseError::Cbor)
}

/// Drive the initiator side of a Noise_XX handshake, then verify the
/// responder's identity-binding payload (carried in message 2) against
/// `expected_node_id` when given. On success, our own identity-binding
/// payload (msg 3) has already been sent and the channel is ready.
pub async fn handshake_initiator<S>(
    mut stream: S,
    static_key: &StaticKey,
    node_identity: &NodeIdentity,
    expected_node_id: Option<&str>,
) -> Result<FedChannel<S>, NoiseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = Builder::new(noise_params())
        .local_private_key(&static_key.private_bytes())?
        .build_initiator()?;

    // msg1: -> e (no payload)
    let mut buf = vec![0u8; MAX_NOISE_MSG];
    let n = hs.write_message(&[], &mut buf)?;
    write_noise_msg(&mut stream, &buf[..n]).await?;

    // msg2: <- e, ee, s, es + responder's identity payload
    let msg2 = read_noise_msg(&mut stream).await?;
    let mut payload_buf = vec![0u8; msg2.len()];
    let n = hs.read_message(&msg2, &mut payload_buf)?;
    payload_buf.truncate(n);
    let peer_payload = decode_payload(&payload_buf)?;
    let remote_static = hs
        .get_remote_static()
        .expect("XX pattern yields a remote static key after message 2")
        .to_vec();
    verify_peer_payload(&peer_payload, &remote_static)?;
    if let Some(expected) = expected_node_id {
        if expected != peer_payload.node_id {
            return Err(NoiseError::IdentityMismatch);
        }
    }

    // msg3: -> s, se + our identity payload
    let our_payload = encode_payload(&sign_static_pub(node_identity, static_key))?;
    let mut buf3 = vec![0u8; MAX_NOISE_MSG];
    let n = hs.write_message(&our_payload, &mut buf3)?;
    write_noise_msg(&mut stream, &buf3[..n]).await?;

    let transport = hs.into_transport_mode()?;
    Ok(FedChannel::new(stream, transport))
}

/// Drive the responder side of a Noise_XX handshake, then verify the
/// initiator's identity-binding payload (carried in message 3). Returns the
/// channel plus the peer's verified `node_id` — the responder doesn't know
/// who to expect ahead of time (that's the trust-store's job, design §3),
/// it only proves the claimed identity is genuine.
pub async fn handshake_responder<S>(
    mut stream: S,
    static_key: &StaticKey,
    node_identity: &NodeIdentity,
) -> Result<(FedChannel<S>, String), NoiseError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hs = Builder::new(noise_params())
        .local_private_key(&static_key.private_bytes())?
        .build_responder()?;

    // msg1: <- e (no payload)
    let msg1 = read_noise_msg(&mut stream).await?;
    let mut buf1 = vec![0u8; msg1.len()];
    hs.read_message(&msg1, &mut buf1)?;

    // msg2: -> e, ee, s, es + our identity payload
    let our_payload = encode_payload(&sign_static_pub(node_identity, static_key))?;
    let mut buf2 = vec![0u8; MAX_NOISE_MSG];
    let n = hs.write_message(&our_payload, &mut buf2)?;
    write_noise_msg(&mut stream, &buf2[..n]).await?;

    // msg3: <- s, se + initiator's identity payload
    let msg3 = read_noise_msg(&mut stream).await?;
    let mut payload_buf = vec![0u8; msg3.len()];
    let n = hs.read_message(&msg3, &mut payload_buf)?;
    payload_buf.truncate(n);
    let peer_payload = decode_payload(&payload_buf)?;
    let remote_static = hs
        .get_remote_static()
        .expect("XX pattern yields a remote static key after message 3")
        .to_vec();
    verify_peer_payload(&peer_payload, &remote_static)?;

    let peer_node_id = peer_payload.node_id;
    let transport = hs.into_transport_mode()?;
    Ok((FedChannel::new(stream, transport), peer_node_id))
}

/// A live, authenticated Noise transport session. `send_frame`/`recv_frame`
/// move whole logical plaintext frames of arbitrary size (up to
/// `MAX_FRAME`), transparently chunking across as many Noise transport
/// messages as needed (design doc §1: outer 2-byte BE Noise ciphertext
/// frames, inner 4-byte BE total-length plaintext prefix).
pub struct FedChannel<S> {
    stream: S,
    transport: TransportState,
    /// Decrypted bytes read from the wire but not yet consumed by a
    /// `recv_frame` call — either because we haven't accumulated a whole
    /// logical frame yet, or (not currently produced by our own sender, but
    /// tolerated for robustness) a Noise message happened to carry the tail
    /// of one frame and the head of the next.
    rx_buf: Vec<u8>,
}

impl<S> FedChannel<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(stream: S, transport: TransportState) -> Self {
        FedChannel {
            stream,
            transport,
            rx_buf: Vec::new(),
        }
    }

    /// Send one logical plaintext frame. `plaintext` must be at most
    /// `MAX_FRAME` bytes; larger frames are rejected rather than truncated.
    pub async fn send_frame(&mut self, plaintext: &[u8]) -> io::Result<()> {
        let len = u32::try_from(plaintext.len()).map_err(io::Error::other)?;
        if len > MAX_FRAME {
            return Err(io::Error::other("frame exceeds MAX_FRAME"));
        }
        let mut logical = Vec::with_capacity(4 + plaintext.len());
        logical.extend_from_slice(&len.to_be_bytes());
        logical.extend_from_slice(plaintext);

        for chunk in logical.chunks(MAX_NOISE_PAYLOAD) {
            let mut ct = vec![0u8; chunk.len() + NOISE_TAG_LEN];
            let n = self
                .transport
                .write_message(chunk, &mut ct)
                .map_err(io::Error::other)?;
            ct.truncate(n);
            write_noise_msg(&mut self.stream, &ct).await?;
        }
        Ok(())
    }

    /// Receive one logical plaintext frame, reading as many Noise transport
    /// messages as needed to reassemble it. Any decrypt failure or
    /// malformed length prefix surfaces as an `io::Error`.
    pub async fn recv_frame(&mut self) -> io::Result<Vec<u8>> {
        while self.rx_buf.len() < 4 {
            self.pull_chunk().await?;
        }
        let total_len =
            u32::from_be_bytes(self.rx_buf[0..4].try_into().expect("checked len >= 4")) as usize;
        if total_len as u64 > u64::from(MAX_FRAME) {
            return Err(io::Error::other("claimed frame length exceeds MAX_FRAME"));
        }
        while self.rx_buf.len() < 4 + total_len {
            self.pull_chunk().await?;
        }
        let frame = self.rx_buf[4..4 + total_len].to_vec();
        self.rx_buf.drain(0..4 + total_len);
        Ok(frame)
    }

    async fn pull_chunk(&mut self) -> io::Result<()> {
        let ct = read_noise_msg(&mut self.stream).await?;
        let mut pt = vec![0u8; ct.len()];
        let n = self
            .transport
            .read_message(&ct, &mut pt)
            .map_err(io::Error::other)?;
        pt.truncate(n);
        self.rx_buf.extend_from_slice(&pt);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn identity_pair(dir: &Path) -> (StaticKey, NodeIdentity) {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let key = StaticKey::load_or_create(&dir.join(format!("static-{n}.key"))).unwrap();
        let identity = NodeIdentity::load_or_create(&dir.join(format!("identity-{n}"))).unwrap();
        (key, identity)
    }

    /// Full, honest handshake pair over an in-memory duplex. Buffer is sized
    /// generously (1 MiB) so the chunking tests' large payloads never block
    /// on backpressure within a single sequential test task.
    async fn duplex_handshake_pair() -> (
        FedChannel<tokio::io::DuplexStream>,
        FedChannel<tokio::io::DuplexStream>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let (init_key, init_id) = identity_pair(dir.path()).await;
        let (resp_key, resp_id) = identity_pair(dir.path()).await;

        let (a, b) = tokio::io::duplex(1 << 20);
        let responder_task =
            tokio::spawn(async move { handshake_responder(b, &resp_key, &resp_id).await });
        let init_channel = handshake_initiator(a, &init_key, &init_id, None)
            .await
            .unwrap();
        let (resp_channel, _peer_node_id) = responder_task.await.unwrap().unwrap();
        (init_channel, resp_channel)
    }

    /// Manually drives a Noise_XX responder using a caller-supplied
    /// handshake-payload, bypassing `handshake_responder`'s own (honest)
    /// signing so tests can inject a malicious/malformed identity claim.
    async fn fake_responder_with_payload<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        static_key: &StaticKey,
        payload_bytes: Vec<u8>,
    ) {
        let mut hs = Builder::new(noise_params())
            .local_private_key(&static_key.private_bytes())
            .unwrap()
            .build_responder()
            .unwrap();
        let msg1 = read_noise_msg(&mut stream).await.unwrap();
        let mut buf1 = vec![0u8; msg1.len()];
        hs.read_message(&msg1, &mut buf1).unwrap();
        let mut buf2 = vec![0u8; MAX_NOISE_MSG];
        let n = hs.write_message(&payload_bytes, &mut buf2).unwrap();
        write_noise_msg(&mut stream, &buf2[..n]).await.unwrap();
    }

    #[tokio::test]
    async fn handshake_happy_path_roundtrips_frames_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let (init_key, init_id) = identity_pair(dir.path()).await;
        let (resp_key, resp_id) = identity_pair(dir.path()).await;
        let expected_responder = resp_id.node_id();
        let expected_initiator = init_id.node_id();

        let (a, b) = tokio::io::duplex(1 << 20);
        let responder_task =
            tokio::spawn(async move { handshake_responder(b, &resp_key, &resp_id).await });
        let mut init_channel =
            handshake_initiator(a, &init_key, &init_id, Some(&expected_responder))
                .await
                .unwrap();
        let (mut resp_channel, peer_node_id) = responder_task.await.unwrap().unwrap();
        assert_eq!(peer_node_id, expected_initiator);

        init_channel.send_frame(b"hello federation").await.unwrap();
        let got = resp_channel.recv_frame().await.unwrap();
        assert_eq!(got, b"hello federation");

        resp_channel.send_frame(b"ack").await.unwrap();
        let got2 = init_channel.recv_frame().await.unwrap();
        assert_eq!(got2, b"ack");
    }

    #[tokio::test]
    async fn wrong_identity_sig_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (init_key, init_id) = identity_pair(dir.path()).await;
        let (resp_key, _unused_resp_id) = identity_pair(dir.path()).await;
        let (_attacker_key, attacker_id) = identity_pair(dir.path()).await;
        let (_victim_key, victim_id) = identity_pair(dir.path()).await;

        // Malicious responder: claims to be `victim_id` but signs the
        // static pubkey with `attacker_id`'s key instead.
        let bad_sig = attacker_id.sign(&resp_key.public_bytes());
        let bad_payload = IdentityPayload {
            node_id: victim_id.node_id(),
            sig: bad_sig,
        };
        let payload_bytes = encode_payload(&bad_payload).unwrap();

        let (a, b) = tokio::io::duplex(1 << 20);
        let responder_task =
            tokio::spawn(
                async move { fake_responder_with_payload(b, &resp_key, payload_bytes).await },
            );

        let result = handshake_initiator(a, &init_key, &init_id, None).await;
        assert!(matches!(result, Err(NoiseError::BadSignature)));
        responder_task.await.unwrap();
    }

    #[tokio::test]
    async fn undomain_separated_signature_is_dropped() {
        // A signature that's otherwise entirely genuine (right key, right
        // pubkey bytes, right node_id) but computed WITHOUT the
        // NOISE_STATIC_V1 domain prefix must still be rejected. This proves
        // the domain separation is load-bearing, not decorative: an old
        // (pre-domain-separation) signature format, or a signature lifted
        // from a different signing context that happened to cover the same
        // raw bytes, must not verify here.
        let dir = tempfile::tempdir().unwrap();
        let (init_key, init_id) = identity_pair(dir.path()).await;
        let (resp_key, resp_id) = identity_pair(dir.path()).await;

        // Sign the raw static pubkey directly -- no domain prefix -- the
        // way the pre-Task-1-review code did.
        let raw_sig = resp_id.sign(&resp_key.public_bytes());
        let bad_payload = IdentityPayload {
            node_id: resp_id.node_id(),
            sig: raw_sig,
        };
        let payload_bytes = encode_payload(&bad_payload).unwrap();

        let (a, b) = tokio::io::duplex(1 << 20);
        let responder_task =
            tokio::spawn(
                async move { fake_responder_with_payload(b, &resp_key, payload_bytes).await },
            );

        let result = handshake_initiator(a, &init_key, &init_id, None).await;
        assert!(matches!(result, Err(NoiseError::BadSignature)));
        responder_task.await.unwrap();
    }

    #[tokio::test]
    async fn expected_node_id_mismatch_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (init_key, init_id) = identity_pair(dir.path()).await;
        let (resp_key, resp_id) = identity_pair(dir.path()).await;

        let (a, b) = tokio::io::duplex(1 << 20);
        let responder_task =
            tokio::spawn(async move { handshake_responder(b, &resp_key, &resp_id).await });

        let wrong_expected = format!("rf:{}", "0".repeat(64));
        let result = handshake_initiator(a, &init_key, &init_id, Some(&wrong_expected)).await;
        assert!(matches!(result, Err(NoiseError::IdentityMismatch)));
        // Responder's own read of msg3 will fail (initiator dropped its
        // stream without sending it) — that's expected, just confirm no
        // panic on that side either.
        let _ = responder_task.await.unwrap();
    }

    #[tokio::test]
    async fn chunking_roundtrips_one_byte() {
        let (mut a, mut b) = duplex_handshake_pair().await;
        let payload = vec![0x11u8; 1];
        a.send_frame(&payload).await.unwrap();
        assert_eq!(b.recv_frame().await.unwrap(), payload);
    }

    #[tokio::test]
    async fn chunking_roundtrips_at_65519_boundary() {
        // 65519 = MAX_NOISE_PAYLOAD; with the 4-byte length prefix this is
        // the smallest payload that spills into a second Noise message.
        let (mut a, mut b) = duplex_handshake_pair().await;
        let payload = vec![0x22u8; 65519];
        a.send_frame(&payload).await.unwrap();
        assert_eq!(b.recv_frame().await.unwrap(), payload);
    }

    #[tokio::test]
    async fn chunking_roundtrips_100kib() {
        let (mut a, mut b) = duplex_handshake_pair().await;
        let payload = vec![0x33u8; 100 * 1024];
        a.send_frame(&payload).await.unwrap();
        assert_eq!(b.recv_frame().await.unwrap(), payload);
    }

    #[tokio::test]
    async fn garbage_on_wire_returns_error_not_panic() {
        let (mut a, mut b) = duplex_handshake_pair().await;
        // Bypass send_frame entirely: write a length-prefixed blob that is
        // not a valid Noise ciphertext (wrong tag, wrong key, whatever) —
        // simulates line noise or a hostile peer.
        let garbage = vec![0xAAu8; 32];
        write_noise_msg(&mut a.stream, &garbage).await.unwrap();

        let result = b.recv_frame().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_frame_rejects_oversize_content() {
        let (mut a, _b) = duplex_handshake_pair().await;
        let too_big = vec![0u8; MAX_FRAME as usize + 1];
        assert!(a.send_frame(&too_big).await.is_err());
    }

    #[tokio::test]
    async fn recv_frame_rejects_oversize_claimed_length() {
        let (mut a, mut b) = duplex_handshake_pair().await;
        // Hand-craft a validly-encrypted Noise message whose *decrypted*
        // inner length prefix claims more than MAX_FRAME, without ever
        // materializing that many bytes — this must be rejected before any
        // attempt to buffer up to the claimed length.
        let malicious_header = (MAX_FRAME + 1).to_be_bytes();
        let mut ct = vec![0u8; malicious_header.len() + NOISE_TAG_LEN];
        let n = a
            .transport
            .write_message(&malicious_header, &mut ct)
            .unwrap();
        ct.truncate(n);
        write_noise_msg(&mut a.stream, &ct).await.unwrap();

        let result = b.recv_frame().await;
        assert!(result.is_err());
    }
}
