//! Sealed envelope AEAD format (design doc §2, SPEC §113): the origin edge
//! gateway encrypts the already-signed cycle-F canonical envelope CBOR to
//! the destination edge gateway's stable X25519 key (`fed::sealkey::
//! SealedKey`), so the fabric between them routes opaque ciphertext.
//!
//! `SealedEnvelope` is the wire frame: `alg`/`id`/`expires_at` are
//! CLEARTEXT header fields a router reads before decrypting (routing,
//! dedup on id+expiry, expiry checks); `epk`/`nonce`/`ct` are the AEAD
//! payload. `crypto_box::ChaChaBox` (X25519 key agreement + XChaCha20-
//! Poly1305 AEAD, RustCrypto, license-gated Task 1) has no AAD channel, so
//! the header's `id`/`expires_at` are bound to the ciphertext by
//! DUPLICATION: the sealed plaintext carries its own copy of both, and
//! `unseal` asserts they match the header after decrypting -- see
//! `unseal`'s doc comment.
//!
//! `seal` is wired into federation egress (`engine::process_due_fed`'s
//! `security_mode: sealed` branch, Task 4, design §4). `unseal` is wired
//! into federation ingress (`engine::fed_sealed_ingress`, Task 5, design
//! §5), reached via `fed::conn::handle_frame`'s `Fed::Sealed` arm.

use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{ChaChaBox, PublicKey, SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// The only sealed-envelope algorithm tag this cycle understands (design
/// §2: "recipient rejects unknown alg -> dead-letter UNSUPPORTED_SEAL_ALG
/// -- forward-compat by construction"). The PQ-hybrid seam for a later
/// phase is a NEW tag value, never a change to what this one means.
pub const SEAL_ALG_V1: &str = "x25519-xchacha20poly1305-v1";

/// The wire-visible sealed envelope frame (design §2). `alg`/`id`/
/// `expires_at` are readable without decrypting -- a router uses them for
/// dedup/expiry/alg-support checks before ever touching `ct`. `epk` (32
/// bytes: the per-message ephemeral X25519 public key), `nonce` (24 bytes:
/// the XChaCha20 nonce) and `ct` (the AEAD ciphertext -- the origin's full
/// canonical signed envelope plus a duplicate `id`/`expires_at`, see
/// `unseal`) are opaque to anyone but the holder of the matching sealed
/// secret key. All three are `serde_bytes`-encoded (a CBOR byte string,
/// not an array of CBOR uints) -- same convention `fed::advert::Advert::
/// sig` uses.
///
/// Field lengths (32/24) are NOT enforced by this type itself -- `epk`/
/// `nonce` arrive off the wire as attacker-controlled `Vec<u8>` of
/// whatever length a peer chose to send; `unseal` validates lengths
/// explicitly and fails closed (`SealError::BadSeal`) rather than
/// panicking on a short/long slice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub alg: String,
    pub id: String,
    pub expires_at: i64,
    #[serde(with = "serde_bytes")]
    pub epk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}

/// Sealing/unsealing failures (design §2: "Any failure -> typed error
/// mapped to a dead-letter reason" -- Task 5 maps these to
/// UNSUPPORTED_SEAL_ALG/BAD_SEAL dead-letter reasons). Every variant is a
/// flat fail-closed outcome: none of them carry the attacker-controlled
/// bytes that caused them, so it's always safe to `Display`/log a
/// `SealError` directly.
#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    /// `alg` is not `SEAL_ALG_V1`. Checked FIRST, before any crypto is
    /// attempted -- a receiver that doesn't understand a newer/PQ-hybrid
    /// tag rejects outright rather than guessing at how to open it.
    UnsupportedAlg,
    /// AEAD open failed: wrong recipient key, tampered/malformed `ct`,
    /// `epk`, or `nonce` (including wrong-length `epk`/`nonce`, caught
    /// before ever reaching `crypto_box` -- see `parse_epk`/`parse_nonce`),
    /// or -- lumped into this same variant, not split out -- the correctly
    /// decrypted plaintext wasn't valid CBOR for the expected `(bytes,
    /// string, i64)` shape. `crypto_box`'s own `aead::Error` deliberately
    /// carries no detail (avoids giving an attacker an oracle for WHICH
    /// check failed), so there is nothing more specific this variant could
    /// report either.
    BadSeal,
    /// Decryption and CBOR decode both succeeded, but the plaintext's
    /// duplicated `id`/`expires_at` did not match the cleartext header's.
    /// This is the routing-metadata binding check (design §2: "crypto_box
    /// has no AAD channel; duplication + equality check binds the routing
    /// metadata to the ciphertext without one") -- it is the one failure
    /// mode that is NOT a crypto failure (the ciphertext genuinely opened
    /// under this key/nonce), so it gets its own variant rather than
    /// folding into `BadSeal`.
    BadBinding,
}

/// The plaintext `ct` wraps (design §2): the full canonical signed
/// envelope CBOR, plus a duplicate `id`/`expires_at` for the header
/// binding `unseal` checks. A plain tuple, not a struct with its own
/// `Serialize` impl -- same "explicit tuple, never the type's own derive"
/// posture as `fed::sign::canonical_bytes`/`fed::advert::canonical_bytes`,
/// for the identical reason: this shape must never silently drift because
/// some unrelated struct grew a field. ciborium encodes a Rust tuple as a
/// definite-length CBOR array in field order, which is what makes the KAT
/// byte-stability test below possible.
///
/// The envelope-bytes slot is `serde_bytes::ByteBuf`, NOT a bare
/// `Vec<u8>` (Task 4 review fix round 1, discovered via a real
/// near-`MAX_FRAME` sealed egress test -- carried back into Task 2's
/// format): unlike a STRUCT field, a tuple element has nowhere to hang a
/// `#[serde(with = "serde_bytes")]` attribute, so a bare `Vec<u8>` here
/// serializes via serde's generic `Vec<T>` impl -- a CBOR array of
/// individual per-byte integers, NOT a compact CBOR byte string. For
/// mostly-random AEAD-adjacent bytes (every value 24..=255 costs 2 CBOR
/// bytes instead of 1), that inflates the encoded plaintext to roughly
/// DOUBLE `canonical_env_cbor`'s length before it's even encrypted --
/// invisible at the tiny sizes Task 2's own tests used, but fatal at
/// anything approaching `SEALED_MAX_BYTES` (`engine::process_due_fed_sealed`
/// checks the PRE-seal length, on the assumption -- true again now -- that
/// sealing adds only a small, roughly-constant overhead). `ByteBuf` is
/// `serde_bytes`' owned type: it round-trips through the SAME derive-free
/// tuple shape (`Serialize`/`Deserialize` as a CBOR byte string, not a
/// sequence) without needing a wrapper struct just to attach an attribute.
type SealedPlaintext = (serde_bytes::ByteBuf, String, i64);

fn encode_plaintext(canonical_env_cbor: &[u8], id: &str, expires_at: i64) -> Vec<u8> {
    let tuple: SealedPlaintext = (
        serde_bytes::ByteBuf::from(canonical_env_cbor.to_vec()),
        id.to_string(),
        expires_at,
    );
    let mut buf = Vec::new();
    ciborium::into_writer(&tuple, &mut buf)
        .expect("canonical tuple of a byte vec/string/i64 always serializes");
    buf
}

/// Parses a wire `epk` byte vector into a `crypto_box::PublicKey`, failing
/// closed (`SealError::BadSeal`, never a panic) on any length other than
/// 32 -- `PublicKey::from_slice` itself is already a checked constructor
/// (`Result`, not a panicking one), so this is a thin, explicitly-named
/// wrapper rather than a length assumption baked in anywhere else.
fn parse_epk(epk: &[u8]) -> Result<PublicKey, SealError> {
    PublicKey::from_slice(epk).map_err(|_| SealError::BadSeal)
}

/// Parses a wire `nonce` byte vector into a `crypto_box::Nonce`, failing
/// closed (`SealError::BadSeal`, never a panic) on any length other than
/// 24. Unlike `PublicKey::from_slice`, `GenericArray::from_slice` (which
/// `crypto_box::Nonce::from_slice` is) PANICS on a length mismatch -- so
/// the explicit length check here happens BEFORE that call, making the
/// subsequent `from_slice` provably safe rather than merely "usually
/// fine": `nonce` is attacker-controlled wire input (an arbitrary-length
/// `Vec<u8>`, not a fixed-size array) and must never reach a panicking
/// constructor unchecked.
fn parse_nonce(nonce: &[u8]) -> Result<crypto_box::Nonce, SealError> {
    if nonce.len() != 24 {
        return Err(SealError::BadSeal);
    }
    Ok(*crypto_box::Nonce::from_slice(nonce))
}

/// Seals `canonical_env_cbor` -- the ALREADY-SIGNED cycle-F canonical
/// envelope bytes (design §2: origin signs first, seals second, so the
/// destination verifies the origin signature after decrypt; that ordering
/// is Task 4's job, this function just takes whatever bytes it's handed)
/// -- for `recipient_pub`. Generates a fresh ephemeral X25519 keypair and a
/// random 24-byte nonce per call (design §2: "the origin's static sealed
/// key is NOT used as sender -- forward-compat with §113.3's
/// sealed-sender"; a fresh ephemeral key every message is also why the
/// output is never byte-reproducible -- the test module's `seal_fixed_for_
/// kat` seam fixes both for the KAT).
///
/// Wired into federation egress: `engine::process_due_fed`'s
/// `security_mode: sealed` branch calls this directly -- production egress
/// must always use a fresh ephemeral key, never a persisted/reused one.
pub fn seal(
    canonical_env_cbor: &[u8],
    id: &str,
    expires_at: i64,
    recipient_pub: &PublicKey,
) -> SealedEnvelope {
    let ephemeral_secret = SecretKey::generate(&mut OsRng);
    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    seal_fixed(canonical_env_cbor, id, expires_at, recipient_pub, ephemeral_secret, nonce)
}

/// The fully-deterministic core `seal` (fresh randomness) and the KAT
/// test (fixed randomness) both build on: given an already-chosen
/// ephemeral secret AND nonce, seals with no further randomness. Not
/// exposed beyond this module -- fixing the inputs is purely a test-module
/// concern (see `tests::seal_fixed_for_kat`), never a knob production
/// code should reach for.
fn seal_fixed(
    canonical_env_cbor: &[u8],
    id: &str,
    expires_at: i64,
    recipient_pub: &PublicKey,
    ephemeral_secret: SecretKey,
    nonce: crypto_box::Nonce,
) -> SealedEnvelope {
    let plaintext = encode_plaintext(canonical_env_cbor, id, expires_at);
    let ephemeral_public = ephemeral_secret.public_key();
    let sender_box = ChaChaBox::new(recipient_pub, &ephemeral_secret);
    let ct = sender_box
        .encrypt(&nonce, plaintext.as_slice())
        .expect("encrypting well-formed plaintext under a valid key/nonce cannot fail");
    SealedEnvelope {
        alg: SEAL_ALG_V1.to_string(),
        id: id.to_string(),
        expires_at,
        epk: ephemeral_public.to_bytes().to_vec(),
        nonce: nonce.to_vec(),
        ct,
    }
}

/// Opens `sealed` with `own_secret` (the recipient's `fed::sealkey::
/// SealedKey::secret()`), returning the inner canonical envelope CBOR on
/// success (design §2's full receive-path order):
///
/// 1. `alg != SEAL_ALG_V1` -> `SealError::UnsupportedAlg`, checked first
///    and without touching any crypto.
/// 2. Parse `epk`/`nonce` off the wire (`parse_epk`/`parse_nonce` --
///    wrong-length input fails closed here, never panics).
/// 3. `ChaChaBox::new(&epk, own_secret).decrypt(&nonce, &ct)` -- any AEAD
///    failure (wrong recipient key, tampered `ct`/`epk`/`nonce`) ->
///    `SealError::BadSeal`.
/// 4. CBOR-decode the decrypted plaintext as `(canonical_env_cbor, inner_id,
///    inner_expires_at)` -- a decrypted-but-malformed plaintext also ->
///    `SealError::BadSeal` (design §2 lumps "any failure" up through here
///    into the one variant; see `SealError::BadSeal`'s doc comment).
/// 5. Assert `inner_id == sealed.id && inner_expires_at ==
///    sealed.expires_at` -- the header/inner binding (design §2) -- else
///    `SealError::BadBinding`.
/// 6. Return `canonical_env_cbor`. The CALLER (`engine::fed_sealed_ingress`,
///    Task 5) is responsible for everything downstream: CBOR-decoding it
///    as an `Envelope`, `fed::sign::verify_chain`, trust, dedup.
pub fn unseal(sealed: &SealedEnvelope, own_secret: &SecretKey) -> Result<Vec<u8>, SealError> {
    if sealed.alg != SEAL_ALG_V1 {
        return Err(SealError::UnsupportedAlg);
    }

    let epk = parse_epk(&sealed.epk)?;
    let nonce = parse_nonce(&sealed.nonce)?;

    let recipient_box = ChaChaBox::new(&epk, own_secret);
    let plaintext = recipient_box
        .decrypt(&nonce, sealed.ct.as_slice())
        .map_err(|_| SealError::BadSeal)?;

    let (canonical_env_cbor, inner_id, inner_expires_at): SealedPlaintext =
        ciborium::from_reader(plaintext.as_slice()).map_err(|_| SealError::BadSeal)?;

    if inner_id != sealed.id || inner_expires_at != sealed.expires_at {
        return Err(SealError::BadBinding);
    }

    Ok(canonical_env_cbor.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient_keypair() -> (SecretKey, PublicKey) {
        let secret = SecretKey::generate(&mut OsRng);
        let public = secret.public_key();
        (secret, public)
    }

    // A fixed ephemeral secret + fixed nonce for the KAT below. Neither
    // value is meaningful beyond "some specific 32/24 bytes" -- what
    // matters is that they're FIXED, so the sealed output is
    // byte-reproducible across runs/versions.
    const FIXED_EPHEMERAL: [u8; 32] = [0x11; 32];
    const FIXED_NONCE: [u8; 24] = [0x22; 24];
    // A fixed recipient secret too, so the KAT's `recipient_pub` (and thus
    // the whole sealed byte layout) is fully pinned, not just the sender
    // side.
    const FIXED_RECIPIENT: [u8; 32] = [0x33; 32];
    // Computed once from the fixed ephemeral/nonce/recipient triple above
    // -- see `kat_fixed_ephemeral_and_nonce_locks_exact_sealed_bytes`.
    // Relocked, Task 4 review fix round 1: `SealedPlaintext`'s envelope-
    // bytes slot changed from a bare `Vec<u8>` (serialized as a CBOR array
    // of per-byte integers -- a real bug, not a cosmetic one; see
    // `SealedPlaintext`'s doc comment) to `serde_bytes::ByteBuf`
    // (serialized as a compact CBOR byte string). That is a genuine,
    // intentional wire-format change to what `ct` decrypts to -- this is
    // exactly the "breaking wire-format event" every `canonical_bytes`-
    // style golden vector in this codebase is documented to represent when
    // it moves, not a test casually re-pinned to whatever the code
    // happens to output.
    const KAT_LOCKED_HEX: &str = "a663616c67781b7832353531392d786368616368613230706f6c79313330352d7631626964666b61742d69646a657870697265735f61741a6553f1006365706b58207b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13656e6f6e63655818222222222222222222222222222222222222222222222222626374582fee42b869eb3a1fe5ad00e418a1c8ad3e7c54c3436ade3f184f96e2c295c277a1d42bd7bb8d651fef14346526caaa6a";

    /// Test-only seam completing the byte-stability KAT: given the
    /// a fixed ephemeral secret
    /// PLUS a fixed nonce (both required -- a random nonce alone still
    /// makes the ciphertext non-reproducible), produce a fully
    /// deterministic `SealedEnvelope`. Lives in the test module rather
    /// than as a `pub(crate)` production function, since fixing the nonce
    /// is never something real sealing should ever want to do (a reused
    /// nonce under the same key is a real AEAD confidentiality break) --
    /// unlike the ephemeral-secret seam, which the brief explicitly names
    /// as a reusable interface.
    fn seal_for_kat(
        canonical_env_cbor: &[u8],
        id: &str,
        expires_at: i64,
        recipient_pub: &PublicKey,
    ) -> SealedEnvelope {
        let ephemeral_secret = SecretKey::from_bytes(FIXED_EPHEMERAL);
        let nonce = *crypto_box::Nonce::from_slice(&FIXED_NONCE);
        seal_fixed(canonical_env_cbor, id, expires_at, recipient_pub, ephemeral_secret, nonce)
    }

    // --- round-trip -----------------------------------------------------

    #[test]
    fn unseal_of_seal_round_trips_the_canonical_bytes() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let env_cbor = b"pretend this is a canonical signed envelope".to_vec();
        let sealed = seal(&env_cbor, "msg-1", 1_800_000_000, &recipient_pub);

        let opened = unseal(&sealed, &recipient_secret).unwrap();
        assert_eq!(opened, env_cbor);
    }

    #[test]
    fn unseal_of_seal_with_ephemeral_round_trips() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let env_cbor = b"another canonical envelope body".to_vec();
        let ephemeral = SecretKey::generate(&mut OsRng);
        let sealed =
            seal_fixed(&env_cbor, "msg-2", 1_800_000_001, &recipient_pub, ephemeral,
                       ChaChaBox::generate_nonce(&mut OsRng));

        let opened = unseal(&sealed, &recipient_secret).unwrap();
        assert_eq!(opened, env_cbor);
    }

    #[test]
    fn header_fields_carry_through_unchanged() {
        let (_recipient_secret, recipient_pub) = recipient_keypair();
        let env_cbor = b"body".to_vec();
        let sealed = seal(&env_cbor, "msg-header-check", 42, &recipient_pub);
        assert_eq!(sealed.alg, SEAL_ALG_V1);
        assert_eq!(sealed.id, "msg-header-check");
        assert_eq!(sealed.expires_at, 42);
        assert_eq!(sealed.epk.len(), 32);
        assert_eq!(sealed.nonce.len(), 24);
    }

    // --- KAT byte-stability ----------------------------------------------

    #[test]
    fn kat_fixed_ephemeral_and_nonce_locks_exact_sealed_bytes() {
        let recipient_secret = SecretKey::from_bytes(FIXED_RECIPIENT);
        let recipient_pub = recipient_secret.public_key();
        let env_cbor = b"KAT envelope body".to_vec();

        let sealed = seal_for_kat(&env_cbor, "kat-id", 1_700_000_000, &recipient_pub);

        // Cross-version stability lock (brief: "a KAT test injects a
        // FIXED ephemeral secret (+ fixed nonce ...) to lock exact sealed
        // bytes for cross-version stability"). Locks the entire serialized
        // wire frame (CBOR of the `SealedEnvelope` struct itself, header
        // fields included) as one hex string -- same golden-vector
        // convention `fed::sign`/`fed::advert` already use. If this ever
        // changes, that's a breaking wire-format event for the sealed
        // envelope AEAD, not a test to casually update.
        let mut serialized = Vec::new();
        ciborium::into_writer(&sealed, &mut serialized).unwrap();
        let hex: String = serialized.iter().map(|b| format!("{b:02x}")).collect();

        assert_eq!(hex, KAT_LOCKED_HEX);
    }

    // --- tamper matrix ----------------------------------------------------

    #[test]
    fn tamper_ct_byte_fails_bad_seal() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-3", 1, &recipient_pub);
        sealed.ct[0] ^= 0xFF;
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadSeal));
    }

    #[test]
    fn tamper_epk_byte_fails_bad_seal() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-4", 1, &recipient_pub);
        sealed.epk[0] ^= 0xFF;
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadSeal));
    }

    #[test]
    fn tamper_nonce_byte_fails_bad_seal() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-5", 1, &recipient_pub);
        sealed.nonce[0] ^= 0xFF;
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadSeal));
    }

    #[test]
    fn tamper_header_id_fails_bad_binding() {
        // The AEAD itself still opens fine (id isn't part of ct's AAD --
        // there is none); the mismatch is only caught by the post-decrypt
        // binding check.
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-6", 1, &recipient_pub);
        sealed.id = "different-id".to_string();
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadBinding));
    }

    #[test]
    fn tamper_header_expires_at_fails_bad_binding() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-7", 1, &recipient_pub);
        sealed.expires_at = 999;
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadBinding));
    }

    // --- wrong key / unknown alg -------------------------------------------

    #[test]
    fn wrong_recipient_secret_fails_bad_seal() {
        let (_recipient_secret, recipient_pub) = recipient_keypair();
        let (wrong_secret, _wrong_pub) = recipient_keypair();
        let sealed = seal(b"body", "msg-8", 1, &recipient_pub);
        assert_eq!(unseal(&sealed, &wrong_secret), Err(SealError::BadSeal));
    }

    #[test]
    fn unknown_alg_fails_unsupported_alg_without_touching_crypto() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-9", 1, &recipient_pub);
        sealed.alg = "some-future-pq-hybrid-v2".to_string();
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::UnsupportedAlg));
    }

    // --- malformed wire input never panics ---------------------------------

    #[test]
    fn wrong_length_epk_fails_bad_seal_not_panic() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-10", 1, &recipient_pub);
        sealed.epk = vec![0u8; 5]; // way short of 32
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadSeal));
    }

    #[test]
    fn oversized_epk_fails_bad_seal_not_panic() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-11", 1, &recipient_pub);
        sealed.epk = vec![0u8; 64]; // too long
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadSeal));
    }

    #[test]
    fn wrong_length_nonce_fails_bad_seal_not_panic() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-12", 1, &recipient_pub);
        sealed.nonce = vec![0u8; 3]; // way short of 24
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadSeal));
    }

    #[test]
    fn empty_epk_and_nonce_fail_bad_seal_not_panic() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-13", 1, &recipient_pub);
        sealed.epk = Vec::new();
        sealed.nonce = Vec::new();
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadSeal));
    }

    /// Carried from the Task 2 review (round 1): probed live but never
    /// committed as a permanent test. `epk`/`nonce` are both still
    /// well-formed (32/24 bytes) and `alg` is the one this build supports
    /// -- only `ct` itself is empty, so this exercises the AEAD open call
    /// directly (`ChaChaBox::decrypt`), not the length pre-checks
    /// `parse_epk`/`parse_nonce` already cover above. An empty ciphertext
    /// can never contain a valid 16-byte Poly1305 tag, so decryption must
    /// fail closed (`SealError::BadSeal`) rather than panic on an
    /// out-of-bounds read while trying to split off a tag that isn't there.
    #[test]
    fn empty_ct_under_a_valid_alg_fails_bad_seal_not_panic() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-14", 1, &recipient_pub);
        assert_eq!(sealed.alg, SEAL_ALG_V1, "fixture sanity check: alg must be the valid one");
        sealed.ct = Vec::new();
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadSeal));
    }

    /// Same carried case, the other shape: `ct` present but truncated to
    /// fewer bytes than the 16-byte AEAD tag alone would need -- still a
    /// valid `alg`, still fails closed rather than panicking.
    #[test]
    fn truncated_ct_under_a_valid_alg_fails_bad_seal_not_panic() {
        let (recipient_secret, recipient_pub) = recipient_keypair();
        let mut sealed = seal(b"body", "msg-15", 1, &recipient_pub);
        assert_eq!(sealed.alg, SEAL_ALG_V1, "fixture sanity check: alg must be the valid one");
        sealed.ct.truncate(3); // well short of the 16-byte AEAD tag alone
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::BadSeal));
    }

    // --- no sentinel plaintext in the serialized frame ---------------------

    #[test]
    fn serialized_sealed_envelope_never_contains_the_sentinel_body() {
        const SENTINEL: &[u8] = b"SENTINEL-PLAINTEXT-SHOULD-NEVER-APPEAR-ON-THE-WIRE";
        let (_recipient_secret, recipient_pub) = recipient_keypair();
        let sealed = seal(SENTINEL, "msg-sentinel", 1, &recipient_pub);

        let mut serialized = Vec::new();
        ciborium::into_writer(&sealed, &mut serialized).unwrap();

        assert!(
            !serialized.windows(SENTINEL.len()).any(|w| w == SENTINEL),
            "serialized sealed envelope leaked the sentinel plaintext body"
        );
    }

    // --- alg check happens before crypto ------------------------------------

    #[test]
    fn unknown_alg_is_rejected_even_with_garbage_epk_nonce_ct() {
        // Proves alg is checked FIRST (design §2 order) -- a completely
        // garbage epk/nonce/ct with an unrecognized alg still yields
        // UnsupportedAlg, not a crypto-layer BadSeal from trying (and
        // panicking on, if the ordering were wrong) garbage bytes.
        let (recipient_secret, _recipient_pub) = recipient_keypair();
        let sealed = SealedEnvelope {
            alg: "totally-unknown".to_string(),
            id: "x".to_string(),
            expires_at: 1,
            epk: vec![0u8; 1],
            nonce: vec![0u8; 1],
            ct: vec![0u8; 1],
        };
        assert_eq!(unseal(&sealed, &recipient_secret), Err(SealError::UnsupportedAlg));
    }
}
