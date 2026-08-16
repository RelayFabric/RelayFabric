//! Domain-separation prefixes (Controller ruling, Task 1 review): every
//! Ed25519 signature this codebase computes is over a fixed byte prefix
//! naming its signing purpose, concatenated with the purpose-specific bytes.
//!
//! Why: without a prefix, a valid signature produced for one purpose can be
//! byte-identical to (or, worse, replayable as) a valid signature for a
//! *different* purpose whenever the two purposes' raw signed bytes happen to
//! coincide or overlap — a "signature confusion" / cross-protocol replay.
//! Concretely here: the Noise identity-binding payload signs a raw 32-byte
//! X25519 public key, and an envelope's origin signature signs canonical
//! envelope bytes that could — for a maliciously constructed envelope — be
//! made to start with or equal 32 arbitrary bytes. Tagging every signing
//! context with a distinct, never-reused prefix closes that confusion class
//! outright: a signature can only ever verify under the one domain it was
//! created for.
//!
//! Each prefix ends in `-v1:` so a future breaking change to any one
//! signing scheme can mint a new domain (`-v2:`) without any ambiguity
//! against old signatures still in flight.

/// fed/noise.rs: signs the raw 32-byte X25519 static public key transmitted
/// in the Noise identity-binding handshake payload.
pub const NOISE_STATIC_V1: &[u8] = b"relayfabric-noise-static-v1:";

/// fed/sign.rs: signs an envelope's canonical bytes at the origin gateway
/// (design §2, gateway provenance).
pub const ENVELOPE_V1: &[u8] = b"relayfabric-envelope-v1:";

/// fed/sign.rs: signs one attestation-chain link, over
/// `digest(canonical) || prev_sig || ts_rfc3339` (design §2, §33).
pub const ATTEST_V1: &[u8] = b"relayfabric-attest-v1:";
