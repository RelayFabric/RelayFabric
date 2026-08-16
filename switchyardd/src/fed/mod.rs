//! Federation core (design doc §1-5, cycle F): switchyardd-to-switchyardd
//! links secured with Noise and bound to Ed25519 node identities, signed
//! canonical envelopes with an attestation chain, and the CBOR wire frames
//! exchanged over a link once its handshake completes. This module
//! currently provides the link layer (noise), the signing layer (sign), and
//! the frame layer (wire); the trust store lives in `storage.rs` and
//! federation policy config in `config.rs` (both cross-cutting, so they
//! aren't under `fed/`). Connection lifecycle and routing integration land
//! in later tasks of this cycle.

pub mod domains;
pub mod noise;
pub mod sign;
pub mod wire;
