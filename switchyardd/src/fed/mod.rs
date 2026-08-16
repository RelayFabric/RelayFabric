//! Federation core (design doc §1-2, cycle F): switchyardd-to-switchyardd
//! links secured with Noise and bound to Ed25519 node identities, plus
//! signed canonical envelopes with an attestation chain. This module
//! currently provides the link layer (noise) and the signing layer (sign);
//! trust store, policies, and routing integration land in later tasks of
//! this cycle.

pub mod domains;
pub mod noise;
pub mod sign;
