//! Federation core (design doc §1, cycle F): switchyardd-to-switchyardd
//! links secured with Noise and bound to Ed25519 node identities. This
//! module currently provides only the link layer (noise); envelopes, trust
//! store, policies, and routing integration land in later tasks of this
//! cycle.

pub mod noise;
