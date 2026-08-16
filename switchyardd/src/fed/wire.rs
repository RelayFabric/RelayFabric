//! Federation wire frames (design §5): the CBOR-tagged frames exchanged
//! over an established `fed::noise::FedChannel` once its Noise handshake is
//! complete. `hello` (the Noise identity-binding payload) is NOT one of
//! these -- it's exchanged inside the handshake itself (`fed/noise.rs`),
//! before any `Fed` frame can flow.
//!
//! Tag field is `t` (relay-ipc's `PluginToDaemon`/`DaemonToPlugin`
//! precedent), CBOR-encoded via `ciborium` the same way. Unlike relay-ipc's
//! enums -- which error on an unrecognized tag, because both ends of that
//! wire are versioned together in this repo -- `Fed` MUST tolerate an
//! unrecognized tag from a peer running a newer daemon (design §5
//! "additive versioning: unknown `t` ignored"): a fed link crosses
//! independently-upgraded nodes, so an older daemon has to keep working
//! when a newer peer sends a frame type it doesn't know about yet, rather
//! than tearing down the link. `#[serde(other)]` on the trailing unit
//! variant gives this for free with an internally-tagged enum: serde
//! buffers the whole frame into a generic `Content` value before matching
//! `t`, so a `t` it doesn't recognize falls through to `Unknown` regardless
//! of what other fields the unrecognized frame carries -- proved by
//! `unknown_tag_with_unrecognized_fields_decodes_to_unknown` below, which
//! deliberately includes fields no known variant has.
//!
//! This module is staged: nothing in main's runtime path sends/receives a
//! `Fed` frame yet (consumed by `fed/conn.rs` Task 4 / engine egress/ingress
//! Task 5, which drive `FedChannel::send_frame`/`recv_frame` with CBOR
//! bytes of these variants). Silence dead_code at the module level until
//! then, same as `fed/sign.rs`.
#![allow(dead_code)]

use relay_core::Envelope;
use serde::{Deserialize, Serialize};

/// One frame on a federation link (design §5). `Envelope`/`Ack`/`Ping`/
/// `Pong` are the only frame types this cycle defines; `Unknown` is the
/// decode-only fallback for any future tag a newer peer might send.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Fed {
    /// A routed message, addressed to the peer's local route named
    /// `target_route` (design §5 ingress: `target_route ∈ ingress_routes`
    /// is enforced by the RECEIVER, not the sender). `env` is boxed
    /// (clippy::large_enum_variant): `Envelope` is by far the largest field
    /// any variant here carries, and boxing it keeps `Ack`/`Ping`/`Pong`
    /// from paying for its stack size on every construction/match. `Box<T>`
    /// serializes identically to `T` (serde forwards through it), so the
    /// wire shape is unaffected -- still a plain `env` map, not wrapped.
    Envelope {
        env: Box<Envelope>,
        target_route: String,
    },
    /// Acknowledges successful ingress of the envelope `id` (design §5
    /// egress: `Fed::Ack{id}` ⇒ delivered).
    Ack {
        id: String,
    },
    /// Keepalive, sender → peer (design §5: 30s keepalive, 90s dead timer).
    Ping {},
    /// Keepalive reply.
    Pong {},
    /// Decode-only fallback for a `t` this build doesn't recognize (design
    /// §5 "additive versioning: unknown `t` ignored (fleet precedent)").
    /// Callers ignore it outright -- there is nothing on it to act on.
    /// Never intentionally constructed to send; encoding it would produce a
    /// frame tagged `"unknown"`, which is not a real wire frame type.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use ciborium::Value;
    use relay_core::{Endpoint, Sender};

    fn envelope() -> Envelope {
        let now = Utc::now();
        Envelope::new(
            Endpoint { protocol: "mock".into(), endpoint: "chan".into() },
            Sender { native_ref: "!abcd".into() },
            "text".into(),
            "hello".into(),
            now,
            now + Duration::hours(1),
            8,
        )
    }

    fn roundtrip(msg: &Fed) -> Fed {
        let mut buf = Vec::new();
        ciborium::into_writer(msg, &mut buf).unwrap();
        ciborium::from_reader(buf.as_slice()).unwrap()
    }

    // --- roundtrips ------------------------------------------------------

    #[test]
    fn envelope_frame_roundtrips() {
        let env = envelope();
        let id = env.id;
        let msg = Fed::Envelope { env: Box::new(env), target_route: "regional-chat".into() };
        match roundtrip(&msg) {
            Fed::Envelope { env, target_route } => {
                assert_eq!(env.id, id);
                assert_eq!(target_route, "regional-chat");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn ack_frame_roundtrips() {
        let msg = Fed::Ack { id: "0189f1e4-1111-7000-8000-000000000001".into() };
        match roundtrip(&msg) {
            Fed::Ack { id } => assert_eq!(id, "0189f1e4-1111-7000-8000-000000000001"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn ping_frame_roundtrips() {
        let msg = Fed::Ping {};
        assert!(matches!(roundtrip(&msg), Fed::Ping {}));
    }

    #[test]
    fn pong_frame_roundtrips() {
        let msg = Fed::Pong {};
        assert!(matches!(roundtrip(&msg), Fed::Pong {}));
    }

    // --- unknown-tag tolerance --------------------------------------------

    /// The base case: a tag no variant recognizes, no other fields at all.
    #[test]
    fn unknown_tag_with_no_other_fields_decodes_to_unknown() {
        let map = Value::Map(vec![(Value::Text("t".into()), Value::Text("future_thing".into()))]);
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        let decoded: Fed = ciborium::from_reader(buf.as_slice()).unwrap();
        assert!(matches!(decoded, Fed::Unknown), "got {decoded:?}");
    }

    /// The real-world case (design §5's actual concern): a tag no variant
    /// recognizes, PLUS fields that don't belong to any known `Fed` variant
    /// either -- e.g. a future `t: "resync"` frame carrying its own novel
    /// field shapes. `#[serde(other)]` on an internally-tagged enum buffers
    /// the entire frame into a generic value before ever trying to match a
    /// variant, so unrecognized extra fields must not cause a decode error
    /// -- this is the scenario the brief singled out as needing an actual
    /// test rather than an assumption.
    #[test]
    fn unknown_tag_with_unrecognized_fields_decodes_to_unknown() {
        let map = Value::Map(vec![
            (Value::Text("t".into()), Value::Text("resync".into())),
            (Value::Text("weird_field".into()), Value::Integer(42.into())),
            (
                Value::Text("nested".into()),
                Value::Array(vec![Value::Text("x".into()), Value::Bool(true)]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        let decoded: Fed = ciborium::from_reader(buf.as_slice()).unwrap();
        assert!(matches!(decoded, Fed::Unknown), "got {decoded:?}");
    }

    /// A known tag but with an extra, never-defined field alongside its real
    /// ones must still decode into that known variant (forward-compat within
    /// a recognized frame type), not fall through to `Unknown`.
    #[test]
    fn known_tag_with_extra_unrecognized_field_still_decodes_to_that_variant() {
        let map = Value::Map(vec![
            (Value::Text("t".into()), Value::Text("ping".into())),
            (Value::Text("surprise".into()), Value::Integer(1.into())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        let decoded: Fed = ciborium::from_reader(buf.as_slice()).unwrap();
        assert!(matches!(decoded, Fed::Ping {}), "got {decoded:?}");
    }
}
