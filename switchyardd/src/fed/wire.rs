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
//! Consumed by `fed::conn`, which drives `FedChannel::send_frame`/
//! `recv_frame` with CBOR bytes of these variants on every live connection.
//! `Sealed` (design §4/§5, SPEC §113.4/§113.2, cycle H) is this cycle's
//! additive variant: `engine::process_due_fed`'s `security_mode: sealed`
//! branch sends it (Task 4); `fed::conn::handle_frame` dispatches it to
//! `engine::fed_sealed_ingress` (Task 5) exactly like `Envelope` dispatches
//! to `engine::fed_ingress`.

use super::advert::Advert;
use super::seal::SealedEnvelope;
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
    Ack { id: String },
    /// Keepalive, sender → peer (design §5: 30s keepalive, 90s dead timer).
    Ping {},
    /// Keepalive reply.
    Pong {},
    /// RFDP discovery (design §2, cycle G): the sender's current signed
    /// Node Advertisement -- sent as a reply to a peer's `AdvertReq`, or
    /// proactively on the per-connection refresh timer (`fed::conn`,
    /// `advert_ttl_secs / 2`). Not boxed unlike `Envelope`'s `env`: an
    /// `Advert` is far smaller (no message body/attachments), well under
    /// the size where `clippy::large_enum_variant` would flag it.
    Advert { advert: Advert },
    /// RFDP discovery (design §2, cycle G): "send me your current advert,
    /// if you have one" -- sent once by each side at connection-up
    /// (subject to the local discovery scope gate, `fed::conn::
    /// advert_scope_allows`), and carries no fields of its own.
    AdvertReq {},
    /// Sealed-routing egress (design §4, SPEC §113.4, cycle H, Task 4): a
    /// routed message whose payload the ORIGIN edge gateway has AEAD-sealed
    /// (`fed::seal::seal`) for the destination edge gateway's stable
    /// `sealed_key` -- the fabric between them (phase-1: the direct peer
    /// only, no relay-through yet) routes opaque ciphertext. `sealed.id`/
    /// `sealed.expires_at` are the CLEARTEXT routing/dedup/expiry header a
    /// receiver reads without decrypting (`fed::seal::SealedEnvelope`'s own
    /// doc comment); `target_route` is the same "which local route on the
    /// RECEIVER'S side" addressing `Fed::Envelope::target_route` already
    /// uses, cleartext for the identical reason (routing metadata, not
    /// payload). Ingress handling (`fed::seal::unseal` -> CBOR-decode as
    /// `Envelope` -> `fed::sign::verify_chain` -> trust -> downgrade
    /// refusal -> dedup -> deliver, design §5) is `engine::
    /// fed_sealed_ingress` (Task 5), dispatched from `fed::conn::
    /// handle_frame` exactly like `Envelope` dispatches to `fed_ingress`.
    Sealed {
        sealed: SealedEnvelope,
        target_route: String,
    },
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
            Endpoint {
                protocol: "mock".into(),
                endpoint: "chan".into(),
            },
            Sender {
                native_ref: "!abcd".into(),
            },
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
        let msg = Fed::Envelope {
            env: Box::new(env),
            target_route: "regional-chat".into(),
        };
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
        let msg = Fed::Ack {
            id: "0189f1e4-1111-7000-8000-000000000001".into(),
        };
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

    // --- RFDP discovery frames (design §2, cycle G) ------------------------

    fn sample_advert() -> Advert {
        use crate::fed::advert::SecurityCaps;
        use std::collections::BTreeMap;
        Advert {
            rf_version: 1,
            node_id: format!("rf:{}", "ab".repeat(32)),
            name: "test-node".into(),
            services: BTreeMap::from([("federation".to_string(), true)]),
            protocols: BTreeMap::new(),
            security: SecurityCaps {
                translate: true,
                signed: true,
                sealed: true,
                sealed_key: Some("33".repeat(32)),
            },
            expires: 1_786_838_400,
            sig: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn advert_frame_roundtrips() {
        let msg = Fed::Advert {
            advert: sample_advert(),
        };
        match roundtrip(&msg) {
            Fed::Advert { advert } => assert_eq!(advert, sample_advert()),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn advert_req_frame_roundtrips() {
        let msg = Fed::AdvertReq {};
        assert!(matches!(roundtrip(&msg), Fed::AdvertReq {}));
    }

    // --- Sealed frame (design §4, SPEC §113.4, cycle H, Task 4) -----------

    fn sample_sealed() -> SealedEnvelope {
        SealedEnvelope {
            alg: "x25519-xchacha20poly1305-v1".into(),
            id: "0189f1e4-4444-7000-8000-000000000004".into(),
            expires_at: 1_800_000_000,
            epk: vec![7u8; 32],
            nonce: vec![9u8; 24],
            ct: vec![1, 2, 3, 4, 5, 6, 7, 8],
        }
    }

    #[test]
    fn sealed_frame_roundtrips() {
        let msg = Fed::Sealed {
            sealed: sample_sealed(),
            target_route: "regional-chat".into(),
        };
        match roundtrip(&msg) {
            Fed::Sealed {
                sealed,
                target_route,
            } => {
                assert_eq!(sealed, sample_sealed());
                assert_eq!(target_route, "regional-chat");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // --- unknown-tag tolerance --------------------------------------------

    /// The base case: a tag no variant recognizes, no other fields at all.
    #[test]
    fn unknown_tag_with_no_other_fields_decodes_to_unknown() {
        let map = Value::Map(vec![(
            Value::Text("t".into()),
            Value::Text("future_thing".into()),
        )]);
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
