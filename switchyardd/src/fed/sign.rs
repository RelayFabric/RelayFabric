//! Signed envelopes with an attestation chain (design doc §2, §33): the
//! origin gateway signs an envelope's canonical bytes once
//! (`sign_origin`/`verify_origin`), and every forwarding gateway appends a
//! chained attestation (`append_attestation`) that a receiver walks and
//! verifies end-to-end (`verify_chain`) before accepting the envelope. v0.3
//! signs at the origin gateway only (gateway provenance, §30); user-key
//! origin signatures are v0.4.
//!
//! `verify_chain` is consumed by `engine::fed_ingress` (Task 4). `sign_origin`/
//! `append_attestation` are consumed by federation egress
//! (`engine::process_due_fed`, Task 5).

use super::domains;
use crate::node_identity::{self, NodeIdentity};
use chrono::{DateTime, Utc};
use relay_core::{Attestation, Envelope, OriginSig};
use sha2::{Digest, Sha256};
use std::fmt;

/// Signature-chain verification failures. Any failure here means the caller
/// dead_letters the envelope `BAD_SIGNATURE` (design §2, §5).
#[derive(Debug, PartialEq, Eq)]
pub enum SigError {
    /// The envelope has no origin signature to verify or to chain
    /// attestations from.
    MissingOrigin,
    /// A signature (the origin's, or one attestation link's) did not
    /// verify against its expected signer and bytes.
    BadSignature,
}

impl fmt::Display for SigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SigError::MissingOrigin => write!(f, "envelope has no origin signature"),
            SigError::BadSignature => write!(f, "envelope signature chain did not verify"),
        }
    }
}

impl std::error::Error for SigError {}

/// Deterministic CBOR array of the fields an origin/attestation signature
/// covers (design §2, revised per Task 2 review round 1): `[id,
/// source.protocol, source.endpoint, sender.native_ref, kind, body,
/// created_at.to_rfc3339(), sorted [sha256, filename, mime, size] per
/// attachment]`.
///
/// Two review-driven widenings over the original spec, both closing a
/// tamper class an on-path relay could otherwise exploit without breaking
/// the origin signature:
/// - Attachments sign their full per-attachment metadata (`filename`,
///   `mime`, `size`), not just the content hash -- otherwise a relay could
///   rewrite a filename/mime/size (e.g. disguise an executable as a PDF)
///   while leaving a signature over the untouched bytes valid.
/// - `source.endpoint` is included alongside `source.protocol` -- otherwise
///   a relay could redirect an envelope to a different endpoint under the
///   same protocol undetected (a display-spoof class: the receiving side
///   would show a channel the origin never signed for).
///
/// Built as an explicit tuple -- NOT by serializing `Envelope` itself --
/// so the signed bytes can never shift because of the struct's own field
/// order/additions (e.g. the `origin`/`attestations`/`hops` fields this
/// same design adds must never be part of what gets signed, or signing
/// would be self-referential). ciborium serializes a Rust tuple as a
/// definite-length CBOR array in field order, which is what makes this
/// byte-for-byte stable across versions -- locked by the golden vector test
/// below. `priority` is deliberately NOT signed -- federation ingress
/// strips/ignores remote `priority` entirely (Task 4's job; controller
/// ruling), so there is nothing here for a signature to protect.
pub fn canonical_bytes(env: &Envelope) -> Vec<u8> {
    let mut attachments: Vec<(&str, &str, &str, u64)> = env
        .attachments
        .iter()
        .map(|a| {
            (
                a.sha256.as_str(),
                a.filename.as_str(),
                a.mime.as_str(),
                a.size,
            )
        })
        .collect();
    attachments.sort_unstable_by(|a, b| a.0.cmp(b.0));

    let tuple = (
        env.id.to_string(),
        env.source.protocol.as_str(),
        env.source.endpoint.as_str(),
        env.sender.native_ref.as_str(),
        env.kind.as_str(),
        env.body.as_str(),
        env.created_at.to_rfc3339(),
        attachments,
    );
    let mut buf = Vec::new();
    ciborium::into_writer(&tuple, &mut buf)
        .expect("canonical tuple of primitive/string fields always serializes");
    buf
}

/// SHA-256 digest of the canonical bytes (design §2's `digest(canonical)`),
/// the fixed anchor every attestation in the chain signs over. Note this
/// digest never changes as attestations are appended -- it depends only on
/// the fields `canonical_bytes` covers, none of which is the attestation
/// list itself.
fn digest_canonical(env: &Envelope) -> [u8; 32] {
    Sha256::digest(canonical_bytes(env)).into()
}

/// `domain || parts[0] || parts[1] || ...` -- the shared domain-separation
/// concatenation used by every signing context in fed/ (Task 1 review
/// ruling, see `fed/domains.rs`).
fn domain_separated(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let len = domain.len() + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut msg = Vec::with_capacity(len);
    msg.extend_from_slice(domain);
    for p in parts {
        msg.extend_from_slice(p);
    }
    msg
}

fn origin_bytes(env: &Envelope) -> Vec<u8> {
    let canonical = canonical_bytes(env);
    domain_separated(domains::ENVELOPE_V1, &[&canonical])
}

/// Sign an envelope's canonical bytes at the origin gateway (design §2:
/// `domains::ENVELOPE_V1 || canonical_bytes`).
///
/// Consumed by federation egress (`engine::process_due_fed`, Task 5: signs
/// a locally-originated envelope's `origin` the first time it egresses to a
/// peer) and by this crate's own test fixtures (`engine::tests_support::
/// signed_test_envelope`).
pub fn sign_origin(env: &Envelope, identity: &NodeIdentity) -> OriginSig {
    OriginSig {
        node_id: identity.node_id(),
        sig: identity.sign(&origin_bytes(env)),
    }
}

/// Verify an envelope's origin signature against its current canonical
/// bytes. Does not walk `attestations` -- see `verify_chain` for the full
/// walk.
pub fn verify_origin(env: &Envelope) -> Result<(), SigError> {
    let origin = env.origin.as_ref().ok_or(SigError::MissingOrigin)?;
    if node_identity::verify(&origin.node_id, &origin_bytes(env), &origin.sig) {
        Ok(())
    } else {
        Err(SigError::BadSignature)
    }
}

/// Bytes one attestation link signs: `digest(canonical) || prev_sig ||
/// ts_rfc3339` (design §2), domain-separated with `domains::ATTEST_V1`.
fn attestation_bytes(digest: &[u8; 32], prev_sig: &[u8], ts: DateTime<Utc>) -> Vec<u8> {
    let ts_bytes = ts.to_rfc3339();
    domain_separated(domains::ATTEST_V1, &[digest, prev_sig, ts_bytes.as_bytes()])
}

/// Append one attestation to the chain: `identity` signs over the
/// envelope's canonical-bytes digest, chained to the previous link's
/// signature (the last attestation's sig, or the origin's sig if this is
/// the first attestation), plus `now`. Requires an origin signature to
/// already be present -- an envelope can't be attested before it's signed.
///
/// Consumed by federation egress (`engine::process_due_fed`, Task 5): every
/// outbound hop -- whether this daemon is the origin (just signed above) or
/// a forwarding gateway relaying an already-signed envelope -- appends its
/// own attestation before sending.
pub fn append_attestation(
    env: &mut Envelope,
    identity: &NodeIdentity,
    now: DateTime<Utc>,
) -> Result<(), SigError> {
    let digest = digest_canonical(env);
    let prev_sig: Vec<u8> = match env.attestations.last() {
        Some(a) => a.sig.clone(),
        None => env
            .origin
            .as_ref()
            .ok_or(SigError::MissingOrigin)?
            .sig
            .clone(),
    };
    let sig = identity.sign(&attestation_bytes(&digest, &prev_sig, now));
    env.attestations.push(Attestation {
        node_id: identity.node_id(),
        ts: now,
        sig,
    });
    Ok(())
}

/// Walk and verify the full chain: the origin signature, then every
/// attestation in order, each checked against the digest of the current
/// canonical bytes chained to the previous link's signature. Any failure
/// anywhere in the chain is `BadSignature` (design §2: any failure ->
/// dead_letter `BAD_SIGNATURE`).
pub fn verify_chain(env: &Envelope) -> Result<(), SigError> {
    verify_origin(env)?;
    let digest = digest_canonical(env);
    let mut prev_sig: Vec<u8> = env
        .origin
        .as_ref()
        .expect("verify_origin above already required this to be Some")
        .sig
        .clone();
    for att in &env.attestations {
        let msg = attestation_bytes(&digest, &prev_sig, att.ts);
        if !node_identity::verify(&att.node_id, &msg, &att.sig) {
            return Err(SigError::BadSignature);
        }
        prev_sig = att.sig.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Duration};
    use relay_core::{AttachmentMeta, Endpoint, Sender};
    use uuid::Uuid;

    fn identity(dir: &std::path::Path, name: &str) -> NodeIdentity {
        NodeIdentity::load_or_create(&dir.join(name)).unwrap()
    }

    /// A fully fixed envelope (fixed id, fixed timestamps) so tests --
    /// especially the golden vector -- are deterministic. `created_at` is
    /// the only timestamp `canonical_bytes` reads; `received_at` (set by
    /// `Envelope::new` to `Utc::now()`) is deliberately NOT part of the
    /// signed fields, so it's left as-is.
    fn fixed_envelope() -> Envelope {
        let created_at: DateTime<Utc> = "2026-08-16T00:00:00Z".parse().unwrap();
        let mut env = Envelope::new(
            Endpoint {
                protocol: "mock".into(),
                endpoint: "chan".into(),
            },
            Sender {
                native_ref: "!abcd1234".into(),
            },
            "text".into(),
            "hello federation".into(),
            created_at,
            created_at + Duration::hours(24),
            8,
        );
        env.id = Uuid::parse_str("0189f1e4-1111-7000-8000-000000000001").unwrap();
        env
    }

    // --- golden vector -----------------------------------------------

    #[test]
    fn canonical_bytes_golden_vector_is_locked() {
        let env = fixed_envelope();
        let hex: String = canonical_bytes(&env)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        // Cross-version stability lock (design §2): if this ever changes,
        // that's a breaking wire-format event for federation signing, not
        // a test to casually update.
        assert_eq!(
            hex,
            "88782430313839663165342d313131312d373030302d383030302d30303030303030303030\
             3031646d6f636b646368616e6921616263643132333464746578747068656c6c6f206665\
             646572617469\
             6f6e7819323032362d30382d31365430303a30303a30302b30303a303080"
        );
    }

    // --- sign/verify round-trip ---------------------------------------

    #[test]
    fn sign_and_verify_origin_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut env = fixed_envelope();
        env.origin = Some(sign_origin(&env, &id));
        assert_eq!(verify_origin(&env), Ok(()));
    }

    #[test]
    fn verify_chain_with_origin_only_and_no_attestations_is_ok() {
        // Base case (design §2): a freshly-originated envelope that has
        // never been forwarded has a valid origin signature and an empty
        // attestation list -- `verify_chain` must accept that as a complete,
        // valid chain on its own, not require at least one attestation.
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut env = fixed_envelope();
        env.origin = Some(sign_origin(&env, &id));
        assert!(env.attestations.is_empty());
        assert_eq!(verify_chain(&env), Ok(()));
    }

    #[test]
    fn append_attestation_and_verify_chain_round_trips_multiple_hops() {
        let dir = tempfile::tempdir().unwrap();
        let origin_id = identity(dir.path(), "origin");
        let hop1 = identity(dir.path(), "hop1");
        let hop2 = identity(dir.path(), "hop2");
        let now = Utc::now();

        let mut env = fixed_envelope();
        env.origin = Some(sign_origin(&env, &origin_id));
        append_attestation(&mut env, &hop1, now).unwrap();
        append_attestation(&mut env, &hop2, now + Duration::seconds(1)).unwrap();

        assert_eq!(env.attestations.len(), 2);
        assert_eq!(verify_chain(&env), Ok(()));
    }

    #[test]
    fn append_attestation_without_origin_is_missing_origin() {
        let dir = tempfile::tempdir().unwrap();
        let hop1 = identity(dir.path(), "hop1");
        let mut env = fixed_envelope();
        let err = append_attestation(&mut env, &hop1, Utc::now()).unwrap_err();
        assert_eq!(err, SigError::MissingOrigin);
    }

    #[test]
    fn verify_origin_without_origin_is_missing_origin() {
        let env = fixed_envelope();
        assert_eq!(verify_origin(&env), Err(SigError::MissingOrigin));
    }

    // --- tamper matrix: flip one byte in body, ref, id, attestation ts,
    // sig -- each must fail verification. ------------------------------

    #[test]
    fn tamper_body_after_signing_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut env = fixed_envelope();
        env.origin = Some(sign_origin(&env, &id));
        assert_eq!(verify_origin(&env), Ok(()));

        env.body.push('!');
        assert_eq!(verify_origin(&env), Err(SigError::BadSignature));
    }

    #[test]
    fn tamper_native_ref_after_signing_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut env = fixed_envelope();
        env.origin = Some(sign_origin(&env, &id));
        assert_eq!(verify_origin(&env), Ok(()));

        env.sender.native_ref.push('X');
        assert_eq!(verify_origin(&env), Err(SigError::BadSignature));
    }

    #[test]
    fn tamper_id_after_signing_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut env = fixed_envelope();
        env.origin = Some(sign_origin(&env, &id));
        assert_eq!(verify_origin(&env), Ok(()));

        env.id = Uuid::parse_str("0189f1e4-2222-7000-8000-000000000002").unwrap();
        assert_eq!(verify_origin(&env), Err(SigError::BadSignature));
    }

    #[test]
    fn tamper_source_endpoint_after_signing_fails_verification() {
        // Review round 1: source.endpoint is now signed (display-spoof
        // class) -- a relay redirecting an envelope to a different endpoint
        // under the same protocol must break the origin signature.
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut env = fixed_envelope();
        env.origin = Some(sign_origin(&env, &id));
        assert_eq!(verify_origin(&env), Ok(()));

        env.source.endpoint.push_str("-spoofed");
        assert_eq!(verify_origin(&env), Err(SigError::BadSignature));
    }

    #[test]
    fn tamper_attachment_filename_after_signing_fails_verification() {
        // Review round 1: attachment filename/mime/size are now signed
        // alongside the sha256, so a relay can no longer rewrite a
        // filename (e.g. disguise an executable as a PDF) while leaving
        // the origin signature valid.
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut env = fixed_envelope();
        env.attachments.push(AttachmentMeta {
            filename: "invoice.pdf".into(),
            mime: "application/pdf".into(),
            size: 4096,
            sha256: "cafe".into(),
        });
        env.origin = Some(sign_origin(&env, &id));
        assert_eq!(verify_origin(&env), Ok(()));

        env.attachments[0].filename = "invoice.exe".into();
        assert_eq!(verify_origin(&env), Err(SigError::BadSignature));
    }

    #[test]
    fn tamper_attestation_timestamp_fails_chain_verification() {
        let dir = tempfile::tempdir().unwrap();
        let origin_id = identity(dir.path(), "origin");
        let hop1 = identity(dir.path(), "hop1");
        let mut env = fixed_envelope();
        env.origin = Some(sign_origin(&env, &origin_id));
        append_attestation(&mut env, &hop1, Utc::now()).unwrap();
        assert_eq!(verify_chain(&env), Ok(()));

        env.attestations[0].ts += Duration::seconds(1);
        assert_eq!(verify_chain(&env), Err(SigError::BadSignature));
    }

    #[test]
    fn tamper_signature_byte_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut env = fixed_envelope();
        env.origin = Some(sign_origin(&env, &id));
        assert_eq!(verify_origin(&env), Ok(()));

        env.origin.as_mut().unwrap().sig[0] ^= 0xFF;
        assert_eq!(verify_origin(&env), Err(SigError::BadSignature));
    }

    // --- attachment determinism ----------------------------------------

    #[test]
    fn canonical_bytes_with_no_attachments_ends_in_empty_attachment_array() {
        let env = fixed_envelope();
        assert!(env.attachments.is_empty());
        let bytes = canonical_bytes(&env);
        // CBOR empty definite-length array is the single byte 0x80; the
        // canonical tuple's last element (the per-attachment
        // [sha, filename, mime, size] list) must serialize to exactly that
        // when there are no attachments.
        assert_eq!(bytes.last(), Some(&0x80));
    }

    #[test]
    fn canonical_bytes_is_order_independent_for_multiple_attachments() {
        let mut env_a = fixed_envelope();
        env_a.attachments.push(AttachmentMeta {
            filename: "b.bin".into(),
            mime: "application/octet-stream".into(),
            size: 2,
            sha256: "bbbb".into(),
        });
        env_a.attachments.push(AttachmentMeta {
            filename: "a.bin".into(),
            mime: "application/octet-stream".into(),
            size: 1,
            sha256: "aaaa".into(),
        });

        let mut env_b = fixed_envelope();
        env_b.attachments.push(AttachmentMeta {
            filename: "a.bin".into(),
            mime: "application/octet-stream".into(),
            size: 1,
            sha256: "aaaa".into(),
        });
        env_b.attachments.push(AttachmentMeta {
            filename: "b.bin".into(),
            mime: "application/octet-stream".into(),
            size: 2,
            sha256: "bbbb".into(),
        });

        // Same attachments, inserted in opposite order: canonical bytes
        // (and therefore any signature over them) must be identical --
        // attachment order is an artifact of upload sequencing, not
        // semantic content, and must not perturb signing.
        assert_eq!(canonical_bytes(&env_a), canonical_bytes(&env_b));

        // And genuinely different from the no-attachment case.
        assert_ne!(canonical_bytes(&env_a), canonical_bytes(&fixed_envelope()));

        // Each attachment's filename/mime/size must stay paired with its
        // OWN sha256 through the sort, not just sorted independently --
        // swapping which metadata goes with which sha must change the
        // canonical bytes (proves the review-round-1 metadata widening is
        // actually wired to the right attachment, not just present
        // somewhere in the tuple).
        let mut env_c = fixed_envelope();
        env_c.attachments.push(AttachmentMeta {
            filename: "a.bin".into(),
            mime: "application/octet-stream".into(),
            size: 1,
            sha256: "bbbb".into(), // mismatched: a.bin's metadata under bbbb's sha
        });
        env_c.attachments.push(AttachmentMeta {
            filename: "b.bin".into(),
            mime: "application/octet-stream".into(),
            size: 2,
            sha256: "aaaa".into(), // mismatched: b.bin's metadata under aaaa's sha
        });
        assert_ne!(canonical_bytes(&env_a), canonical_bytes(&env_c));
    }

    // --- domain-prefix tests --------------------------------------------

    #[test]
    fn origin_signature_without_domain_prefix_is_rejected() {
        // A signature that is otherwise entirely genuine -- right key,
        // right canonical bytes -- but computed WITHOUT the
        // domains::ENVELOPE_V1 prefix must not verify. Proves the origin
        // domain separation is load-bearing.
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut env = fixed_envelope();
        let raw_sig = id.sign(&canonical_bytes(&env)); // no domain prefix
        env.origin = Some(OriginSig {
            node_id: id.node_id(),
            sig: raw_sig,
        });
        assert_eq!(verify_origin(&env), Err(SigError::BadSignature));
    }

    #[test]
    fn attestation_signature_without_domain_prefix_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let origin_id = identity(dir.path(), "origin");
        let hop1 = identity(dir.path(), "hop1");
        let mut env = fixed_envelope();
        env.origin = Some(sign_origin(&env, &origin_id));

        let digest = digest_canonical(&env);
        let prev_sig = env.origin.as_ref().unwrap().sig.clone();
        let now = Utc::now();
        // Sign digest || prev_sig || ts directly, skipping domains::ATTEST_V1.
        let mut raw_msg = Vec::new();
        raw_msg.extend_from_slice(&digest);
        raw_msg.extend_from_slice(&prev_sig);
        raw_msg.extend_from_slice(now.to_rfc3339().as_bytes());
        let raw_sig = hop1.sign(&raw_msg);
        env.attestations.push(Attestation {
            node_id: hop1.node_id(),
            ts: now,
            sig: raw_sig,
        });

        assert_eq!(verify_chain(&env), Err(SigError::BadSignature));
    }

    #[test]
    fn envelope_domain_signature_does_not_verify_under_the_noise_domain() {
        // A signature genuinely produced under domains::ENVELOPE_V1 must
        // not verify against the same payload bytes reinterpreted under
        // domains::NOISE_STATIC_V1 -- exactly the cross-protocol confusion
        // class fed/domains.rs exists to close.
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let env = fixed_envelope();
        let canonical = canonical_bytes(&env);
        let sig = id.sign(&domain_separated(domains::ENVELOPE_V1, &[&canonical]));

        let msg_under_noise_domain = domain_separated(domains::NOISE_STATIC_V1, &[&canonical]);
        assert!(!node_identity::verify(
            &id.node_id(),
            &msg_under_noise_domain,
            &sig
        ));
    }
}
