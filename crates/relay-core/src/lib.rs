use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

mod transport;
pub use transport::{Bandwidth, Latency, TransportCharacteristics, TransportClass, TransportPolicy};

pub const ENVELOPE_VERSION: u8 = 1;

/// Priority classes (spec §39), highest urgency first. Index in this array
/// IS the numeric rank stored in `deliveries.priority` (0..4) — `emergency`
/// schedules ahead of everything else, `background` behind everything.
pub const PRIORITY_CLASSES: [&str; 5] = ["emergency", "high", "normal", "bulk", "background"];

fn default_priority() -> String {
    PRIORITY_CLASSES[2].to_string()
}

/// Maps a priority class name to its scheduling rank (0..4, lower = more
/// urgent). Any name not in `PRIORITY_CLASSES` — including a sender-supplied
/// value we've never heard of — falls back to `normal`'s rank (2) rather
/// than erroring: an unrecognized priority must not be treated as either the
/// most or least urgent traffic by default.
pub fn priority_rank(priority: &str) -> u8 {
    PRIORITY_CLASSES
        .iter()
        .position(|&class| class == priority)
        .map_or(2, |i| i as u8)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub protocol: String,
    pub endpoint: String,
}

impl FromStr for Endpoint {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (protocol, endpoint) = s
            .split_once(':')
            .ok_or_else(|| format!("endpoint '{s}' must be 'protocol:endpoint'"))?;
        if protocol.is_empty() || endpoint.is_empty() {
            return Err(format!("endpoint '{s}' must be 'protocol:endpoint'"));
        }
        Ok(Endpoint { protocol: protocol.into(), endpoint: endpoint.into() })
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.protocol, self.endpoint)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sender {
    pub native_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub filename: String,
    pub mime: String,
    pub size: u64,
    pub sha256: String,
}

/// Federation origin signature (design §2, cycle F): the origin gateway's
/// Ed25519 signature over the envelope's canonical bytes
/// (`fed::sign::canonical_bytes`), proving gateway provenance (§30).
/// v0.3 signs at the origin gateway only; user-key origin signatures are
/// v0.4. `sig` is raw signature bytes, so it's a CBOR byte string
/// (`serde_bytes`) rather than an array of small-uint items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginSig {
    pub node_id: String,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// One link in the attestation chain (design §2, §33): each forwarding
/// gateway appends one of these, signing over the canonical-bytes digest
/// chained with the previous signature and its own timestamp
/// (`fed::sign::append_attestation`), so a verifier can walk the chain and
/// detect any reordering or tampering of hops, and any dropped hop that
/// isn't the last one (removing an interior link breaks the `prev_sig`
/// chain for every link after it). Caveat: dropping the TRAILING
/// attestation is undetectable by construction -- the chain proves prefix
/// integrity (nothing between origin and the last surviving link was
/// altered), not completeness (that no hop signed after the last one
/// present). A receiver that needs completeness has to enforce it
/// out-of-band (e.g. an expected minimum hop count), not via this chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub node_id: String,
    pub ts: DateTime<Utc>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

fn is_zero_hops(hops: &u32) -> bool {
    *hops == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u8,
    pub id: Uuid,
    pub source: Endpoint,
    pub sender: Sender,
    pub kind: String, // free-form: unknown types must not break routing (spec §14)
    pub body: String,
    pub created_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub reply_to: Option<Uuid>,
    // hop fields are carried but only meaningful once federation exists
    pub hop_count: u8,
    pub hop_limit: u8,
    #[serde(default)]
    pub attachments: Vec<AttachmentMeta>,
    // additive (spec §39): old envelopes stored before this field existed
    // deserialize as "normal", the same fallback `priority_rank` uses for
    // any other unrecognized class name.
    #[serde(default = "default_priority")]
    pub priority: String,
    // additive (design §2, cycle F): kept last, and each individually
    // skipped when empty/absent/zero, so a pre-federation envelope's
    // serialized bytes are byte-for-byte unchanged — both relay-ipc golden
    // frames stay locked (asserted there) and Python plugins never see
    // these fields.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub origin: Option<OriginSig>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub attestations: Vec<Attestation>,
    #[serde(skip_serializing_if = "is_zero_hops", default)]
    pub hops: u32,
}

impl Envelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: Endpoint,
        sender: Sender,
        kind: String,
        body: String,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        hop_limit: u8,
    ) -> Self {
        Envelope {
            version: ENVELOPE_VERSION,
            id: Uuid::now_v7(),
            source,
            sender,
            kind,
            body,
            created_at,
            received_at: Utc::now(),
            expires_at,
            reply_to: None,
            hop_count: 0,
            hop_limit,
            attachments: Vec::new(),
            priority: default_priority(),
            origin: None,
            attestations: Vec::new(),
            hops: 0,
        }
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Capabilities {
    pub text: bool,
    pub direct_messages: bool,
    pub groups: bool,
    pub attachments: bool,
    pub location: bool,
    pub reactions: bool,
    pub receipts: bool,
    pub presence: bool,
    pub max_payload: Option<u64>,
}

impl Default for Capabilities {
    fn default() -> Self {
        Capabilities {
            text: true,
            direct_messages: false,
            groups: false,
            attachments: false,
            location: false,
            reactions: false,
            receipts: false,
            presence: false,
            max_payload: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn endpoint_parses_on_first_colon() {
        let e: Endpoint = "signal:group:pasadena".parse().unwrap();
        assert_eq!(e.protocol, "signal");
        assert_eq!(e.endpoint, "group:pasadena");
        assert_eq!(e.to_string(), "signal:group:pasadena");
        assert!("nocolon".parse::<Endpoint>().is_err());
    }

    #[test]
    fn envelope_expiry() {
        let now = Utc::now();
        let mut env = Envelope::new(
            Endpoint { protocol: "mock".into(), endpoint: "chan".into() },
            Sender { native_ref: "!abcd".into() },
            "text".into(), "hi".into(), now, now + Duration::hours(24), 8,
        );
        assert!(!env.is_expired(now));
        assert!(env.is_expired(now + Duration::hours(25)));
        env.expires_at = now - Duration::seconds(1);
        assert!(env.is_expired(now));
    }

    #[test]
    fn priority_rank_maps_every_class_in_order() {
        assert_eq!(priority_rank("emergency"), 0);
        assert_eq!(priority_rank("high"), 1);
        assert_eq!(priority_rank("normal"), 2);
        assert_eq!(priority_rank("bulk"), 3);
        assert_eq!(priority_rank("background"), 4);
    }

    #[test]
    fn priority_rank_unknown_falls_back_to_normal() {
        assert_eq!(priority_rank("urgent"), 2);
        assert_eq!(priority_rank(""), 2);
        assert_eq!(priority_rank("EMERGENCY"), 2, "class names are case-sensitive, not fuzzy-matched");
    }

    #[test]
    fn envelope_new_defaults_priority_to_normal() {
        let now = Utc::now();
        let env = Envelope::new(
            Endpoint { protocol: "mock".into(), endpoint: "chan".into() },
            Sender { native_ref: "!abcd".into() },
            "text".into(), "hi".into(), now, now + Duration::hours(24), 8,
        );
        assert_eq!(env.priority, "normal");
    }

    #[test]
    fn envelope_priority_serde_roundtrip_and_old_json_defaults_normal() {
        let now = Utc::now();
        let mut env = Envelope::new(
            Endpoint { protocol: "mock".into(), endpoint: "chan".into() },
            Sender { native_ref: "!abcd".into() },
            "text".into(), "hi".into(), now, now + Duration::hours(24), 8,
        );
        env.priority = "emergency".into();
        let json = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.priority, "emergency");

        // Old-format JSON, captured before priority existed, must still
        // deserialize (forward compatibility with rows already in
        // storage.rs's sqlite blob column).
        let mut old: serde_json::Value = serde_json::to_string(&env)
            .map(|s| serde_json::from_str(&s).unwrap())
            .unwrap();
        old.as_object_mut().unwrap().remove("priority");
        let old_env: Envelope = serde_json::from_value(old).unwrap();
        assert_eq!(old_env.priority, "normal");
    }

    #[test]
    fn capabilities_default_is_text_only() {
        let c = Capabilities::default();
        assert!(c.text);
        assert!(!c.attachments);
        assert_eq!(c.max_payload, None);
    }

    #[test]
    fn envelope_attachments_serde_roundtrip_and_old_json_defaults_empty() {
        let now = Utc::now();
        let mut env = Envelope::new(
            Endpoint { protocol: "mock".into(), endpoint: "chan".into() },
            Sender { native_ref: "!abcd".into() },
            "text".into(), "hi".into(), now, now + Duration::hours(24), 8,
        );
        assert!(env.attachments.is_empty());
        env.attachments.push(AttachmentMeta {
            filename: "a.bin".into(),
            mime: "application/octet-stream".into(),
            size: 3,
            sha256: "abc123".into(),
        });

        let json = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.attachments.len(), 1);
        assert_eq!(back.attachments[0].filename, "a.bin");
        assert_eq!(back.attachments[0].mime, "application/octet-stream");
        assert_eq!(back.attachments[0].size, 3);
        assert_eq!(back.attachments[0].sha256, "abc123");

        // Old-format JSON, captured before attachments existed, must still
        // deserialize (forward compatibility with rows already in storage.rs's
        // sqlite blob column).
        let mut old: serde_json::Value = serde_json::to_string(&env)
            .map(|s| serde_json::from_str(&s).unwrap())
            .unwrap();
        old.as_object_mut().unwrap().remove("attachments");
        let old_env: Envelope = serde_json::from_value(old).unwrap();
        assert!(old_env.attachments.is_empty());
    }

    #[test]
    fn envelope_federation_fields_are_absent_when_default() {
        let now = Utc::now();
        let env = Envelope::new(
            Endpoint { protocol: "mock".into(), endpoint: "chan".into() },
            Sender { native_ref: "!abcd".into() },
            "text".into(), "hi".into(), now, now + Duration::hours(24), 8,
        );
        assert!(env.origin.is_none());
        assert!(env.attestations.is_empty());
        assert_eq!(env.hops, 0);

        // Wire-shape rule (design §2): a freshly-constructed envelope has no
        // federation fields yet, so none of the three new keys should
        // appear in its serialized form at all -- this is what keeps the
        // relay-ipc golden frames byte-identical (asserted there).
        let json: serde_json::Value = serde_json::to_value(&env).unwrap();
        let obj = json.as_object().unwrap();
        assert!(!obj.contains_key("origin"));
        assert!(!obj.contains_key("attestations"));
        assert!(!obj.contains_key("hops"));
    }

    #[test]
    fn envelope_federation_fields_roundtrip_when_present_and_old_json_defaults_absent() {
        let now = Utc::now();
        let mut env = Envelope::new(
            Endpoint { protocol: "mock".into(), endpoint: "chan".into() },
            Sender { native_ref: "!abcd".into() },
            "text".into(), "hi".into(), now, now + Duration::hours(24), 8,
        );
        env.origin = Some(OriginSig { node_id: "rf:aa".into(), sig: vec![1, 2, 3] });
        env.attestations.push(Attestation { node_id: "rf:bb".into(), ts: now, sig: vec![4, 5] });
        env.hops = 2;

        let json = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.origin, env.origin);
        assert_eq!(back.attestations, env.attestations);
        assert_eq!(back.hops, 2);

        // Old-format JSON (captured before these fields existed) must still
        // deserialize, falling back to the same defaults a fresh envelope
        // gets (forward compatibility, same precedent as attachments/priority
        // above).
        let mut old: serde_json::Value = serde_json::to_string(&env)
            .map(|s| serde_json::from_str(&s).unwrap())
            .unwrap();
        let obj = old.as_object_mut().unwrap();
        obj.remove("origin");
        obj.remove("attestations");
        obj.remove("hops");
        let old_env: Envelope = serde_json::from_value(old).unwrap();
        assert!(old_env.origin.is_none());
        assert!(old_env.attestations.is_empty());
        assert_eq!(old_env.hops, 0);
    }
}
