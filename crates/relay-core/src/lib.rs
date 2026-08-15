use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

pub const ENVELOPE_VERSION: u8 = 1;

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
    // ponytail: hop fields carried but only meaningful once federation exists
    pub hop_count: u8,
    pub hop_limit: u8,
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
    fn capabilities_default_is_text_only() {
        let c = Capabilities::default();
        assert!(c.text);
        assert!(!c.attachments);
        assert_eq!(c.max_payload, None);
    }
}
