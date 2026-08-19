//! Live event payloads for the design §4 SSE feed: `Daemon.events`
//! (`tokio::sync::broadcast`, capacity 256) broadcasts these to `GET
//! /v1/events` subscribers (admin.rs) and to `switchyardctl events`.
//! Emission is best-effort and near-zero-cost with zero subscribers --
//! see `Daemon::emit_event` (engine.rs), which every call site below goes
//! through rather than touching `Daemon.events` directly.
//!
//! PRIVACY (design §Security invariants, tested by engine.rs's
//! `sse_privacy_*` tests): no message bodies, no full native refs, no
//! identity-link challenge codes, no resolved secrets in ANY payload, ever.
//! `Ingress::sender_masked` is the only sender-identifying field on any
//! variant, always in the established "protocol:masked_ref" compound form
//! (`identity_links::mask_ref`). `LinkVerified` carries neither ref nor
//! display_name, only the opaque numeric link id -- a UI wanting more than
//! "a link changed" fetches `/v1/identities`.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// One broadcast event. `#[serde(untagged)]` so the JSON `data:` line an SSE
/// subscriber sees is just the variant's own fields (`{"id":...,...}`), not
/// wrapped in a `{"Ingress": {...}}` envelope -- the SSE `event:` field
/// (`event_name()`) is what already carries the type, so the JSON payload
/// itself stays flat.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Event {
    /// A message was accepted (passed dedup/rate-limit, matched at least one
    /// route) and fanned out. `id` is the internal message UUID -- safe to
    /// expose as-is (it names nothing about the sender or content) and
    /// shared with `Delivery::id` below so a UI can correlate the two.
    Ingress {
        id: Uuid,
        protocol: String,
        sender_masked: String,
        routes: Vec<String>,
        ts: DateTime<Utc>,
    },
    /// A delivery attempt reached a terminal state or was scheduled for
    /// retry. `state` is one of `delivered | failed | dead_letter | retry`
    /// (design §4) -- a semantic label, not necessarily the literal
    /// `deliveries.state` column value (e.g. a retry is stored as `pending`
    /// but reported here as `retry`, the more meaningful name for a live
    /// feed) -- PLUS `expired` (Finding 1, whole-branch review): a genuine
    /// terminal `deliveries.state` this daemon writes on TTL expiry
    /// (`TTL_EXPIRED`) that predates design §4's four-state list. There is
    /// no more meaningful synonym to fold it into, so it's emitted as the DB
    /// state verbatim rather than reported as `failed`.
    Delivery {
        id: Uuid,
        route: String,
        state: String,
        ts: DateTime<Utc>,
    },
    /// A plugin connected or disconnected from the plugin socket.
    Plugin {
        name: String,
        up: bool,
        ts: DateTime<Utc>,
    },
    /// An identity-link challenge was confirmed. Deliberately carries
    /// nothing but the opaque link id -- no protocol, no ref (masked or
    /// otherwise), no display_name.
    LinkVerified { link_id: i64, ts: DateTime<Utc> },
    /// `apply_config` finished swapping in a new config (via `PUT
    /// /v1/config` or `POST /v1/config/rollback`, either of which lands
    /// here since both call `apply_config` and emission happens inside it).
    ConfigApplied {
        restart_required: Vec<String>,
        ts: DateTime<Utc>,
    },
    /// A federation connection came up or went down (design §5/§6, cycle
    /// F): `peer` is either the configured peer `name` (an operator-chosen
    /// `[a-z0-9-]` string, already safe) or, for a connection from a node
    /// this daemon has no `peers[]` entry for, a SHORTENED `node_id` form
    /// (`fed::display_peer_key`/`fed::short_node_id`) — the full 64-hex
    /// `rf:` node_id never appears in an SSE payload, matching this
    /// module's "no full identifier in a broadcast payload" posture even
    /// though `node_id` isn't itself a secret (it's already exposed to
    /// admins via config and, in a later cycle, `GET /v1/federation`).
    Federation {
        peer: String,
        up: bool,
        ts: DateTime<Utc>,
    },
    /// RFDP discovery (design §2/§6, cycle G): a peer advertisement was
    /// verified and (newer-expires-wins) upserted (`fed::conn::
    /// receive_advert`). PRIVACY: `name` is the SANITIZED display value
    /// (`fed::conn::sanitize_advert_name`) -- NEVER the raw, peer-
    /// controlled string, even though the advert itself is signed (a
    /// signature proves who sent it, not that it's safe to print). Nothing
    /// else from the advert (services/protocols/security/expires) is
    /// carried here -- a subscriber wanting the full document reads Task
    /// 3's `GET /v1/discovery`, which is public-by-design (the advert was
    /// built to be shared); this event is just a "something changed" ping.
    Advert {
        node_id: String,
        name: String,
        ts: DateTime<Utc>,
    },
}

impl Event {
    /// The SSE `event:` field (design §4's exact wire names) -- never the
    /// Rust variant identifier, which is PascalCase.
    pub fn event_name(&self) -> &'static str {
        match self {
            Event::Ingress { .. } => "ingress",
            Event::Delivery { .. } => "delivery",
            Event::Plugin { .. } => "plugin",
            Event::LinkVerified { .. } => "link_verified",
            Event::ConfigApplied { .. } => "config_applied",
            Event::Federation { .. } => "federation",
            Event::Advert { .. } => "advert",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn event_name_matches_design_4_wire_names_not_the_rust_variant_identifier() {
        assert_eq!(
            Event::Ingress {
                id: Uuid::now_v7(),
                protocol: "mocka".into(),
                sender_masked: "mocka:****".into(),
                routes: vec![],
                ts: ts(),
            }
            .event_name(),
            "ingress"
        );
        assert_eq!(
            Event::Delivery {
                id: Uuid::now_v7(),
                route: "general".into(),
                state: "delivered".into(),
                ts: ts()
            }
            .event_name(),
            "delivery"
        );
        assert_eq!(
            Event::Plugin {
                name: "mocka".into(),
                up: true,
                ts: ts()
            }
            .event_name(),
            "plugin"
        );
        assert_eq!(
            Event::LinkVerified {
                link_id: 1,
                ts: ts()
            }
            .event_name(),
            "link_verified"
        );
        assert_eq!(
            Event::ConfigApplied {
                restart_required: vec![],
                ts: ts()
            }
            .event_name(),
            "config_applied"
        );
        assert_eq!(
            Event::Federation {
                peer: "phoenix".into(),
                up: true,
                ts: ts()
            }
            .event_name(),
            "federation"
        );
        assert_eq!(
            Event::Advert {
                node_id: "rf:ab".into(),
                name: "phoenix".into(),
                ts: ts()
            }
            .event_name(),
            "advert"
        );
    }

    #[test]
    fn advert_json_has_no_variant_wrapper_and_carries_node_id_and_sanitized_name() {
        let json = serde_json::to_value(Event::Advert {
            node_id: "rf:ab12".into(),
            name: "clean-name".into(),
            ts: ts(),
        })
        .unwrap();
        assert_eq!(json["node_id"], "rf:ab12");
        assert_eq!(json["name"], "clean-name");
        assert!(json.get("Advert").is_none());
        let keys: std::collections::BTreeSet<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from(["node_id", "name", "ts"]),
            "Advert must carry nothing beyond node_id/name/ts -- no services/protocols/security"
        );
    }

    #[test]
    fn federation_json_has_no_variant_wrapper_and_carries_peer_and_up() {
        let json = serde_json::to_value(Event::Federation {
            peer: "phoenix".into(),
            up: true,
            ts: ts(),
        })
        .unwrap();
        assert_eq!(json["peer"], "phoenix");
        assert_eq!(json["up"], true);
        assert!(json.get("Federation").is_none());
    }

    /// The JSON `data:` payload must be the variant's own fields directly --
    /// no `{"LinkVerified": {...}}` wrapper -- since the SSE `event:` field
    /// already names the type.
    #[test]
    fn json_serialization_is_untagged_flat_fields_no_variant_name_wrapper() {
        let json = serde_json::to_value(Event::LinkVerified {
            link_id: 42,
            ts: ts(),
        })
        .unwrap();
        assert_eq!(json["link_id"], 42);
        assert!(json.get("LinkVerified").is_none());
        let keys: std::collections::BTreeSet<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from(["link_id", "ts"]),
            "LinkVerified must carry nothing beyond link_id/ts -- no ref, no display_name"
        );
    }

    #[test]
    fn ingress_json_has_no_variant_wrapper_and_carries_the_expected_fields() {
        let json = serde_json::to_value(Event::Ingress {
            id: Uuid::now_v7(),
            protocol: "mocka".into(),
            sender_masked: "mocka:si****1234".into(),
            routes: vec!["general".into()],
            ts: ts(),
        })
        .unwrap();
        assert_eq!(json["protocol"], "mocka");
        assert_eq!(json["sender_masked"], "mocka:si****1234");
        assert_eq!(json["routes"], serde_json::json!(["general"]));
        assert!(json.get("Ingress").is_none());
    }
}
