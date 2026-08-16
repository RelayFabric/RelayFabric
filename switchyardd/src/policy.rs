use crate::config::Policy;
use relay_core::{Endpoint, Envelope};

#[derive(Debug)]
pub enum Decision<'a> {
    Allow {
        max_payload: Option<usize>,
        /// False when any matching policy's `rules.attachments` is
        /// `"reject"`. Anything else (absent, or any string other than
        /// "reject") is allow-by-default, same posture as the rest of this
        /// module: an unset or unrecognized value never blocks delivery.
        attachments_allowed: bool,
        /// Minimum `max_attachment_bytes` across matching policies, same
        /// tightest-wins combination rule as `max_payload`.
        max_attachment_bytes: Option<u64>,
    },
    Deny {
        policy: &'a str,
    },
}

pub fn evaluate<'a>(
    policies: &'a [Policy],
    env: &Envelope,
    dest: &Endpoint,
) -> Decision<'a> {
    let mut max_payload: Option<usize> = None;
    let mut attachments_allowed = true;
    let mut max_attachment_bytes: Option<u64> = None;
    for p in policies {
        if !p.r#match.destination_protocol.is_empty()
            && !p.r#match.destination_protocol.contains(&dest.protocol)
        {
            continue;
        }
        if p.rules.deny || p.rules.drop_kinds.contains(&env.kind) {
            return Decision::Deny { policy: &p.name };
        }
        if let Some(mp) = p.rules.max_payload {
            max_payload = Some(max_payload.map_or(mp, |cur| cur.min(mp)));
        }
        if p.rules.attachments.as_deref() == Some("reject") {
            attachments_allowed = false;
        }
        if let Some(mab) = p.rules.max_attachment_bytes {
            max_attachment_bytes = Some(max_attachment_bytes.map_or(mab, |cur| cur.min(mab)));
        }
    }
    Decision::Allow { max_payload, attachments_allowed, max_attachment_bytes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Policy, PolicyMatch, PolicyRules};
    use chrono::Utc;
    use relay_core::{Endpoint, Envelope, Sender};

    fn env(kind: &str) -> Envelope {
        let now = Utc::now();
        Envelope::new(
            "mocka:chan".parse().unwrap(),
            Sender { native_ref: "!a".into() },
            kind.into(), "hello".into(), now, now + chrono::Duration::hours(1), 8,
        )
    }

    fn policy(protocols: &[&str], rules: PolicyRules) -> Policy {
        Policy {
            name: "p".into(),
            r#match: PolicyMatch {
                destination_protocol: protocols.iter().map(|s| s.to_string()).collect(),
            },
            rules,
        }
    }

    fn dest() -> Endpoint { "mockb:chan".parse().unwrap() }

    #[test]
    fn no_policies_allows_unlimited() {
        match evaluate(&[], &env("text"), &dest()) {
            Decision::Allow { max_payload: None, attachments_allowed: true, max_attachment_bytes: None } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn nonmatching_protocol_is_ignored() {
        let p = policy(&["meshtastic"], PolicyRules { deny: true, ..Default::default() });
        assert!(matches!(evaluate(&[p], &env("text"), &dest()), Decision::Allow { .. }));
    }

    #[test]
    fn deny_and_drop_kinds_deny() {
        let deny = policy(&["mockb"], PolicyRules { deny: true, ..Default::default() });
        assert!(matches!(evaluate(&[deny], &env("text"), &dest()), Decision::Deny { .. }));
        let strip = policy(&["mockb"], PolicyRules {
            drop_kinds: vec!["location".into()], ..Default::default()
        });
        assert!(matches!(evaluate(std::slice::from_ref(&strip), &env("location"), &dest()), Decision::Deny { .. }));
        assert!(matches!(evaluate(&[strip], &env("text"), &dest()), Decision::Allow { .. }));
    }

    #[test]
    fn max_payload_takes_the_minimum() {
        let a = policy(&["mockb"], PolicyRules { max_payload: Some(500), ..Default::default() });
        let b = policy(&["mockb"], PolicyRules { max_payload: Some(200), ..Default::default() });
        match evaluate(&[a, b], &env("text"), &dest()) {
            Decision::Allow { max_payload: Some(200), .. } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn no_attachment_rules_allows_attachments_unlimited() {
        let p = policy(&["mockb"], PolicyRules { max_payload: Some(200), ..Default::default() });
        match evaluate(&[p], &env("text"), &dest()) {
            Decision::Allow { attachments_allowed: true, max_attachment_bytes: None, .. } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn attachments_reject_blocks_attachments_but_still_allows_the_message() {
        let p = policy(&["mockb"], PolicyRules {
            attachments: Some("reject".into()), ..Default::default()
        });
        match evaluate(&[p], &env("text"), &dest()) {
            Decision::Allow { attachments_allowed: false, .. } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn attachments_value_other_than_reject_is_allow_by_default() {
        let p = policy(&["mockb"], PolicyRules {
            attachments: Some("allow".into()), ..Default::default()
        });
        assert!(matches!(
            evaluate(&[p], &env("text"), &dest()),
            Decision::Allow { attachments_allowed: true, .. }
        ));
    }

    #[test]
    fn nonmatching_protocol_does_not_reject_attachments() {
        let p = policy(&["meshtastic"], PolicyRules {
            attachments: Some("reject".into()), ..Default::default()
        });
        assert!(matches!(
            evaluate(&[p], &env("text"), &dest()),
            Decision::Allow { attachments_allowed: true, .. }
        ));
    }

    #[test]
    fn max_attachment_bytes_takes_the_minimum_across_matching_policies() {
        let a = policy(&["mockb"], PolicyRules {
            max_attachment_bytes: Some(5_000_000), ..Default::default()
        });
        let b = policy(&["mockb"], PolicyRules {
            max_attachment_bytes: Some(1_000_000), ..Default::default()
        });
        match evaluate(&[a, b], &env("text"), &dest()) {
            Decision::Allow { max_attachment_bytes: Some(1_000_000), .. } => {}
            other => panic!("{other:?}"),
        }
    }
}
