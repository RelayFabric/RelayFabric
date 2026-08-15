use crate::config::Policy;
use relay_core::{Endpoint, Envelope};

#[derive(Debug)]
#[allow(dead_code)] // consumed by engine wiring (Task 9); remove allow when used
pub enum Decision<'a> {
    Allow { max_payload: Option<usize> },
    Deny { policy: &'a str },
}

#[allow(dead_code)] // consumed by engine wiring (Task 9); remove allow when used
pub fn evaluate<'a>(
    policies: &'a [Policy],
    env: &Envelope,
    dest: &Endpoint,
) -> Decision<'a> {
    let mut max_payload: Option<usize> = None;
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
    }
    Decision::Allow { max_payload }
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
            Decision::Allow { max_payload: None } => {}
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
            Decision::Allow { max_payload: Some(200) } => {}
            other => panic!("{other:?}"),
        }
    }
}
