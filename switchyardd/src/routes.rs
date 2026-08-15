use crate::config::RouteConfig;
use relay_core::Endpoint;

/// Deny by default: only explicitly routed (source → destinations) pairs
/// flow, and the ingress endpoint never echoes back to itself (spec §24, §38).
#[allow(dead_code)] // consumed by engine wiring (Task 9); remove allow when used
pub fn route<'a>(
    routes: &'a [RouteConfig],
    source: &Endpoint,
) -> Vec<(&'a str, &'a Endpoint)> {
    let mut out = Vec::new();
    for r in routes {
        if !r.sources.contains(source) {
            continue;
        }
        for dest in &r.destinations {
            if dest != source {
                out.push((r.name.as_str(), dest));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteConfig;
    use relay_core::Endpoint;

    fn ep(s: &str) -> Endpoint { s.parse().unwrap() }

    fn routes() -> Vec<RouteConfig> {
        vec![RouteConfig {
            name: "general".into(),
            sources: vec![ep("mocka:chan"), ep("mockb:chan")],
            destinations: vec![ep("mocka:chan"), ep("mockb:chan")],
        }]
    }

    #[test]
    fn routes_to_other_destinations_not_ingress() {
        let r = routes();
        let out = route(&r, &ep("mocka:chan"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "general");
        assert_eq!(*out[0].1, ep("mockb:chan"));
    }

    #[test]
    fn unrouted_source_yields_nothing() {
        let r = routes();
        assert!(route(&r, &ep("mocka:other")).is_empty());
        assert!(route(&r, &ep("ghost:chan")).is_empty());
    }
}
