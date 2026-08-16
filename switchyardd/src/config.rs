use relay_core::Endpoint;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    #[serde(default)]
    pub plugins: BTreeMap<String, PluginConfig>,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub policies: Vec<Policy>,
    #[serde(default = "default_ttl")]
    pub ttl_default_secs: u64,
    #[serde(default = "default_ttl")]
    pub dedup_ttl_secs: u64,
    #[serde(default = "default_hop_limit")]
    pub hop_limit: u8,
    #[serde(default = "default_max_attachment_bytes")]
    pub max_attachment_bytes: u64,
    #[serde(default)]
    pub public_services: Vec<PublicService>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub transport_budgets: BTreeMap<String, Budget>,
}

fn default_ttl() -> u64 { 86_400 }
fn default_hop_limit() -> u8 { 8 }
fn default_max_attachment_bytes() -> u64 { 8 * 1024 * 1024 }

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub data_dir: PathBuf,
    #[serde(default)]
    pub public: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PublicService {
    pub name: String,
    pub r#type: String, // echoed verbatim by GET /v1/public
    pub ingress: Vec<String>,
    pub egress: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Limits {
    #[serde(default)]
    pub per_sender: PerSender,
    #[serde(default)]
    pub per_route: PerRoute,
    #[serde(default)]
    pub global: GlobalLimits,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PerSender {
    pub messages_per_minute: u32,
    pub bytes_per_hour: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PerRoute {
    pub queue_max: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GlobalLimits {
    pub queue_max: u32,
    pub cas_max_bytes: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Budget {
    pub messages_per_minute: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
    pub command: Option<String>,
    #[serde(default)]
    pub config: serde_yaml::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    pub name: String,
    #[serde(deserialize_with = "endpoints")]
    pub sources: Vec<Endpoint>,
    #[serde(deserialize_with = "endpoints")]
    pub destinations: Vec<Endpoint>,
}

fn endpoints<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Endpoint>, D::Error> {
    let raw: Vec<String> = Vec::deserialize(d)?;
    raw.iter()
        .map(|s| s.parse().map_err(serde::de::Error::custom))
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub name: String,
    #[serde(rename = "match")]
    pub r#match: PolicyMatch,
    pub rules: PolicyRules,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyMatch {
    #[serde(default)]
    pub destination_protocol: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyRules {
    #[serde(default)]
    pub max_payload: Option<usize>,
    #[serde(default)]
    pub drop_kinds: Vec<String>,
    #[serde(default)]
    pub deny: bool,
    /// "allow" or "reject"; absent is allow, same posture as the rest of
    /// this struct's optional fields (see policy::evaluate). Any other
    /// string is rejected by `validate()` at config load time — a typo here
    /// is a security-relevant fail-open (it would silently behave like
    /// "allow" at runtime otherwise), so it must fail loudly instead.
    #[serde(default)]
    pub attachments: Option<String>,
    #[serde(default)]
    pub max_attachment_bytes: Option<u64>,
}

pub fn load(path: &Path) -> Result<Config, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let cfg: Config = serde_yaml::from_str(&raw).map_err(|e| e.to_string())?;
    validate(&cfg)?;
    Ok(cfg)
}

pub fn validate(cfg: &Config) -> Result<(), String> {
    let mut names = BTreeSet::new();
    for r in &cfg.routes {
        if !names.insert(&r.name) {
            return Err(format!("duplicate route name '{}'", r.name));
        }
        for ep in r.sources.iter().chain(&r.destinations) {
            match cfg.plugins.get(&ep.protocol) {
                Some(p) if p.enabled => {}
                Some(_) => {
                    return Err(format!(
                        "route '{}' references disabled plugin '{}'", r.name, ep.protocol))
                }
                None => {
                    return Err(format!(
                        "route '{}' references unknown plugin '{}'", r.name, ep.protocol))
                }
            }
        }
    }
    for p in &cfg.policies {
        if let Some(v) = &p.rules.attachments {
            if v != "allow" && v != "reject" {
                return Err(format!(
                    "policy '{}' has invalid attachments value '{v}' (expected \"allow\" or \"reject\")",
                    p.name
                ));
            }
        }
    }

    // Validate public_services protocols are enabled plugins
    for svc in &cfg.public_services {
        for proto in svc.ingress.iter().chain(&svc.egress) {
            match cfg.plugins.get(proto) {
                Some(p) if p.enabled => {}
                Some(_) => {
                    return Err(format!(
                        "public_services '{}' references disabled plugin '{}'; enable the plugin or remove the entry",
                        svc.name, proto))
                }
                None => {
                    return Err(format!(
                        "public_services '{}' references unknown plugin '{}'; enable the plugin or remove the entry",
                        svc.name, proto))
                }
            }
        }
    }

    // Validate routes coverage when node.public is true
    if cfg.node.public {
        for route in &cfg.routes {
            // Collect all protocols from public_services ingress
            let ingress_protocols: BTreeSet<_> = cfg
                .public_services
                .iter()
                .flat_map(|s| s.ingress.iter().cloned())
                .collect();

            // Collect all protocols from public_services egress
            let egress_protocols: BTreeSet<_> = cfg
                .public_services
                .iter()
                .flat_map(|s| s.egress.iter().cloned())
                .collect();

            // Check that all source protocols are in ingress
            for ep in &route.sources {
                if !ingress_protocols.contains(&ep.protocol) {
                    return Err(format!(
                        "node.public is true but route '{}' has source protocol '{}' not covered by any public_services ingress; add '{}' to a public_services ingress list",
                        route.name, ep.protocol, ep.protocol));
                }
            }

            // Check that all destination protocols are in egress
            for ep in &route.destinations {
                if !egress_protocols.contains(&ep.protocol) {
                    return Err(format!(
                        "node.public is true but route '{}' has destination protocol '{}' not covered by any public_services egress; add '{}' to a public_services egress list",
                        route.name, ep.protocol, ep.protocol));
                }
            }
        }
    }

    // Validate transport_budgets keys are enabled plugins
    for (proto, budget) in &cfg.transport_budgets {
        if budget.messages_per_minute == 0 {
            return Err(format!(
                "transport_budgets '{}' has messages_per_minute 0 which would block all egress; omit the entry instead",
                proto));
        }
        match cfg.plugins.get(proto) {
            Some(p) if p.enabled => {}
            Some(_) => {
                return Err(format!(
                    "transport_budgets entry '{proto}' references a disabled plugin; enable the plugin or remove the entry"))
            }
            None => {
                return Err(format!(
                    "transport_budgets entry '{proto}' references an unknown plugin; enable the plugin or remove the entry"))
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
    command: "relayfabric-mockb"
policies:
  - name: small
    match:
      destination_protocol: [mockb]
    rules:
      max_payload: 200
      drop_kinds: [location]
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#;

    fn parse(s: &str) -> Result<Config, String> {
        let cfg: Config = serde_yaml::from_str(s).map_err(|e| e.to_string())?;
        validate(&cfg)?;
        Ok(cfg)
    }

    #[test]
    fn parses_valid_config() {
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.node.name, "test-node");
        assert_eq!(cfg.routes[0].sources[0].protocol, "mocka");
        assert_eq!(cfg.hop_limit, 8);
        assert_eq!(cfg.ttl_default_secs, 86400);
        assert_eq!(cfg.max_attachment_bytes, 8 * 1024 * 1024);
        assert_eq!(cfg.policies[0].rules.max_payload, Some(200));
        assert!(cfg.plugins["mocka"].command.is_none());
    }

    #[test]
    fn parses_attachment_policy_rules() {
        let yaml = GOOD.replace(
            "      max_payload: 200\n      drop_kinds: [location]",
            "      max_payload: 200\n      drop_kinds: [location]\n      attachments: reject\n      max_attachment_bytes: 1000000",
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.policies[0].rules.attachments.as_deref(), Some("reject"));
        assert_eq!(cfg.policies[0].rules.max_attachment_bytes, Some(1_000_000));
    }

    #[test]
    fn attachment_policy_fields_default_to_none_when_absent() {
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.policies[0].rules.attachments, None);
        assert_eq!(cfg.policies[0].rules.max_attachment_bytes, None);
    }

    /// A typo in `rules.attachments` (e.g. "rejct" instead of "reject") must
    /// fail loudly at config load, not fail open at runtime: `evaluate()`
    /// only ever checks for the literal string "reject", so any other value
    /// silently behaves like "allow" unless caught here.
    #[test]
    fn rejects_invalid_attachments_policy_value() {
        let bad = GOOD.replace(
            "      max_payload: 200\n      drop_kinds: [location]",
            "      max_payload: 200\n      drop_kinds: [location]\n      attachments: rejct",
        );
        let err = parse(&bad).unwrap_err();
        assert!(err.contains("small"), "err should name the policy: {err}");
        assert!(err.contains("rejct"), "err should quote the bad value: {err}");
    }

    #[test]
    fn allow_reject_and_absent_attachments_values_are_all_valid() {
        for value in ["allow", "reject"] {
            let yaml = GOOD.replace(
                "      max_payload: 200\n      drop_kinds: [location]",
                &format!("      max_payload: 200\n      drop_kinds: [location]\n      attachments: {value}"),
            );
            let cfg = parse(&yaml).unwrap_or_else(|e| panic!("'{value}' should be valid: {e}"));
            assert_eq!(cfg.policies[0].rules.attachments.as_deref(), Some(value));
        }
        // absent (GOOD as-is) is also valid, covered by
        // attachment_policy_fields_default_to_none_when_absent above.
        assert!(parse(GOOD).is_ok());
    }

    #[test]
    fn rejects_route_to_unknown_plugin() {
        let bad = GOOD.replace("mockb:chan", "ghost:chan");
        let err = parse(&bad).unwrap_err();
        assert!(err.contains("ghost"), "err was: {err}");
    }

    #[test]
    fn rejects_route_to_disabled_plugin() {
        let bad = GOOD.replace("mockb:\n    enabled: true", "mockb:\n    enabled: false");
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn rejects_duplicate_route_names() {
        let bad = format!("{GOOD}
  - name: general
    sources: [\"mocka:chan\"]
    destinations: [\"mockb:chan\"]
");
        let err = parse(&bad).unwrap_err();
        assert!(err.contains("duplicate"), "err was: {err}");
    }

    #[test]
    fn v0_1_style_config_parses_with_all_defaults() {
        // v0.1-style config has none of the new keys
        let cfg = parse(GOOD).unwrap();
        assert!(!cfg.node.public);
        assert!(cfg.public_services.is_empty());
        assert_eq!(cfg.limits.per_sender.messages_per_minute, 0);
        assert_eq!(cfg.limits.per_sender.bytes_per_hour, 0);
        assert_eq!(cfg.limits.per_route.queue_max, 0);
        assert_eq!(cfg.limits.global.queue_max, 0);
        assert_eq!(cfg.limits.global.cas_max_bytes, 0);
        assert!(cfg.transport_budgets.is_empty());
    }

    #[test]
    fn public_false_with_uncovered_routes_ok() {
        let yaml = r#"
node:
  name: test-node
  public: false
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#;
        let cfg = parse(yaml).unwrap();
        assert!(!cfg.node.public);
        assert_eq!(cfg.routes[0].name, "general");
    }

    #[test]
    fn public_true_with_covered_routes_ok() {
        let yaml = r#"
node:
  name: test-node
  public: true
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
public_services:
  - name: service1
    type: mqtt
    ingress: [mocka]
    egress: [mockb]
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#;
        let cfg = parse(yaml).unwrap();
        assert!(cfg.node.public);
        assert_eq!(cfg.public_services[0].name, "service1");
        assert_eq!(cfg.public_services[0].ingress, vec!["mocka"]);
        assert_eq!(cfg.public_services[0].egress, vec!["mockb"]);
    }

    #[test]
    fn public_true_uncovered_source_protocol_err() {
        let yaml = r#"
node:
  name: test-node
  public: true
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
public_services:
  - name: service1
    type: mqtt
    ingress: []
    egress: [mockb]
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.contains("general"), "error should name route: {err}");
        assert!(err.contains("mocka"), "error should name protocol: {err}");
        assert!(err.contains("ingress"), "error should hint ingress: {err}");
    }

    #[test]
    fn public_true_uncovered_destination_protocol_err() {
        let yaml = r#"
node:
  name: test-node
  public: true
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
public_services:
  - name: service1
    type: mqtt
    ingress: [mocka]
    egress: []
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.contains("general"), "error should name route: {err}");
        assert!(err.contains("mockb"), "error should name protocol: {err}");
        assert!(err.contains("egress"), "error should hint egress: {err}");
    }

    #[test]
    fn unknown_plugin_in_public_services_err() {
        let yaml = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
public_services:
  - name: service1
    type: mqtt
    ingress: [ghost]
    egress: [mocka]
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.contains("service1"), "error should name service: {err}");
        assert!(err.contains("ghost"), "error should name plugin: {err}");
    }

    #[test]
    fn zero_transport_budget_err() {
        let yaml = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
transport_budgets:
  mocka:
    messages_per_minute: 0
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.contains("mocka"), "error should name budget: {err}");
        assert!(err.contains("0"), "error should mention 0: {err}");
        assert!(err.contains("omit"), "error should hint omit: {err}");
    }

    #[test]
    fn unknown_plugin_in_transport_budgets_err() {
        let yaml = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
transport_budgets:
  ghost:
    messages_per_minute: 100
"#;
        let err = parse(yaml).unwrap_err();
        assert!(err.contains("ghost"), "error should name plugin: {err}");
    }

    #[test]
    fn nonzero_transport_budget_ok() {
        let yaml = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
transport_budgets:
  mocka:
    messages_per_minute: 100
"#;
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.transport_budgets["mocka"].messages_per_minute, 100);
    }

    #[test]
    fn limits_all_zero_ok() {
        let yaml = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
limits:
  per_sender:
    messages_per_minute: 0
    bytes_per_hour: 0
  per_route:
    queue_max: 0
  global:
    queue_max: 0
    cas_max_bytes: 0
"#;
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.limits.per_sender.messages_per_minute, 0);
        assert_eq!(cfg.limits.per_sender.bytes_per_hour, 0);
    }

    #[test]
    fn limits_nonzero_ok() {
        let yaml = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
limits:
  per_sender:
    messages_per_minute: 100
    bytes_per_hour: 50000
  per_route:
    queue_max: 1000
  global:
    queue_max: 10000
    cas_max_bytes: 1000000000
"#;
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.limits.per_sender.messages_per_minute, 100);
        assert_eq!(cfg.limits.per_sender.bytes_per_hour, 50000);
        assert_eq!(cfg.limits.per_route.queue_max, 1000);
        assert_eq!(cfg.limits.global.queue_max, 10000);
        assert_eq!(cfg.limits.global.cas_max_bytes, 1000000000);
    }

    #[test]
    fn multiple_public_services_ingress_and_egress_combined() {
        let yaml = r#"
node:
  name: test-node
  public: true
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
  mockc:
    enabled: true
public_services:
  - name: service1
    type: mqtt
    ingress: [mocka]
    egress: [mockb]
  - name: service2
    type: http
    ingress: [mockc]
    egress: [mockc]
routes:
  - name: general
    sources: ["mocka:chan", "mockc:chan"]
    destinations: ["mockb:chan", "mockc:chan"]
"#;
        let cfg = parse(yaml).unwrap();
        assert_eq!(cfg.public_services.len(), 2);
        assert!(cfg.node.public);
    }
}
