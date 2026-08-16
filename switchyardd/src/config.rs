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
}

fn default_ttl() -> u64 { 86_400 }
fn default_hop_limit() -> u8 { 8 }
fn default_max_attachment_bytes() -> u64 { 8 * 1024 * 1024 }

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub data_dir: PathBuf,
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
}
