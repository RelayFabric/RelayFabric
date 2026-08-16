use crate::secrets;
use relay_core::Endpoint;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    #[serde(default)]
    pub plugins: BTreeMap<String, PluginConfig>,
    /// Pre-resolution snapshot of each plugin's `config:` block, taken
    /// before `resolve_secrets` overwrites `plugins[_].config` with
    /// resolved secret values (design §2's redaction invariant). Any
    /// admin/display code that surfaces plugin config MUST read from here,
    /// never from `plugins[_].config` -- see `admin.rs`'s redaction tests.
    /// `plugins.rs::supervise` is the one consumer that legitimately reads
    /// the resolved `plugins[_].config` (it forwards it to the plugin
    /// process over the `RELAYFABRIC_PLUGIN_CONFIG` env var).
    #[serde(skip)]
    pub raw_plugin_configs: BTreeMap<String, serde_yaml::Value>,
    /// Verbatim text of the config file, captured by `load`/`load_from_str`
    /// BEFORE parsing/secret resolution touch anything (design §1/§2).
    /// Skipped by serde (empty by default, e.g. for every hand-built
    /// `Config` literal the test suite constructs directly rather than
    /// through `load_from_str`) and never mutated afterward except by
    /// `Daemon::apply_config`, which stores the incoming request's raw text
    /// here on swap. Admin `GET /v1/config` (Task 2) serves this back
    /// byte-for-byte -- secrets stay in their unresolved `${...}` form and
    /// resolution never touches this field at all, so byte-fidelity and
    /// zero secret exposure both fall out of "just don't re-serialize
    /// anything".
    #[serde(skip)]
    pub raw_yaml: String,
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
    /// Design §3/§4, cycle F: absent entirely (every pre-cycle-F config,
    /// including the v0.2 example config) means federation is off, exactly
    /// like today -- no Noise listener, no fed egress/ingress, no trust
    /// seeding. `apply_config` (engine.rs) treats ANY change to this block
    /// as `"daemon"` restart-required this cycle: live fed reconfig
    /// (rebinding the listener, tearing down/rekeying live peer
    /// connections against a changed `peers`/`accept_from`/etc without a
    /// restart) is deferred to a later cycle, so a config write here only
    /// takes effect on next daemon start, unlike routes/policies/limits/
    /// render/identity_mode.
    #[serde(default)]
    pub federation: Option<FederationConfig>,
}

fn default_ttl() -> u64 { 86_400 }
fn default_hop_limit() -> u8 { 8 }
fn default_max_attachment_bytes() -> u64 { 8 * 1024 * 1024 }

/// Reserved route name for identity-link challenge/confirmation deliveries
/// (design §Lifecycle, §IPC): a user route may never be named this
/// (`validate()` rejects it below), and `engine::process_due` dispatches
/// deliveries queued under it via `SendDirect` instead of the normal
/// `Send`/alias/render path.
pub const IDENTITY_ROUTE: &str = "@identity";

/// `PartialEq` powers `Daemon::apply_config`'s restart-required diff
/// (design §1): any change to `node.*` is restart-only (the plugin/admin
/// socket paths are derived from `data_dir` and bound once at startup).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

/// `PartialEq` powers `Daemon::apply_config`'s restart-required diff
/// (design §1): a plugin process is only ever restarted-by-implication
/// (never actually restarted by apply itself -- `supervise` keeps the old
/// one running) when `{enabled, command, config}` changes.
#[derive(Debug, Clone, PartialEq, Deserialize)]
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
    /// Design §Rendering: "pseudonymous" (default, backward compatible with
    /// pre-cycle-C configs that have no such key) renders the HMAC alias as
    /// today; "linked" renders the verified link's `display_name` instead,
    /// when one exists for the envelope's (source protocol, native_ref) —
    /// see `engine::process_due`. `validate()` rejects any other value.
    #[serde(default = "default_identity_mode")]
    pub identity_mode: String,
    /// Design §4: per-route rendering knobs, sized for the WebUI to expose.
    /// Absent entirely (every pre-cycle-D config) defaults to
    /// `RenderConfig::default()` -- `tag: "alias"`, `max_chars: 0` -- which
    /// reproduces today's rendering exactly (`engine::process_due`,
    /// `transform::render`). `validate()` rejects `tag` outside
    /// {alias, none} and `max_chars` in 1..16.
    #[serde(default)]
    pub render: RenderConfig,
}

fn default_identity_mode() -> String { "pseudonymous".to_string() }

#[derive(Debug, Clone, Deserialize)]
pub struct RenderConfig {
    /// "alias" (default): render the sender tag as today -- the HMAC alias,
    /// or in `identity_mode: linked` with a verified link, that link's
    /// `display_name`. "none": suppress the `[tag]\n` prefix ENTIRELY --
    /// the route opted out of tags altogether, so this also suppresses the
    /// linked display_name, not just the pseudonym (see
    /// `engine::process_due`'s render-tag selection).
    #[serde(default = "default_render_tag")]
    pub tag: String,
    /// 0 (default): no route-level truncation. >=16: truncates the
    /// MESSAGE BODY ONLY (fix round 1) to this many Unicode *characters*
    /// (not bytes) -- the sender tag is NEVER counted or shortened by this,
    /// no matter how long it is (a linked `display_name` has no length cap
    /// anywhere; an earlier ruling that truncated the assembled
    /// `"[tag]\nbody"` string let a long tag eat the whole budget and
    /// silently drop the body entirely -- see `transform::truncate_body`).
    /// The transport's `max_payload` byte cap still applies afterward, to
    /// the fully assembled message, as the hard floor (`transform::
    /// render`) -- unlike `max_chars`, it MAY still truncate into the tag
    /// if it's tight enough; that's pre-existing v0.1 behavior, unrelated
    /// to this route-level knob. Values 1..16 are rejected by `validate()`
    /// -- large enough for the truncated body to still carry meaningful
    /// content, not a footgun that reduces it to near-nothing.
    #[serde(default)]
    pub max_chars: u32,
}

impl Default for RenderConfig {
    fn default() -> Self {
        RenderConfig { tag: default_render_tag(), max_chars: 0 }
    }
}

fn default_render_tag() -> String { "alias".to_string() }

/// Federation policy config (design §3/§4, cycle F). `PartialEq`/`Eq` power
/// `Daemon::apply_config`'s restart-required diff (see `Config::federation`'s
/// doc comment): the whole block compares as one unit, so any field change
/// anywhere in here -- including a peer added/removed/edited -- trips the
/// `"daemon"` restart entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FederationConfig {
    /// Optional: absent means outbound-only (no Noise listener bound).
    #[serde(default)]
    pub listen: Option<String>,
    /// "verified" (default) or "trusted" -- minimum trust store level
    /// (`storage::Store::trust_level`) an origin/attestation chain's signer
    /// must have for an inbound envelope to be accepted (design §3).
    #[serde(default = "default_accept_from")]
    pub accept_from: String,
    /// Inbound envelopes at or over this hop count are dead_lettered
    /// `HOP_LIMIT` (design §5).
    #[serde(default = "default_max_hops")]
    pub max_hops: u32,
    /// Inbound TTL is clamped down to this many seconds (design §4).
    #[serde(default = "default_max_ttl_secs")]
    pub max_ttl_secs: u64,
    /// "pseudonymous" (default) or "full" -- outbound source ref handling
    /// (design §4).
    #[serde(default = "default_identity_exposure")]
    pub identity_exposure: String,
    /// Local route names federated peers may inject an ingress envelope
    /// into (design §4). Default empty: no route accepts fed ingress unless
    /// explicitly listed here.
    #[serde(default)]
    pub ingress_routes: Vec<String>,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    /// Extra node_ids seeded to trust level `trusted` at boot, beyond
    /// whatever `peers[].trust` already grants (design §3).
    #[serde(default)]
    pub trusted: Vec<String>,
    /// Node_ids seeded to trust level `blocked` at boot; a blocked peer's
    /// connection is refused at handshake (design §3).
    #[serde(default)]
    pub blocked: Vec<String>,
}

fn default_accept_from() -> String {
    "verified".to_string()
}
fn default_max_hops() -> u32 {
    4
}
fn default_max_ttl_secs() -> u64 {
    86_400
}
fn default_identity_exposure() -> String {
    "pseudonymous".to_string()
}

/// One configured federation peer (design §4 YAML `federation.peers[]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PeerConfig {
    pub name: String,
    /// `"rf:" + 64 hex chars` -- the peer's Ed25519 public key, cycle-A
    /// format (see `node_identity::NodeIdentity::node_id`).
    pub node_id: String,
    pub addr: String,
    /// "verified" (default) or "trusted" -- this peer's trust store level,
    /// seeded at boot (design §3: "peers[] entries with node_id ⇒ at least
    /// verified").
    #[serde(default = "default_peer_trust")]
    pub trust: String,
}

fn default_peer_trust() -> String {
    "verified".to_string()
}

/// Protocol name reserved for federation (design §4/§5): no plugin may
/// claim it, and no route SOURCE may claim it as a source protocol -- a fed
/// envelope is injected into a route's fan-out programmatically (design
/// §5 ingress), never received the way a plugin's inbound traffic is.
/// Route DESTINATIONS are deliberately NOT restricted here: Task 5 teaches
/// `fed:<peer_name>/<remote_route>` as a valid destination endpoint (design
/// §5 egress) -- validating that shape is Task 5's job, not this one's.
pub const FED_PROTOCOL: &str = "fed";

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
    load_from_str(&raw)
}

/// Parses, validates, and resolves secrets for `raw` YAML config text --
/// the same pipeline `load` runs against a file's contents, factored out so
/// callers with text that didn't come from disk (admin `PUT /v1/config` and
/// `POST /v1/config/validate`, Task 3) can run it too. `Config.raw_yaml` is
/// captured from `raw` verbatim, immediately after parsing and BEFORE
/// `resolve_secrets` mutates `plugins[_].config` in place -- so it always
/// holds exactly what the caller supplied, secrets un-resolved.
pub fn load_from_str(raw: &str) -> Result<Config, String> {
    let mut cfg: Config = serde_yaml::from_str(raw).map_err(|e| e.to_string())?;
    cfg.raw_yaml = raw.to_string();
    validate(&cfg)?;
    resolve_secrets(&mut cfg)?;
    warn_if_public_with_no_limits(&cfg);
    warn_if_federation_node_id_overlap(&cfg);
    Ok(cfg)
}

/// Resolves every `${env:NAME}`/`${file:/abs/path}` secret reference
/// (design §2 / SPEC §51, §59) found anywhere inside a plugin's `config:`
/// block, recursing through nested mappings and sequences. The resolved
/// value replaces the reference in-place in `cfg.plugins[_].config` --
/// that's the runtime config `plugins.rs::supervise` forwards to the
/// plugin process over IPC (`RELAYFABRIC_PLUGIN_CONFIG`). The pre-
/// resolution form is snapshotted into `cfg.raw_plugin_configs` first, so
/// display/admin code has an UNRESOLVED copy to read instead (redaction
/// invariant).
///
/// A config with no secret references anywhere (every v0.1-style config)
/// round-trips with zero resolution attempts and zero errors -- `resolve_value`
/// only ever calls `secrets::resolve` for string leaves that
/// `secrets::parse_ref` recognizes.
///
/// All failures are collected (not short-circuited) so `--check-config`
/// can report every failing reference in one pass (SPEC §59).
fn resolve_secrets(cfg: &mut Config) -> Result<(), String> {
    let mut errors = Vec::new();
    let mut raw = BTreeMap::new();
    for (name, plugin) in cfg.plugins.iter_mut() {
        raw.insert(name.clone(), plugin.config.clone());
        plugin.config = resolve_value(&plugin.config, &mut errors);
    }
    cfg.raw_plugin_configs = raw;
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

/// Recursively walks a `serde_yaml::Value`, replacing any string leaf that
/// is entirely a secret reference with its resolved value. Non-reference
/// strings and non-string values pass through unchanged. Resolution
/// failures are appended to `errors` (naming the `${...}` form, never a
/// value -- see `secrets::resolve`) and the original reference string is
/// left in place for that leaf, since the overall load fails regardless
/// once any error is recorded.
fn resolve_value(v: &serde_yaml::Value, errors: &mut Vec<String>) -> serde_yaml::Value {
    match v {
        serde_yaml::Value::String(s) => match secrets::parse_ref(s) {
            Some(r) => match secrets::resolve(&r) {
                Ok(resolved) => serde_yaml::Value::String(resolved),
                Err(e) => {
                    errors.push(e);
                    v.clone()
                }
            },
            None => {
                // Same rationale as `secrets::resolve`'s permission-file
                // warning: this runs inside `config::load`, before `main`
                // sets up `tracing_subscriber` (and never on the
                // `--check-config` path), so it goes straight to stderr.
                if let Some(warning) = secrets::malformed_ref_warning(s) {
                    eprintln!("warning: {warning}");
                }
                v.clone()
            }
        },
        serde_yaml::Value::Sequence(items) => {
            serde_yaml::Value::Sequence(items.iter().map(|i| resolve_value(i, errors)).collect())
        }
        serde_yaml::Value::Mapping(map) => {
            let mut out = serde_yaml::Mapping::new();
            for (k, val) in map {
                out.insert(k.clone(), resolve_value(val, errors));
            }
            serde_yaml::Value::Mapping(out)
        }
        other => other.clone(),
    }
}

/// A public node with no `per_sender`/`global` limits configured is valid
/// (every `limits` field defaults to 0, meaning unlimited — see §112.8) but
/// almost certainly not what the operator intended: printed at load time,
/// not enforced by `validate()`, because unlimited-but-public is a footgun
/// warning, not a config error. Runs before `tracing_subscriber` is
/// initialized (in particular on the `--check-config` path, which never
/// initializes it at all), so this goes straight to stderr rather than
/// through `tracing::warn!`.
fn warn_if_public_with_no_limits(cfg: &Config) {
    let per_sender_unset =
        cfg.limits.per_sender.messages_per_minute == 0 && cfg.limits.per_sender.bytes_per_hour == 0;
    let global_unset =
        cfg.limits.global.queue_max == 0 && cfg.limits.global.cas_max_bytes == 0;
    if cfg.node.public && per_sender_unset && global_unset {
        eprintln!(
            "warning: node.public is true but limits are unset (unlimited); see SPEC §112.8");
    }
}

/// The node_ids that appear in more than one of `federation.peers[]`
/// (their own `node_id` field), `federation.trusted`, and
/// `federation.blocked` — a pure helper so the overlap computation itself
/// is unit-testable without capturing stderr (see
/// `warn_if_federation_node_id_overlap`, its only caller). Overlap is not
/// a config error (`seed_federation_trust`'s peers -> trusted -> blocked
/// application order already resolves it deterministically, blocked
/// always winning), just a likely operator mistake worth flagging —
/// `warn_if_public_with_no_limits` precedent.
fn overlapping_federation_node_ids(fed: &FederationConfig) -> BTreeSet<String> {
    let peers: BTreeSet<&str> = fed.peers.iter().map(|p| p.node_id.as_str()).collect();
    let trusted: BTreeSet<&str> = fed.trusted.iter().map(String::as_str).collect();
    let blocked: BTreeSet<&str> = fed.blocked.iter().map(String::as_str).collect();
    let mut overlap: BTreeSet<&str> = BTreeSet::new();
    overlap.extend(peers.intersection(&trusted));
    overlap.extend(peers.intersection(&blocked));
    overlap.extend(trusted.intersection(&blocked));
    overlap.into_iter().map(String::from).collect()
}

/// Task 3 review carry-over (Important): a node_id listed in more than one
/// of `federation.peers[]`/`trusted`/`blocked` still loads and seeds
/// deterministically (`seed_federation_trust` applies peers -> trusted ->
/// blocked in that fixed order, so `blocked` always wins any overlap), but
/// it's very likely an operator mistake (e.g. a peer accidentally also
/// listed in `blocked`, silently disabling it) — flagged the same way
/// `warn_if_public_with_no_limits` flags its own footgun: a load-time
/// `eprintln!`, not a `validate()` error, run before `tracing_subscriber`
/// is initialized (in particular on the `--check-config` path).
fn warn_if_federation_node_id_overlap(cfg: &Config) {
    let Some(fed) = &cfg.federation else { return };
    let overlap = overlapping_federation_node_ids(fed);
    if !overlap.is_empty() {
        let ids: Vec<&String> = overlap.iter().collect();
        eprintln!(
            "warning: federation node_id(s) appear in more than one of peers/trusted/blocked: {} \
             (blocked always wins on conflict; see seed_federation_trust)",
            ids.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        );
    }
}

pub fn validate(cfg: &Config) -> Result<(), String> {
    if cfg.plugins.contains_key(FED_PROTOCOL) {
        return Err(format!(
            "plugin name '{FED_PROTOCOL}' is reserved for federation (design §4/§5) and cannot be used as a plugin name"
        ));
    }

    let mut names = BTreeSet::new();
    for r in &cfg.routes {
        if r.name == IDENTITY_ROUTE {
            return Err(format!(
                "route name '{IDENTITY_ROUTE}' is reserved for identity-link delivery and cannot be used as a user route name"
            ));
        }
        if !names.insert(&r.name) {
            return Err(format!("duplicate route name '{}'", r.name));
        }
        if r.identity_mode != "pseudonymous" && r.identity_mode != "linked" {
            return Err(format!(
                "route '{}' has invalid identity_mode '{}' (expected \"pseudonymous\" or \"linked\")",
                r.name, r.identity_mode
            ));
        }
        if r.render.tag != "alias" && r.render.tag != "none" {
            return Err(format!(
                "route '{}' has invalid render.tag '{}' (expected \"alias\" or \"none\")",
                r.name, r.render.tag
            ));
        }
        if r.render.max_chars != 0 && r.render.max_chars < 16 {
            return Err(format!(
                "route '{}' has render.max_chars {} which is below the minimum of 16 (0 disables route-level truncation)",
                r.name, r.render.max_chars
            ));
        }
        if r.sources.iter().any(|ep| ep.protocol == FED_PROTOCOL) {
            return Err(format!(
                "route '{}' has a source with protocol '{FED_PROTOCOL}', which is reserved for federation and cannot be a route source (fed envelopes are injected into a route's fan-out directly, design §5 ingress)",
                r.name
            ));
        }
        for ep in r.sources.iter().chain(&r.destinations) {
            if ep.protocol == FED_PROTOCOL {
                // A route SOURCE with protocol "fed" was already rejected
                // above, so reaching here with FED_PROTOCOL means `ep` is a
                // destination -- validated by `validate_fed_destination`
                // below (design §5, Task 5) instead of the plugin-existence
                // check every other protocol goes through, since `fed` is
                // never a `cfg.plugins` entry (it's reserved, not a plugin).
                continue;
            }
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
        for ep in &r.destinations {
            if ep.protocol == FED_PROTOCOL {
                validate_fed_destination(cfg, &r.name, &ep.endpoint)?;
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

    validate_federation(cfg)?;

    Ok(())
}

/// Design §3/§4 validation for the (optional) `federation` block. A no-op
/// when the block is absent -- every pre-cycle-F config, including the
/// v0.2 example config, must keep loading unchanged.
fn validate_federation(cfg: &Config) -> Result<(), String> {
    let Some(fed) = &cfg.federation else {
        return Ok(());
    };

    if fed.accept_from != "verified" && fed.accept_from != "trusted" {
        return Err(format!(
            "federation.accept_from '{}' is invalid (expected \"verified\" or \"trusted\")",
            fed.accept_from
        ));
    }
    if fed.identity_exposure != "pseudonymous" && fed.identity_exposure != "full" {
        return Err(format!(
            "federation.identity_exposure '{}' is invalid (expected \"pseudonymous\" or \"full\")",
            fed.identity_exposure
        ));
    }
    if let Some(listen) = &fed.listen {
        if listen.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "federation.listen '{listen}' is not a valid address (expected host:port)"
            ));
        }
    }

    let route_names: BTreeSet<&String> = cfg.routes.iter().map(|r| &r.name).collect();
    for name in &fed.ingress_routes {
        if !route_names.contains(name) {
            return Err(format!(
                "federation.ingress_routes names unknown route '{name}'"
            ));
        }
    }

    let mut peer_names = BTreeSet::new();
    for p in &fed.peers {
        if !is_valid_peer_name(&p.name) {
            return Err(format!(
                "federation peer name '{}' is invalid (expected 1-32 chars of [a-z0-9-])",
                p.name
            ));
        }
        if !peer_names.insert(&p.name) {
            return Err(format!("duplicate federation peer name '{}'", p.name));
        }
        if !is_valid_rf_node_id(&p.node_id) {
            return Err(format!(
                "federation peer '{}' has invalid node_id '{}' (expected \"rf:\" + 64 hex chars)",
                p.name, p.node_id
            ));
        }
        if p.addr.parse::<std::net::SocketAddr>().is_err() {
            return Err(format!(
                "federation peer '{}' has invalid addr '{}' (expected host:port)",
                p.name, p.addr
            ));
        }
        if p.trust != "verified" && p.trust != "trusted" {
            return Err(format!(
                "federation peer '{}' has invalid trust '{}' (expected \"verified\" or \"trusted\")",
                p.name, p.trust
            ));
        }
    }

    for node_id in fed.trusted.iter().chain(&fed.blocked) {
        if !is_valid_rf_node_id(node_id) {
            return Err(format!(
                "federation node_id '{node_id}' is invalid (expected \"rf:\" + 64 hex chars)"
            ));
        }
    }

    Ok(())
}

/// Validates a `fed:<peer_name>/<remote_route>` route DESTINATION (design
/// §5 egress, Task 5): `endpoint` here is `ep.endpoint` -- the part after
/// the `fed:` protocol, e.g. `"phoenix/regional-chat"`. Rejects entirely
/// when the `federation` block is absent (design §5: "reject entirely when
/// federation block absent" -- there are no peers to name in that case, so
/// any `fed:` destination is unreachable by construction); otherwise
/// requires the `<peer_name>` half to name a configured
/// `federation.peers[]` entry (a `fed:` destination can only ever egress to
/// a peer this daemon actually dials/accepts) and the `<remote_route>` half
/// to be non-empty and DNS-label-ish, matching `is_valid_peer_name`'s
/// `[a-z0-9-]{1,32}` charset -- there's no local `RouteConfig` to check the
/// remote name against (it names a route on the PEER's daemon, a
/// configuration this side has no visibility into), so this is a pure shape
/// check, not an existence check, same posture `is_valid_peer_name` already
/// takes for a peer name.
fn validate_fed_destination(cfg: &Config, route_name: &str, endpoint: &str) -> Result<(), String> {
    let Some(fed) = &cfg.federation else {
        return Err(format!(
            "route '{route_name}' has a fed: destination '{endpoint}' but no federation block is configured"
        ));
    };
    let Some((peer_name, remote_route)) = endpoint.split_once('/') else {
        return Err(format!(
            "route '{route_name}' has an invalid fed: destination '{endpoint}' (expected \"fed:<peer_name>/<remote_route>\")"
        ));
    };
    if !fed.peers.iter().any(|p| p.name == peer_name) {
        return Err(format!(
            "route '{route_name}' has a fed: destination naming unknown peer '{peer_name}'"
        ));
    }
    if !is_valid_peer_name(remote_route) {
        return Err(format!(
            "route '{route_name}' has an invalid fed: destination remote route '{remote_route}' (expected 1-32 chars of [a-z0-9-])"
        ));
    }
    Ok(())
}

/// DNS-label-ish peer name check (design §4: "names unique + DNS-label-ish"):
/// 1-32 chars, each an ASCII lowercase letter, digit, or hyphen. No regex
/// dependency needed for a character class this small.
fn is_valid_peer_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `"rf:" + 64 hex chars` format check (cycle-A node identity format, design
/// §4/§112.6) -- the same shape `node_identity::verify` parses, duplicated
/// here as a pure format check (config validation has no key material to
/// verify against, just the string shape).
fn is_valid_rf_node_id(s: &str) -> bool {
    match s.strip_prefix("rf:") {
        Some(hex_part) => hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        None => false,
    }
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

    /// Like `parse`, but also runs the secret-reference resolution step
    /// (`load`'s third stage) -- the step `parse` above deliberately skips,
    /// since most of this module's tests are about structural validation
    /// and don't want real env vars / files as a dependency.
    fn parse_and_resolve(s: &str) -> Result<Config, String> {
        let mut cfg = parse(s)?;
        resolve_secrets(&mut cfg)?;
        Ok(cfg)
    }

    // ---- raw_yaml (design §1: hot-reloadable config / admin GET /v1/config) --

    #[test]
    fn load_from_str_captures_raw_yaml_verbatim() {
        let cfg = load_from_str(GOOD).unwrap();
        assert_eq!(cfg.raw_yaml, GOOD);
    }

    #[test]
    fn hand_built_config_literals_default_raw_yaml_to_empty() {
        // The struct-literal path every other test in this module (and
        // engine.rs's test_daemon_full) uses never goes through
        // load_from_str, so raw_yaml -- being #[serde(skip)] -- must fall
        // back to String::default() rather than require every call site to
        // set it.
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.raw_yaml, "");
    }

    #[test]
    fn raw_yaml_retains_unresolved_secret_refs_verbatim_and_never_the_resolved_value() {
        std::env::set_var("RF_CONFIG_TEST_RAW_YAML", "sentinel-raw-yaml-value");
        let yaml = with_secret_config("RF_CONFIG_TEST_RAW_YAML");
        let cfg = load_from_str(&yaml).unwrap();
        assert_eq!(cfg.raw_yaml, yaml);
        assert!(cfg.raw_yaml.contains("${env:RF_CONFIG_TEST_RAW_YAML}"),
            "raw_yaml must keep the reference form: {}", cfg.raw_yaml);
        assert!(!cfg.raw_yaml.contains("sentinel-raw-yaml-value"),
            "raw_yaml must never contain a resolved secret value: {}", cfg.raw_yaml);
        std::env::remove_var("RF_CONFIG_TEST_RAW_YAML");
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
    fn identity_mode_defaults_to_pseudonymous_when_absent() {
        // v0.1/pre-cycle-C style config has no identity_mode key at all.
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.routes[0].identity_mode, "pseudonymous");
    }

    #[test]
    fn identity_mode_linked_is_accepted() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    identity_mode: linked",
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.routes[0].identity_mode, "linked");
    }

    #[test]
    fn identity_mode_unknown_value_is_rejected() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    identity_mode: anonymous",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("general"), "err should name the route: {err}");
        assert!(err.contains("anonymous"), "err should quote the bad value: {err}");
    }

    /// The design's §IPC "@identity" sentinel is where challenge/confirmation
    /// deliveries live (see `engine::process_due`); a user route claiming
    /// that name would collide with the dispatch that special-cases it.
    #[test]
    fn reserved_identity_route_name_is_rejected() {
        let yaml = GOOD.replace("name: general", "name: \"@identity\"");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("@identity"), "err was: {err}");
        assert!(err.contains("reserved"), "err was: {err}");
    }

    #[test]
    fn render_defaults_to_alias_tag_and_zero_max_chars_when_absent() {
        // v0.1/pre-cycle-D configs have no `render:` key on a route at all.
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.routes[0].render.tag, "alias");
        assert_eq!(cfg.routes[0].render.max_chars, 0);
    }

    #[test]
    fn render_tag_none_is_accepted() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    render:\n      tag: none",
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.routes[0].render.tag, "none");
        // max_chars omitted under a present `render:` block still defaults to 0.
        assert_eq!(cfg.routes[0].render.max_chars, 0);
    }

    #[test]
    fn render_max_chars_is_accepted_at_and_above_the_16_floor() {
        for max_chars in [16, 900] {
            let yaml = GOOD.replace(
                "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
                &format!(
                    "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    render:\n      max_chars: {max_chars}"
                ),
            );
            let cfg = parse(&yaml).unwrap_or_else(|e| panic!("max_chars {max_chars} should be valid: {e}"));
            assert_eq!(cfg.routes[0].render.max_chars, max_chars);
            // tag omitted under a present `render:` block still defaults to "alias".
            assert_eq!(cfg.routes[0].render.tag, "alias");
        }
    }

    /// A typo in `render.tag` (e.g. "alais") must fail loudly at config
    /// load, not fail open at runtime the way `identity_mode` and
    /// `policies.rules.attachments` already do for their own typo cases.
    #[test]
    fn render_tag_unknown_value_is_rejected() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    render:\n      tag: alais",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("general"), "err should name the route: {err}");
        assert!(err.contains("alais"), "err should quote the bad value: {err}");
    }

    /// `max_chars` below the 16 floor is rejected rather than silently
    /// truncating messages down to near-nothing; 0 is the explicit
    /// "disabled" sentinel and stays valid (see `render_defaults_to_alias_tag_and_zero_max_chars_when_absent`).
    #[test]
    fn render_max_chars_below_16_is_rejected() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    render:\n      max_chars: 5",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("general"), "err should name the route: {err}");
        assert!(err.contains('5'), "err should quote the bad value: {err}");
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

    // ---- secret references (design §2 / SPEC §51, §59) --------------------

    /// `var_name` is caller-supplied (rather than a shared const) so that
    /// tests running concurrently under `cargo test`'s multi-threaded
    /// default never share a process-global env var: `std::env::set_var`/
    /// `remove_var` racing across threads on the SAME key was a real,
    /// reproduced flake here (a test asserting "unset" could observe
    /// another thread's concurrent `set_var` on the identical name, and
    /// vice versa). Every call site below passes a name unique to that
    /// test.
    fn with_secret_config(var_name: &str) -> String {
        format!(
            r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
    config:
      token: "${{env:{var_name}}}"
      plain: "literal-value"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#
        )
    }

    #[test]
    fn plugin_config_secret_ref_resolves_into_runtime_config() {
        std::env::set_var("RF_CONFIG_TEST_TOKEN_RESOLVE", "sentinel-runtime-value");
        let cfg = parse_and_resolve(&with_secret_config("RF_CONFIG_TEST_TOKEN_RESOLVE")).unwrap();
        let token = cfg.plugins["mocka"].config.get("token").unwrap().as_str().unwrap();
        assert_eq!(token, "sentinel-runtime-value");
        // an ordinary literal string alongside the reference is untouched.
        assert_eq!(cfg.plugins["mocka"].config.get("plain").unwrap().as_str().unwrap(), "literal-value");
        std::env::remove_var("RF_CONFIG_TEST_TOKEN_RESOLVE");
    }

    #[test]
    fn raw_plugin_configs_retains_unresolved_form_for_display() {
        std::env::set_var("RF_CONFIG_TEST_TOKEN_RAW", "sentinel-runtime-value");
        let cfg = parse_and_resolve(&with_secret_config("RF_CONFIG_TEST_TOKEN_RAW")).unwrap();
        let raw_token = cfg.raw_plugin_configs["mocka"].get("token").unwrap().as_str().unwrap();
        assert_eq!(raw_token, "${env:RF_CONFIG_TEST_TOKEN_RAW}");
        // the resolved runtime config must never leak into the raw snapshot.
        assert!(!format!("{:?}", cfg.raw_plugin_configs).contains("sentinel-runtime-value"));
        std::env::remove_var("RF_CONFIG_TEST_TOKEN_RAW");
    }

    #[test]
    fn plugin_config_secret_ref_resolves_recursively_through_nested_objects_and_arrays() {
        std::env::set_var("RF_CONFIG_TEST_NESTED", "sentinel-nested-value");
        let yaml = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
    config:
      nested:
        list:
          - "${env:RF_CONFIG_TEST_NESTED}"
          - "literal"
        inner:
          deep: "${env:RF_CONFIG_TEST_NESTED}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#;
        let cfg = parse_and_resolve(yaml).unwrap();
        let config = &cfg.plugins["mocka"].config;
        let list_item = config["nested"]["list"][0].as_str().unwrap();
        assert_eq!(list_item, "sentinel-nested-value");
        assert_eq!(config["nested"]["list"][1].as_str().unwrap(), "literal");
        assert_eq!(config["nested"]["inner"]["deep"].as_str().unwrap(), "sentinel-nested-value");
        std::env::remove_var("RF_CONFIG_TEST_NESTED");
    }

    #[test]
    fn v0_1_style_plugin_config_without_secret_refs_is_unaffected() {
        // GOOD's plugins carry no `config:` block at all -- the v0.1-compat
        // case: no secret refs anywhere means zero resolution attempts and
        // zero errors, and `raw_plugin_configs` mirrors the (unchanged)
        // resolved config exactly.
        let cfg = parse_and_resolve(GOOD).unwrap();
        assert_eq!(cfg.plugins["mocka"].config, serde_yaml::Value::Null);
        assert_eq!(cfg.raw_plugin_configs["mocka"], serde_yaml::Value::Null);
    }

    #[test]
    fn unresolvable_env_secret_ref_fails_load_naming_the_reference_not_a_value() {
        // RF_CONFIG_TEST_TOKEN_UNSET is unique to this test (see
        // `with_secret_config`'s doc comment) and never set anywhere else,
        // so no `remove_var` race with a concurrently running test is
        // possible; the removal below only guards against a stale leftover
        // from a prior manual run.
        std::env::remove_var("RF_CONFIG_TEST_TOKEN_UNSET");
        let err = parse_and_resolve(&with_secret_config("RF_CONFIG_TEST_TOKEN_UNSET")).unwrap_err();
        assert!(err.contains("${env:RF_CONFIG_TEST_TOKEN_UNSET}"), "err should name the reference: {err}");
    }

    #[test]
    fn multiple_failing_secret_refs_are_all_reported() {
        std::env::remove_var("RF_CONFIG_TEST_MULTI_A");
        std::env::remove_var("RF_CONFIG_TEST_MULTI_B");
        let yaml = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
    config:
      a: "${env:RF_CONFIG_TEST_MULTI_A}"
  mockb:
    enabled: true
    config:
      b: "${env:RF_CONFIG_TEST_MULTI_B}"
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#;
        let err = parse_and_resolve(yaml).unwrap_err();
        assert!(err.contains("${env:RF_CONFIG_TEST_MULTI_A}"), "err was: {err}");
        assert!(err.contains("${env:RF_CONFIG_TEST_MULTI_B}"), "err was: {err}");
    }

    /// Integration-level companion to `secrets::tests::resolve_file_errors_
    /// naming_ref_for_relative_path`: a relative `${file:...}` path must
    /// fail the whole config load, naming the reference, not just fail at
    /// the `secrets` unit level.
    #[test]
    fn relative_file_secret_ref_fails_load_naming_the_reference() {
        let yaml = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
    config:
      token: "${file:relative/token.txt}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#;
        let err = parse_and_resolve(yaml).unwrap_err();
        assert!(err.contains("${file:relative/token.txt}"), "err should name the reference: {err}");
    }

    #[test]
    fn file_secret_ref_resolves_via_load() {
        let dir = tempfile::tempdir().unwrap();
        let secret_path = dir.path().join("token.txt");
        std::fs::write(&secret_path, "sentinel-file-token\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let yaml = format!(
            r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
    config:
      token: "${{file:{}}}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#,
            secret_path.display()
        );
        let cfg_path = dir.path().join("relayfabric.yaml");
        std::fs::write(&cfg_path, &yaml).unwrap();

        let cfg = load(&cfg_path).unwrap();
        assert_eq!(cfg.plugins["mocka"].config.get("token").unwrap().as_str().unwrap(), "sentinel-file-token");
        assert_eq!(
            cfg.raw_plugin_configs["mocka"].get("token").unwrap().as_str().unwrap(),
            format!("${{file:{}}}", secret_path.display()),
        );
    }

    /// Finding: `${vault:x}`-shaped values (unsupported scheme) used to
    /// parse as `None` and silently stay literal with no signal at all --
    /// the plugin then receives the literal string as its token and fails
    /// confusingly downstream, unlike `${file:relative}` which errors
    /// loudly. The fix keeps the "stays literal" behavior (no load
    /// failure -- this is a warning, not an error) but is loud about it via
    /// `secrets::malformed_ref_warning` (see its own unit tests in
    /// `secrets.rs` for the warning content itself).
    #[test]
    fn unknown_scheme_secret_ref_loads_fine_and_stays_literal() {
        let yaml = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
    config:
      token: "${vault:x}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#;
        let cfg = parse_and_resolve(yaml).unwrap();
        assert_eq!(
            cfg.plugins["mocka"].config.get("token").unwrap().as_str().unwrap(),
            "${vault:x}",
        );
    }

    /// v0.1/v0.2-with-no-secret-refs example config used in CI/manual sanity
    /// checks (`cargo run -p switchyardd -- --config docs/relayfabric.example.yaml
    /// --check-config`) must keep loading unchanged: no secret refs anywhere
    /// means `resolve_secrets` is a pure no-op.
    #[test]
    fn example_config_has_no_secret_refs_and_loads_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let raw = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/relayfabric.example.yaml"),
        ).unwrap();
        let cfg_path = dir.path().join("relayfabric.yaml");
        std::fs::write(&cfg_path, &raw).unwrap();
        let cfg = load(&cfg_path).unwrap();
        assert_eq!(cfg.plugins["mqtt"].config["broker"], serde_yaml::Value::String("mqtt://127.0.0.1:1883".into()));
    }

    // ---- federation (design §3/§4, cycle F) --------------------------------

    const FED_BASE: &str = r#"
node:
  name: test-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
routes:
  - name: regional-chat
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#;

    fn node_id_a() -> String { format!("rf:{}", "ab".repeat(32)) }
    fn node_id_b() -> String { format!("rf:{}", "cd".repeat(32)) }
    fn node_id_c() -> String { format!("rf:{}", "ef".repeat(32)) }

    #[test]
    fn federation_block_absent_is_valid_and_field_is_none() {
        // v0.1/pre-cycle-F config has no `federation:` key at all.
        let cfg = parse(GOOD).unwrap();
        assert!(cfg.federation.is_none());
    }

    #[test]
    fn federation_full_block_matches_design_4_yaml_exactly() {
        let yaml = format!(
            r#"{FED_BASE}
federation:
  listen: "127.0.0.1:47000"
  accept_from: trusted
  max_hops: 6
  max_ttl_secs: 3600
  identity_exposure: full
  ingress_routes: [regional-chat]
  peers:
    - name: phoenix
      node_id: "{a}"
      addr: "10.0.0.2:47000"
      trust: trusted
  trusted: ["{b}"]
  blocked: ["{c}"]
"#,
            a = node_id_a(), b = node_id_b(), c = node_id_c(),
        );
        let cfg = parse(&yaml).unwrap_or_else(|e| panic!("full federation block should be valid: {e}"));
        let fed = cfg.federation.unwrap();
        assert_eq!(fed.listen.as_deref(), Some("127.0.0.1:47000"));
        assert_eq!(fed.accept_from, "trusted");
        assert_eq!(fed.max_hops, 6);
        assert_eq!(fed.max_ttl_secs, 3600);
        assert_eq!(fed.identity_exposure, "full");
        assert_eq!(fed.ingress_routes, vec!["regional-chat".to_string()]);
        assert_eq!(fed.peers.len(), 1);
        assert_eq!(fed.peers[0].name, "phoenix");
        assert_eq!(fed.peers[0].node_id, node_id_a());
        assert_eq!(fed.peers[0].addr, "10.0.0.2:47000");
        assert_eq!(fed.peers[0].trust, "trusted");
        assert_eq!(fed.trusted, vec![node_id_b()]);
        assert_eq!(fed.blocked, vec![node_id_c()]);
    }

    #[test]
    fn federation_minimal_block_defaults_every_optional_field() {
        let yaml = format!("{FED_BASE}\nfederation: {{}}\n");
        let cfg = parse(&yaml).unwrap();
        let fed = cfg.federation.unwrap();
        assert_eq!(fed.listen, None, "absent listen = outbound-only node");
        assert_eq!(fed.accept_from, "verified");
        assert_eq!(fed.max_hops, 4);
        assert_eq!(fed.max_ttl_secs, 86_400);
        assert_eq!(fed.identity_exposure, "pseudonymous");
        assert!(fed.ingress_routes.is_empty(), "default: no route accepts fed ingress");
        assert!(fed.peers.is_empty());
        assert!(fed.trusted.is_empty());
        assert!(fed.blocked.is_empty());
    }

    #[test]
    fn federation_peer_trust_defaults_to_verified_when_absent() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n",
            a = node_id_a(),
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.federation.unwrap().peers[0].trust, "verified");
    }

    #[test]
    fn federation_rejects_invalid_accept_from() {
        let yaml = format!("{FED_BASE}\nfederation:\n  accept_from: maybe\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("accept_from"), "err was: {err}");
        assert!(err.contains("maybe"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_invalid_identity_exposure() {
        let yaml = format!("{FED_BASE}\nfederation:\n  identity_exposure: nope\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("identity_exposure"), "err was: {err}");
        assert!(err.contains("nope"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_invalid_listen_address() {
        let yaml = format!("{FED_BASE}\nfederation:\n  listen: \"not-an-addr\"\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("listen"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_ingress_route_naming_an_unknown_route() {
        let yaml = format!("{FED_BASE}\nfederation:\n  ingress_routes: [ghost-route]\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("ingress_routes"), "err was: {err}");
        assert!(err.contains("ghost-route"), "err was: {err}");
    }

    #[test]
    fn federation_ingress_routes_naming_an_existing_route_is_ok() {
        let yaml = format!("{FED_BASE}\nfederation:\n  ingress_routes: [regional-chat]\n");
        assert!(parse(&yaml).is_ok());
    }

    #[test]
    fn federation_rejects_duplicate_peer_names() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n    - name: phoenix\n      node_id: \"{b}\"\n      addr: \"10.0.0.3:47000\"\n",
            a = node_id_a(), b = node_id_b(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("duplicate"), "err was: {err}");
        assert!(err.contains("phoenix"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_peer_name_with_invalid_characters() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: \"Phoenix_AZ\"\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n",
            a = node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("Phoenix_AZ"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_peer_name_over_32_chars() {
        let long_name = "a".repeat(33);
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: \"{long_name}\"\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n",
            a = node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains(&long_name), "err was: {err}");
    }

    #[test]
    fn federation_accepts_peer_name_at_the_32_char_ceiling() {
        let name = "a".repeat(32);
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: \"{name}\"\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n",
            a = node_id_a(),
        );
        let cfg = parse(&yaml).unwrap_or_else(|e| panic!("32-char name should be valid: {e}"));
        assert_eq!(cfg.federation.unwrap().peers[0].name, name);
    }

    #[test]
    fn federation_rejects_malformed_peer_node_id_missing_prefix() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"not-rf-formatted\"\n      addr: \"10.0.0.2:47000\"\n",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("node_id"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_peer_node_id_with_wrong_hex_length() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"rf:abcd\"\n      addr: \"10.0.0.2:47000\"\n",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("node_id"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_peer_node_id_with_non_hex_characters() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"rf:{}\"\n      addr: \"10.0.0.2:47000\"\n",
            "zz".repeat(32),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("node_id"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_invalid_peer_addr() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      addr: \"not-an-addr\"\n",
            a = node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("addr"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_invalid_peer_trust() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n      trust: superfan\n",
            a = node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("trust"), "err was: {err}");
        assert!(err.contains("superfan"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_malformed_trusted_entry() {
        let yaml = format!("{FED_BASE}\nfederation:\n  trusted: [\"not-rf\"]\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("not-rf"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_malformed_blocked_entry() {
        let yaml = format!("{FED_BASE}\nfederation:\n  blocked: [\"not-rf\"]\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("not-rf"), "err was: {err}");
    }

    #[test]
    fn federation_valid_trusted_and_blocked_entries_are_ok() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  trusted: [\"{a}\"]\n  blocked: [\"{b}\"]\n",
            a = node_id_a(), b = node_id_b(),
        );
        let cfg = parse(&yaml).unwrap();
        let fed = cfg.federation.unwrap();
        assert_eq!(fed.trusted, vec![node_id_a()]);
        assert_eq!(fed.blocked, vec![node_id_b()]);
    }

    // ---- federation node_id overlap warning (Task 3 review carry-over) ---

    #[test]
    fn overlapping_federation_node_ids_is_empty_when_every_list_is_disjoint() {
        let fed = fed_cfg_for(
            vec![peer_cfg("phoenix", &node_id_a())], vec![node_id_b()], vec![node_id_c()]);
        assert!(overlapping_federation_node_ids(&fed).is_empty());
    }

    #[test]
    fn overlapping_federation_node_ids_flags_a_peer_also_listed_trusted() {
        let fed = fed_cfg_for(
            vec![peer_cfg("phoenix", &node_id_a())], vec![node_id_a()], vec![]);
        assert_eq!(overlapping_federation_node_ids(&fed), BTreeSet::from([node_id_a()]));
    }

    #[test]
    fn overlapping_federation_node_ids_flags_a_peer_also_listed_blocked() {
        let fed = fed_cfg_for(
            vec![peer_cfg("phoenix", &node_id_a())], vec![], vec![node_id_a()]);
        assert_eq!(overlapping_federation_node_ids(&fed), BTreeSet::from([node_id_a()]));
    }

    #[test]
    fn overlapping_federation_node_ids_flags_trusted_also_listed_blocked() {
        let fed = fed_cfg_for(vec![], vec![node_id_a()], vec![node_id_a()]);
        assert_eq!(overlapping_federation_node_ids(&fed), BTreeSet::from([node_id_a()]));
    }

    #[test]
    fn overlapping_federation_node_ids_dedups_when_the_same_id_is_in_all_three() {
        let fed = fed_cfg_for(
            vec![peer_cfg("phoenix", &node_id_a())], vec![node_id_a()], vec![node_id_a()]);
        assert_eq!(overlapping_federation_node_ids(&fed), BTreeSet::from([node_id_a()]));
    }

    #[test]
    fn federation_config_with_overlapping_node_ids_still_loads_successfully() {
        // Overlap is a warning (eprintln!), never a validate() error --
        // config::load_from_str must still succeed. `blocked` also being in
        // `peers[]` is the "operator accidentally disabled a peer" case
        // this warning exists to catch.
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      \
             addr: \"10.0.0.2:47000\"\n  blocked: [\"{a}\"]\n",
            a = node_id_a(),
        );
        let cfg = load_from_str(&yaml).unwrap_or_else(|e| {
            panic!("overlapping node_ids must warn, not fail config load: {e}")
        });
        assert_eq!(cfg.federation.unwrap().peers[0].node_id, node_id_a());
    }

    fn peer_cfg(name: &str, node_id: &str) -> PeerConfig {
        PeerConfig {
            name: name.into(), node_id: node_id.into(),
            addr: "10.0.0.2:47000".into(), trust: "verified".into(),
        }
    }

    fn fed_cfg_for(
        peers: Vec<PeerConfig>, trusted: Vec<String>, blocked: Vec<String>,
    ) -> FederationConfig {
        FederationConfig {
            listen: None, accept_from: "verified".into(), max_hops: 4, max_ttl_secs: 86_400,
            identity_exposure: "pseudonymous".into(), ingress_routes: vec![],
            peers, trusted, blocked,
        }
    }

    #[test]
    fn fed_reserved_as_plugin_name_is_rejected() {
        let yaml = GOOD.replace(
            "  mocka:\n    enabled: true",
            "  mocka:\n    enabled: true\n  fed:\n    enabled: true",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("fed"), "err was: {err}");
        assert!(err.contains("reserved"), "err was: {err}");
    }

    #[test]
    fn fed_reserved_as_route_source_protocol_is_rejected() {
        let yaml = GOOD.replace(
            "    sources: [\"mocka:chan\", \"mockb:chan\"]",
            "    sources: [\"fed:phoenix/regional-chat\", \"mockb:chan\"]",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("fed"), "err was: {err}");
        assert!(err.contains("general"), "err should name the route: {err}");
        assert!(err.contains("source"), "err was: {err}");
    }

    // ---- fed: route destinations (design §5 egress, Task 5) ---------------
    //
    // Supersedes Task 3's `fed_destination_is_rejected_as_unknown_plugin_
    // not_as_reserved_this_cycle` (that test's own doc comment named this
    // task as the one that would replace it): a `fed:<peer>/<route>`
    // destination is no longer just "an unknown plugin" -- it gets its own
    // validation path (`validate_fed_destination`) with its own error
    // reasons, exercised by the matrix below.

    /// `GOOD` (used by every test in this module) has no `federation:`
    /// block at all -- a `fed:` destination must be rejected entirely in
    /// that case (design §5: "reject entirely when federation block
    /// absent"), not fall through to the generic "unknown plugin" error a
    /// pre-Task-5 build produced.
    #[test]
    fn fed_destination_is_rejected_when_federation_block_is_absent() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"fed:phoenix/regional-chat\", \"mockb:chan\"]",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("general"), "err should name the route: {err}");
        assert!(err.contains("federation"), "err was: {err}");
        assert!(!err.contains("unknown plugin"), "must not fall through to the generic plugin check: {err}");
    }

    /// A `fed:<peer>/<route>` destination naming a peer that's actually
    /// configured in `federation.peers[]` is a valid destination -- no
    /// `cfg.plugins` entry needed, unlike every other protocol.
    #[test]
    fn fed_destination_naming_a_configured_peer_is_accepted() {
        let yaml = format!(
            "{}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{}\"\n      addr: \"10.0.0.2:47000\"\n",
            GOOD.replace(
                "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
                "    destinations: [\"fed:phoenix/regional-chat\", \"mockb:chan\"]",
            ),
            node_id_a(),
        );
        parse(&yaml).unwrap_or_else(|e| panic!("a fed: destination naming a configured peer should be valid: {e}"));
    }

    #[test]
    fn fed_destination_naming_an_unconfigured_peer_is_rejected() {
        let yaml = format!(
            "{}\nfederation:\n  peers:\n    - name: seattle\n      node_id: \"{}\"\n      addr: \"10.0.0.2:47000\"\n",
            GOOD.replace(
                "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
                "    destinations: [\"fed:phoenix/regional-chat\", \"mockb:chan\"]",
            ),
            node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("phoenix"), "err should name the unknown peer: {err}");
        assert!(err.contains("unknown peer"), "err was: {err}");
    }

    #[test]
    fn fed_destination_missing_the_slash_separator_is_rejected() {
        let yaml = format!(
            "{}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{}\"\n      addr: \"10.0.0.2:47000\"\n",
            GOOD.replace(
                "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
                "    destinations: [\"fed:phoenixregionalchat\", \"mockb:chan\"]",
            ),
            node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("invalid fed: destination"), "err was: {err}");
    }

    #[test]
    fn fed_destination_with_empty_remote_route_is_rejected() {
        let yaml = format!(
            "{}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{}\"\n      addr: \"10.0.0.2:47000\"\n",
            GOOD.replace(
                "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
                "    destinations: [\"fed:phoenix/\", \"mockb:chan\"]",
            ),
            node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("remote route"), "err was: {err}");
    }

    #[test]
    fn fed_destination_with_invalid_remote_route_charset_is_rejected() {
        let yaml = format!(
            "{}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{}\"\n      addr: \"10.0.0.2:47000\"\n",
            GOOD.replace(
                "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
                "    destinations: [\"fed:phoenix/Regional_Chat\", \"mockb:chan\"]",
            ),
            node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("Regional_Chat"), "err was: {err}");
        assert!(err.contains("remote route"), "err was: {err}");
    }

    /// v0.2 example config carries no `federation:` key -- must keep
    /// validating exactly as it did before this task's additions.
    #[test]
    fn example_config_has_no_federation_block_and_stays_valid() {
        let raw = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/relayfabric.example.yaml"),
        ).unwrap();
        let cfg: Config = serde_yaml::from_str(&raw).unwrap();
        assert!(cfg.federation.is_none());
        assert!(validate(&cfg).is_ok());
    }
}
