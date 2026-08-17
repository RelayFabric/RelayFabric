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
    /// RFDP discovery (design §111/§112, cycle G): absent entirely (every
    /// pre-cycle-G config) defaults to `DiscoveryConfig::default()` --
    /// `mode: "disabled"` -- matching today's no-advertisement behavior
    /// exactly. `apply_config` (engine.rs) treats ANY change to this
    /// block as `"daemon"` restart-required, the same posture as
    /// `federation` above: advert content/exchange only takes effect on
    /// the next daemon start this cycle.
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    /// Node-level sealed-routing privacy floor (design §3, SPEC §113.2,
    /// cycle H). Absent entirely (every pre-cycle-H config) defaults to
    /// `PrivacyConfig::default()` -- `minimum_security: "gateway"`,
    /// `allow_gateway_decryption: true`, `allow_protocol_downgrade: true` --
    /// which imposes no floor at all and reproduces today's behavior
    /// exactly. Deliberately a TOP-LEVEL `Config` field, NOT nested inside
    /// `NodeConfig`: `Daemon::apply_config`'s restart-required diff compares
    /// `cfg.node` as one unit and reports `"daemon"` on ANY change to it
    /// (see `NodeConfig`'s doc comment) -- but a privacy-floor edit is meant
    /// to take effect live, the same as `routes`/`render`/`identity_mode`
    /// (every read goes through `cfg.read()`/`route_cfg`, so the next
    /// per-message check sees the new value with no restart needed). Nesting
    /// this under `node` would have silently forced a restart for a field
    /// that doesn't need one; keeping it a sibling avoids that trap without
    /// `apply_config` needing any new diff logic at all.
    #[serde(default)]
    pub privacy: PrivacyConfig,
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
    /// Design §3, SPEC §113.1/§113.2, cycle H: "gateway" (default -- current
    /// transform/translate behavior, cycle-F's pseudonymize+sign+cleartext
    /// egress) or "sealed" (the origin edge AEAD-seals the payload for the
    /// destination edge's key; the fabric routes ciphertext only -- design
    /// §2/§4). Default `gateway` preserves ALL existing route behavior
    /// (v0.1/v0.2/v0.3 configs unchanged). "native" (SPEC §113.1's
    /// per-protocol-bridge concept) is documented as an alias of "gateway"
    /// today, NOT a separate value this cycle -- `validate()` rejects it
    /// (and anything else outside {gateway, sealed}) with a message saying
    /// so. Egress/ingress behavior driven by this field is Task 4/5's job;
    /// this task only parses/validates it (design §3's --check-config
    /// downgrade-refusal matrix).
    #[serde(default = "default_security_mode")]
    pub security_mode: String,
    /// Design §3, SPEC §113.2, cycle H: per-route override of the node's
    /// `privacy.allow_gateway_decryption` floor -- `Some(_)` wins over the
    /// node default when set, `None` (default, every pre-cycle-H config)
    /// defers to `privacy.allow_gateway_decryption`. Governs whether THIS
    /// route may terminate a sealed inbound envelope by decrypting it for
    /// delivery to a plaintext leg (§113.3's unavoidable phase-1 gateway
    /// decryption point) -- `false` means the route refuses to be that
    /// termination point (SECURITY_DOWNGRADE_REFUSED). Not validated at
    /// --check-config (only `security_mode` + `privacy.minimum_security` +
    /// a sealed peer's `sealed_key` are, per design §3's three-item
    /// rejection list); resolving/consuming this override is Task 5's job
    /// (ingress downgrade refusal) -- inert this task beyond shape parsing.
    #[serde(default)]
    pub allow_gateway_decryption: Option<bool>,
}

fn default_identity_mode() -> String { "pseudonymous".to_string() }
fn default_security_mode() -> String { "gateway".to_string() }

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
    /// Aggregate egress budget for this peer's fed link, per minute
    /// (design §5, carried from the cycle-F review: the many-distinct-
    /// senders flood gap -- per-sender limits don't cap a peer sending
    /// from many distinct senders). 0 (default) = unlimited. No
    /// `validate()` constraint beyond its type: unlike
    /// `transport_budgets` (where 0 IS an error -- that block has no
    /// "omit for unlimited" escape hatch), a per-peer 0 legitimately
    /// means "no limit", the same posture `limits.*` fields already take.
    /// Enforcement (keyed `"fed/<peer_name>"` in the existing
    /// `BudgetLimiter`) is a later cycle-G task.
    #[serde(default)]
    pub messages_per_minute: u32,
    /// Sealed-routing key pin (design §1/SPEC §113.3, cycle H): 64 lowercase
    /// hex chars, this peer's `fed::sealkey::SealedKey` public half -- an
    /// explicit operator-configured value, independent of whatever this
    /// peer's own advert later claims. `None` (default, every pre-cycle-H
    /// config) means this peer's sealed key is whatever its advert says, if
    /// anything. Egress key-RESOLUTION (config pin vs. advert-learned, and
    /// what happens when both are present and disagree -- config wins +
    /// warn) is a later cycle-H task; this field is validated here (shape
    /// only) and otherwise inert this task.
    #[serde(default)]
    pub sealed_key: Option<String>,
}

fn default_peer_trust() -> String {
    "verified".to_string()
}

/// RFDP discovery policy (design §1/§4, SPEC §111.5/§112.2, cycle G).
/// `PartialEq`/`Eq` power `Daemon::apply_config`'s restart-required diff
/// (see `Config::discovery`'s doc comment): any field change trips the
/// `"daemon"` restart entry, same as `federation`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DiscoveryConfig {
    /// "disabled" (default) | "federation" | "public" -- SPEC §111.5's
    /// four scopes minus "local" (DEFERRED this cycle: no LAN transport
    /// exists yet -- `validate()` rejects it with a "future cycle"
    /// message rather than silently accepting a scope this build can't
    /// actually implement).
    #[serde(default = "default_discovery_mode")]
    pub mode: String,
    /// Seconds an issued advert stays valid before needing a refresh
    /// (design §1: `expires = now + advert_ttl_secs`). Minimum 300 --
    /// `validate()` rejects anything shorter as a churn/flood footgun.
    #[serde(default = "default_advert_ttl_secs")]
    pub advert_ttl_secs: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        DiscoveryConfig { mode: default_discovery_mode(), advert_ttl_secs: default_advert_ttl_secs() }
    }
}

fn default_discovery_mode() -> String {
    "disabled".to_string()
}
fn default_advert_ttl_secs() -> u64 {
    3600
}

/// Node-level sealed-routing privacy floor (design §3, SPEC §113.2, cycle
/// H) -- see `Config::privacy`'s doc comment for why this is a top-level
/// `Config` field rather than nested inside `NodeConfig`. YAML shape matches
/// SPEC §113.2's example exactly:
/// ```yaml
/// privacy:
///   minimum_security: sealed
///   allow_gateway_decryption: false
///   allow_protocol_downgrade: false
/// ```
/// No `PartialEq`/`Eq` derive: unlike `federation`/`discovery`, this block
/// is deliberately NOT part of `Daemon::apply_config`'s restart-required
/// diff (see `Config::privacy`), so nothing ever needs to compare two
/// `PrivacyConfig` values for that purpose.
#[derive(Debug, Clone, Deserialize)]
pub struct PrivacyConfig {
    /// "gateway" (default) or "sealed" -- the minimum `RouteConfig::
    /// security_mode` this node accepts; `validate()` rejects any route
    /// whose `security_mode` ranks below this (sealed > gateway, design
    /// §113.2 downgrade refusal).
    #[serde(default = "default_minimum_security")]
    pub minimum_security: String,
    /// Whether a route may terminate a sealed inbound envelope by
    /// decrypting it for delivery to a plaintext leg (§113.3's phase-1
    /// gateway decryption point). Default `true` (today's only possible
    /// behavior -- every pre-cycle-H node IS such a termination point).
    /// `RouteConfig::allow_gateway_decryption` overrides this per route when
    /// set. Read at ingress (Task 5), not validated at --check-config.
    #[serde(default = "default_allow_gateway_decryption")]
    pub allow_gateway_decryption: bool,
    /// Whether a `sealed`-floor node may still accept/emit a lower-security
    /// leg elsewhere in the fabric (as opposed to the per-route
    /// `minimum_security` floor rejection, which is absolute). Default
    /// `true`. Parsed/stored/defaulted here only -- not read by `validate()`
    /// or anywhere else this task; consumed by egress Task 4 / ingress
    /// Task 5.
    #[serde(default = "default_allow_protocol_downgrade")]
    pub allow_protocol_downgrade: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        PrivacyConfig {
            minimum_security: default_minimum_security(),
            allow_gateway_decryption: default_allow_gateway_decryption(),
            allow_protocol_downgrade: default_allow_protocol_downgrade(),
        }
    }
}

fn default_minimum_security() -> String { "gateway".to_string() }
fn default_allow_gateway_decryption() -> bool { true }
fn default_allow_protocol_downgrade() -> bool { true }

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

    // node.name (final cycle-G review finding): design §1's advert contract
    // says a node's name is "validated <=64 chars, no newlines" -- but that
    // was only ever enforced on a RECEIVED advert's name
    // (`fed::conn::sanitize_advert_name`, run on every remote peer's
    // advert before storage/serve/SSE). Our OWN `node.name` is embedded
    // AND SIGNED into our own advert (`fed::advert::build_from_config` /
    // `build_signed_advert`) and served at `GET /v1/discovery` + ctl
    // `discovery` with no equivalent check -- a bad name never gets
    // sanitized because it's never "received", so a control-char-laden or
    // over-length `node.name` would be signed into a wire advert a
    // third-party RFDP receiver trusts verbatim. Rejecting it HERE, at
    // config load, closes that gap at the source: a config this function
    // accepts can never produce a signed advert with an unsafe name.
    let name_len = cfg.node.name.chars().count();
    if name_len > 64 {
        return Err(format!(
            "node.name is {name_len} characters, over the 64-character limit (design §1: it is \
             signed into this node's own RFDP advert)"
        ));
    }
    if let Some(c) = cfg.node.name.chars().find(|&c| is_unsafe_advert_name_char(c)) {
        return Err(format!(
            "node.name contains an unsafe character ({c:?}) -- no control characters, newlines, \
             or Unicode bidi-control/default-ignorable spoofing codepoints allowed (design §1: it \
             is signed into this node's own RFDP advert)"
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
        if r.security_mode != "gateway" && r.security_mode != "sealed" {
            return Err(format!(
                "route '{}' has invalid security_mode '{}' (expected \"gateway\" or \"sealed\" -- \
                 \"native\" per SPEC §113.1 is an alias of \"gateway\" today, not a separate mode \
                 this cycle; use \"gateway\")",
                r.name, r.security_mode
            ));
        }
        if security_rank(&r.security_mode) < security_rank(&cfg.privacy.minimum_security) {
            return Err(format!(
                "route '{}' has security_mode '{}' which is below the node's privacy.minimum_security \
                 floor '{}' (design §113.2 downgrade refusal: a route may never load below the floor)",
                r.name, r.security_mode, cfg.privacy.minimum_security
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
        if r.security_mode == "sealed" {
            validate_sealed_route(cfg, r)?;
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
    validate_discovery(cfg)?;
    validate_privacy(cfg)?;

    Ok(())
}

/// Design §3 validation for the node-level `privacy` block (SPEC §113.2,
/// cycle H). Never absent -- `Config::privacy` defaults to
/// `PrivacyConfig::default()` (`minimum_security: "gateway"`) via
/// `#[serde(default)]`, so this runs unconditionally; every pre-cycle-H
/// config (no `privacy:` block at all) validates against that default and
/// passes trivially, imposing no floor.
fn validate_privacy(cfg: &Config) -> Result<(), String> {
    let p = &cfg.privacy;
    if p.minimum_security != "gateway" && p.minimum_security != "sealed" {
        return Err(format!(
            "privacy.minimum_security '{}' is invalid (expected \"gateway\" or \"sealed\")",
            p.minimum_security
        ));
    }
    Ok(())
}

/// Rank for `RouteConfig::security_mode`/`PrivacyConfig::minimum_security`
/// ordering comparisons (design §113.2: "sealed > gateway"). Callers only
/// ever pass an already-validated value (`validate()` runs the {gateway,
/// sealed} value check on both fields before any ranking comparison); any
/// other string ranks as `gateway`'s floor (0) defensively rather than
/// panicking, since a rank comparison must never be the thing that panics
/// on operator input.
fn security_rank(mode: &str) -> u8 {
    match mode {
        "sealed" => 1,
        _ => 0,
    }
}

/// Design §3/§113.2 validation specific to a `security_mode: sealed` route,
/// run only when `r.security_mode == "sealed"` (see `validate`'s routes
/// loop). Two --check-config rejections (design §3's downgrade-refusal
/// list, items b/c):
///
/// (b) EVERY destination must be a `fed:<peer>/<route>` destination --
///     sealed routing requires a federation peer this cycle (a plaintext
///     local plugin is not a sealed-capable endpoint: it's the plaintext
///     edge sealing exists to protect against, design §113.1/§3).
/// (c) each such peer must carry a CONFIG-PINNED `sealed_key` --
///     `--check-config` cannot see advert-learned keys (those only exist at
///     runtime, once a peer connection has actually exchanged adverts), so
///     sealed egress can only pass config-time validation when the peer's
///     key is pinned in `federation.peers[].sealed_key` (design §1/§113.2).
///     An advert-learned key alone is a Task 4 runtime concern, not a
///     --check-config pass condition.
///
/// Runs AFTER `validate_fed_destination` has already accepted every `fed:`
/// destination on this route (same loop, called earlier per destination) --
/// so by the time this runs, any non-fed destination has NOT yet been
/// caught (fed-ness is exactly what this function's first check adds), but
/// every `fed:` destination it does see is already known to name a
/// configured peer with a well-formed `<peer>/<route>` shape.
fn validate_sealed_route(cfg: &Config, r: &RouteConfig) -> Result<(), String> {
    for ep in &r.destinations {
        if ep.protocol != FED_PROTOCOL {
            return Err(format!(
                "route '{}' has security_mode 'sealed' but destination '{}:{}' is not a fed:<peer> \
                 destination (sealed routing requires every destination to be a federation peer this \
                 cycle -- a plaintext local plugin cannot be a sealed endpoint, design §3/§113.1)",
                r.name, ep.protocol, ep.endpoint
            ));
        }
        let Some((peer_name, _remote_route)) = ep.endpoint.split_once('/') else {
            // Malformed shape -- `validate_fed_destination` (called earlier
            // in the same routes-loop iteration) already rejected this.
            continue;
        };
        let Some(peer) =
            cfg.federation.as_ref().and_then(|fed| fed.peers.iter().find(|p| p.name == peer_name))
        else {
            // Unknown peer / absent federation block -- likewise already
            // rejected by `validate_fed_destination`.
            continue;
        };
        if peer.sealed_key.is_none() {
            return Err(format!(
                "route '{}' has security_mode 'sealed' to peer '{}' which has no config-pinned \
                 sealed_key -- --check-config cannot see advert-learned keys at load time, so a \
                 sealed destination requires federation.peers[].sealed_key to be set for this peer \
                 (design §1/§113.2)",
                r.name, peer_name
            ));
        }
    }
    Ok(())
}

/// Design §1/§4 validation for `discovery` (SPEC §111.5/§112.2, cycle G).
/// Unlike `federation`, `discovery` is never absent -- `Config::discovery`
/// defaults to `DiscoveryConfig::default()` (`mode: "disabled"`) via
/// `#[serde(default)]`, so this runs unconditionally; every pre-cycle-G
/// config (no `discovery:` block at all) validates against those defaults
/// and passes trivially.
fn validate_discovery(cfg: &Config) -> Result<(), String> {
    let d = &cfg.discovery;
    match d.mode.as_str() {
        "disabled" | "federation" | "public" => {}
        "local" => {
            return Err(
                "discovery.mode 'local' is reserved for a future cycle (no LAN transport exists \
                 yet); use \"disabled\", \"federation\", or \"public\""
                    .to_string(),
            );
        }
        other => {
            return Err(format!(
                "discovery.mode '{other}' is invalid (expected \"disabled\", \"federation\", or \"public\")"
            ));
        }
    }
    if d.advert_ttl_secs < 300 {
        return Err(format!(
            "discovery.advert_ttl_secs {} is below the minimum of 300",
            d.advert_ttl_secs
        ));
    }
    // Ceiling matches `fed::conn::ADVERT_MAX_FUTURE_SECS` (24h), the same
    // bound a receiving peer clamps an incoming advert's `expires` down to
    // (Task 1/3 review, carried minor): without this, a configured TTL
    // above 24h would silently diverge from what every peer actually
    // observes/serves on receipt, rather than being rejected up front.
    if d.advert_ttl_secs > 86_400 {
        return Err(format!(
            "discovery.advert_ttl_secs {} is above the maximum of 86400 (24h -- matches the \
             receive-side far-future clamp)",
            d.advert_ttl_secs
        ));
    }
    if d.mode == "public" && !cfg.node.public {
        return Err(
            "discovery.mode 'public' requires node.public: true (§112.2 pairing)".to_string(),
        );
    }
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
        if let Some(sealed_key) = &p.sealed_key {
            if !is_valid_hex64(sealed_key) {
                return Err(format!(
                    "federation peer '{}' has invalid sealed_key '{}' (expected 64 hex chars)",
                    p.name, sealed_key
                ));
            }
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

/// Whether `c` is unsafe in a `node.name` (final cycle-G review finding --
/// see `validate`'s `node.name` check for why this must be enforced at
/// config load, not just on a received peer advert). Deliberately mirrors
/// -- NOT shares -- `fed::conn::sanitize_advert_name`'s predicate
/// (`char::is_control()` plus `fed::conn::is_display_spoofing`'s exact
/// codepoint set): `config.rs` has no dependency on `fed` today and
/// shouldn't grow one for a single character-class predicate, so this is
/// intentionally duplicated rather than imported. Keep the two in sync if
/// either changes: `char::is_control()` (C0 incl. ESC, DEL, C1) plus the
/// same bidi-control (`\u{061C}`, `\u{200E}`-`\u{200F}`,
/// `\u{202A}`-`\u{202E}`, `\u{2066}`-`\u{2069}`) and default-ignorable
/// (`\u{200B}`-`\u{200D}`, `\u{FEFF}`, `\u{2060}`) codepoints
/// `is_display_spoofing` blocks.
fn is_unsafe_advert_name_char(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{061C}'
                | '\u{200E}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{200B}'..='\u{200D}'
                | '\u{FEFF}'
                | '\u{2060}')
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

/// Bare 64-hex-char format check, no `"rf:"` prefix (design §1, cycle H):
/// the shape `fed::advert::SecurityCaps::sealed_key` and `PeerConfig::
/// sealed_key` both use -- a raw X25519 public key, not a node identity, so
/// it deliberately does NOT reuse `is_valid_rf_node_id`'s prefix.
fn is_valid_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
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

    // ---- node.name (final cycle-G review finding) --------------------------

    #[test]
    fn node_name_within_limit_and_plain_ascii_is_valid() {
        let good = GOOD.replace("name: test-node", "name: Regional Gateway 12");
        let cfg = parse(&good).unwrap();
        assert_eq!(cfg.node.name, "Regional Gateway 12");
    }

    #[test]
    fn node_name_over_64_chars_is_rejected() {
        let long_name = "x".repeat(65);
        let bad = GOOD.replace("name: test-node", &format!("name: {long_name}"));
        let err = parse(&bad).unwrap_err();
        assert!(err.contains("node.name"), "err was: {err}");
        assert!(err.contains("65"), "err should name the length: {err}");
    }

    #[test]
    fn node_name_at_exactly_64_chars_is_valid() {
        let name = "x".repeat(64);
        let good = GOOD.replace("name: test-node", &format!("name: {name}"));
        let cfg = parse(&good).unwrap();
        assert_eq!(cfg.node.name.chars().count(), 64);
    }

    #[test]
    fn node_name_with_a_control_char_is_rejected() {
        // ESC (the byte that starts every ANSI/CSI escape sequence) embedded
        // in an otherwise-normal name -- YAML double-quoted scalar so \x1b
        // survives as a literal control byte in the parsed string.
        let bad = GOOD.replace("name: test-node", "name: \"evil\\x1bname\"");
        let err = parse(&bad).unwrap_err();
        assert!(err.contains("node.name"), "err was: {err}");
        assert!(err.contains("unsafe character"), "err was: {err}");
    }

    #[test]
    fn node_name_with_a_newline_is_rejected() {
        let bad = GOOD.replace("name: test-node", "name: \"line one\\nline two\"");
        let err = parse(&bad).unwrap_err();
        assert!(err.contains("node.name"), "err was: {err}");
    }

    #[test]
    fn node_name_with_an_rlo_bidi_override_is_rejected() {
        // U+202E RLO -- the same display-spoofing codepoint
        // `fed::conn::is_display_spoofing` blocks on a RECEIVED advert's
        // name; this proves our OWN node.name gets the same treatment
        // before it's ever signed into a wire advert.
        let bad = GOOD.replace("name: test-node", "name: \"evil\\u202Ename\"");
        let err = parse(&bad).unwrap_err();
        assert!(err.contains("node.name"), "err was: {err}");
        assert!(err.contains("unsafe character"), "err was: {err}");
    }

    // The shipped `docs/relayfabric.example.yaml` node.name
    // ("example-gateway") is already covered by
    // `example_config_has_no_federation_block_and_stays_valid` and
    // `example_config_has_no_discovery_block_and_stays_valid` below, both
    // of which call `validate(&cfg)` end to end -- no separate test needed
    // here, just confirmed by the final sweep's `--check-config` run too.

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

    // --- peer sealed_key (design §1, cycle H) ------------------------------

    #[test]
    fn federation_peer_sealed_key_defaults_to_none_when_absent() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n",
            a = node_id_a(),
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.federation.unwrap().peers[0].sealed_key, None);
    }

    #[test]
    fn federation_accepts_a_valid_peer_sealed_key() {
        let sealed_key = "11".repeat(32);
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n      sealed_key: \"{sk}\"\n",
            a = node_id_a(), sk = sealed_key,
        );
        let cfg = parse(&yaml).unwrap_or_else(|e| panic!("valid sealed_key should be accepted: {e}"));
        assert_eq!(cfg.federation.unwrap().peers[0].sealed_key, Some(sealed_key));
    }

    #[test]
    fn federation_rejects_peer_sealed_key_with_wrong_hex_length() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n      sealed_key: \"abcd\"\n",
            a = node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("sealed_key"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_peer_sealed_key_with_non_hex_characters() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n      sealed_key: \"{}\"\n",
            "zz".repeat(32), a = node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("sealed_key"), "err was: {err}");
    }

    #[test]
    fn federation_rejects_peer_sealed_key_with_rf_prefix() {
        // sealed_key is a bare X25519 public key, NOT a node identity --
        // the "rf:" node_id prefix must not be accepted here.
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      addr: \"10.0.0.2:47000\"\n      sealed_key: \"rf:{}\"\n",
            "11".repeat(32), a = node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("sealed_key"), "err was: {err}");
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
            messages_per_minute: 0, sealed_key: None,
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

    // ---- discovery (design §1/§4, SPEC §111.5/§112.2, cycle G) ------------

    #[test]
    fn discovery_block_absent_defaults_to_disabled_and_ttl_3600() {
        // v0.1/v0.2/pre-cycle-G config has no `discovery:` key at all.
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.discovery.mode, "disabled");
        assert_eq!(cfg.discovery.advert_ttl_secs, 3600);
    }

    #[test]
    fn example_config_has_no_discovery_block_and_stays_valid() {
        let raw = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/relayfabric.example.yaml"),
        ).unwrap();
        let cfg: Config = serde_yaml::from_str(&raw).unwrap();
        assert_eq!(cfg.discovery.mode, "disabled");
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn discovery_mode_federation_is_valid() {
        let yaml = format!("{GOOD}\ndiscovery:\n  mode: federation\n");
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.discovery.mode, "federation");
    }

    #[test]
    fn discovery_mode_public_with_node_public_true_is_valid() {
        let yaml = GOOD.replace(
            "node:\n  name: test-node\n  data_dir: /tmp/relayfabric-test",
            "node:\n  name: test-node\n  public: true\n  data_dir: /tmp/relayfabric-test",
        ) + "\npublic_services:\n  - name: svc\n    type: chat\n    ingress: [mocka, mockb]\n    \
           egress: [mocka, mockb]\ndiscovery:\n  mode: public\n";
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.discovery.mode, "public");
        assert!(cfg.node.public);
    }

    #[test]
    fn discovery_mode_public_without_node_public_is_rejected() {
        let yaml = format!("{GOOD}\ndiscovery:\n  mode: public\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("public"), "err was: {err}");
        assert!(err.contains("node.public"), "err was: {err}");
    }

    #[test]
    fn discovery_mode_local_is_rejected_as_reserved_for_a_future_cycle() {
        let yaml = format!("{GOOD}\ndiscovery:\n  mode: local\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("local"), "err was: {err}");
        assert!(err.contains("future"), "err should say 'future': {err}");
    }

    #[test]
    fn discovery_mode_garbage_is_rejected() {
        let yaml = format!("{GOOD}\ndiscovery:\n  mode: nonsense\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("nonsense"), "err was: {err}");
    }

    #[test]
    fn discovery_advert_ttl_secs_at_minimum_300_is_valid() {
        let yaml = format!("{GOOD}\ndiscovery:\n  mode: federation\n  advert_ttl_secs: 300\n");
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.discovery.advert_ttl_secs, 300);
    }

    #[test]
    fn discovery_advert_ttl_secs_below_300_is_rejected() {
        let yaml = format!("{GOOD}\ndiscovery:\n  mode: federation\n  advert_ttl_secs: 299\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("advert_ttl_secs"), "err was: {err}");
        assert!(err.contains("300"), "err was: {err}");
    }

    #[test]
    fn discovery_advert_ttl_secs_at_maximum_86400_is_valid() {
        let yaml = format!("{GOOD}\ndiscovery:\n  mode: federation\n  advert_ttl_secs: 86400\n");
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.discovery.advert_ttl_secs, 86400);
    }

    #[test]
    fn discovery_advert_ttl_secs_above_86400_is_rejected() {
        let yaml = format!("{GOOD}\ndiscovery:\n  mode: federation\n  advert_ttl_secs: 86401\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("advert_ttl_secs"), "err was: {err}");
        assert!(err.contains("86400"), "err was: {err}");
    }

    #[test]
    fn discovery_default_ttl_when_mode_disabled_needs_no_ttl_key() {
        // A discovery block that only sets `mode` still gets the 3600
        // default ttl, which is >= 300 -- no separate ttl key required.
        let yaml = format!("{GOOD}\ndiscovery:\n  mode: disabled\n");
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.discovery.advert_ttl_secs, 3600);
    }

    // ---- federation.peers[].messages_per_minute (carried from cycle F) ----

    #[test]
    fn peer_messages_per_minute_defaults_to_zero_unlimited() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      \
             addr: \"10.0.0.2:47000\"\n",
            a = node_id_a(),
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.federation.unwrap().peers[0].messages_per_minute, 0);
    }

    #[test]
    fn peer_messages_per_minute_explicit_value_is_accepted() {
        let yaml = format!(
            "{FED_BASE}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{a}\"\n      \
             addr: \"10.0.0.2:47000\"\n      messages_per_minute: 1\n",
            a = node_id_a(),
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.federation.unwrap().peers[0].messages_per_minute, 1);
    }

    // ---- security_mode + privacy floor (design §3, SPEC §113.1/§113.2, cycle H) ----

    #[test]
    fn security_mode_defaults_to_gateway_when_absent() {
        // v0.1/.../v0.3 (pre-cycle-H) config has no security_mode key at all.
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.routes[0].security_mode, "gateway");
    }

    #[test]
    fn security_mode_gateway_is_explicitly_accepted() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    security_mode: gateway",
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.routes[0].security_mode, "gateway");
    }

    #[test]
    fn security_mode_unknown_value_is_rejected() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    security_mode: opaque",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("general"), "err should name the route: {err}");
        assert!(err.contains("opaque"), "err should quote the bad value: {err}");
    }

    /// SPEC §113.1: `native` is documented as an alias of `gateway` today,
    /// not a distinct mode this cycle -- the rejection message must say so
    /// (not just "invalid value"), so an operator reading it knows exactly
    /// what to write instead.
    #[test]
    fn security_mode_native_is_rejected_as_an_alias_of_gateway_not_a_separate_mode() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    security_mode: native",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("native"), "err should quote the value: {err}");
        assert!(err.contains("alias"), "err should explain native is an alias of gateway: {err}");
        assert!(err.contains("gateway"), "err was: {err}");
    }

    #[test]
    fn allow_gateway_decryption_route_override_defaults_to_none() {
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.routes[0].allow_gateway_decryption, None);
    }

    #[test]
    fn allow_gateway_decryption_route_override_parses_explicit_false() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    allow_gateway_decryption: false",
        );
        let cfg = parse(&yaml).unwrap();
        assert_eq!(cfg.routes[0].allow_gateway_decryption, Some(false));
    }

    #[test]
    fn security_rank_orders_sealed_above_gateway() {
        assert!(security_rank("sealed") > security_rank("gateway"));
    }

    // ---- privacy floor (node-level, design §3, SPEC §113.2, cycle H) ------

    #[test]
    fn privacy_block_absent_defaults_to_no_floor() {
        // v0.1/.../v0.3 (pre-cycle-H) config has no privacy: key at all.
        let cfg = parse(GOOD).unwrap();
        assert_eq!(cfg.privacy.minimum_security, "gateway");
        assert!(cfg.privacy.allow_gateway_decryption);
        assert!(cfg.privacy.allow_protocol_downgrade);
    }

    #[test]
    fn privacy_allow_gateway_decryption_and_allow_protocol_downgrade_parse_explicit_false() {
        let yaml = format!(
            "{GOOD}\nprivacy:\n  allow_gateway_decryption: false\n  allow_protocol_downgrade: false\n"
        );
        let cfg = parse(&yaml).unwrap();
        assert!(!cfg.privacy.allow_gateway_decryption);
        assert!(!cfg.privacy.allow_protocol_downgrade);
    }

    #[test]
    fn privacy_minimum_security_invalid_value_is_rejected() {
        let yaml = format!("{GOOD}\nprivacy:\n  minimum_security: paranoid\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("minimum_security"), "err was: {err}");
        assert!(err.contains("paranoid"), "err was: {err}");
    }

    #[test]
    fn privacy_minimum_security_gateway_accepts_a_gateway_route() {
        // The default floor -- explicit here for clarity -- imposes no
        // restriction beyond what GOOD already validates.
        let yaml = format!("{GOOD}\nprivacy:\n  minimum_security: gateway\n");
        assert!(parse(&yaml).is_ok());
    }

    /// Downgrade-refusal rejection (a) (design §113.2): a `gateway` route
    /// loading under a `sealed` node floor is below the floor and must be
    /// rejected at --check-config, naming both the route and the floor.
    #[test]
    fn privacy_minimum_security_sealed_rejects_a_gateway_route() {
        let yaml = format!("{GOOD}\nprivacy:\n  minimum_security: sealed\n");
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("general"), "err should name the route: {err}");
        assert!(err.contains("gateway"), "err should name the route's mode: {err}");
        assert!(err.contains("sealed"), "err should name the floor: {err}");
        assert!(err.contains("floor"), "err should say 'floor': {err}");
    }

    /// Floor ordering (sealed > gateway): a `sealed` route to a peer with a
    /// config-pinned `sealed_key` satisfies a `sealed` node floor -- the
    /// floor check must not reject a route that already meets or exceeds it.
    #[test]
    fn privacy_minimum_security_sealed_accepts_a_sealed_route_to_a_keyed_peer() {
        let sealed_key = "33".repeat(32);
        let yaml = format!(
            "{}\nprivacy:\n  minimum_security: sealed\nfederation:\n  peers:\n    - name: phoenix\n      \
             node_id: \"{}\"\n      addr: \"10.0.0.2:47000\"\n      sealed_key: \"{}\"\n",
            GOOD.replace(
                "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
                "    destinations: [\"fed:phoenix/regional-chat\"]\n    security_mode: sealed",
            ),
            node_id_a(), sealed_key,
        );
        let cfg = parse(&yaml)
            .unwrap_or_else(|e| panic!("a sealed route to a keyed peer should satisfy a sealed floor: {e}"));
        assert_eq!(cfg.privacy.minimum_security, "sealed");
        assert_eq!(cfg.routes[0].security_mode, "sealed");
    }

    // ---- sealed routes require a fed: dest + a config-pinned peer key -----
    // (design §3's --check-config downgrade-refusal list, items b/c)

    /// Rejection (b): every destination on a `sealed` route must be a
    /// `fed:<peer>` destination -- GOOD's route has two plain plugin
    /// destinations, neither of which can be a sealed endpoint.
    #[test]
    fn sealed_route_to_a_non_fed_destination_is_rejected() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]\n    security_mode: sealed",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("general"), "err should name the route: {err}");
        assert!(err.contains("sealed"), "err was: {err}");
        assert!(err.contains("mocka:chan"), "err should name the offending destination: {err}");
    }

    /// Rejection (b), mixed case: one `fed:` destination and one plain
    /// plugin destination on the same `sealed` route -- still rejected
    /// (EVERY destination must be fed:, not just at least one).
    #[test]
    fn sealed_route_with_a_mix_of_fed_and_non_fed_destinations_is_rejected() {
        let yaml = format!(
            "{}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{}\"\n      \
             addr: \"10.0.0.2:47000\"\n      sealed_key: \"{}\"\n",
            GOOD.replace(
                "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
                "    destinations: [\"fed:phoenix/regional-chat\", \"mockb:chan\"]\n    security_mode: sealed",
            ),
            node_id_a(), "44".repeat(32),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("sealed"), "err was: {err}");
        assert!(err.contains("mockb:chan"), "err should name the non-fed destination: {err}");
    }

    /// Rejection (c): a `sealed` route to a `fed:` peer that has NO
    /// config-pinned `sealed_key` -- --check-config cannot see
    /// advert-learned keys, so this must fail even though the peer is
    /// otherwise fully configured (valid node_id/addr).
    #[test]
    fn sealed_route_to_fed_peer_without_a_configured_sealed_key_is_rejected() {
        let yaml = format!(
            "{}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{}\"\n      addr: \"10.0.0.2:47000\"\n",
            GOOD.replace(
                "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
                "    destinations: [\"fed:phoenix/regional-chat\"]\n    security_mode: sealed",
            ),
            node_id_a(),
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("general"), "err should name the route: {err}");
        assert!(err.contains("phoenix"), "err should name the peer: {err}");
        assert!(err.contains("sealed_key"), "err was: {err}");
    }

    /// Positive control for rejection (c): the same route/peer, but with a
    /// config-pinned `sealed_key` this time -- must pass.
    #[test]
    fn sealed_route_to_fed_peer_with_a_configured_sealed_key_is_accepted() {
        let sealed_key = "22".repeat(32);
        let yaml = format!(
            "{}\nfederation:\n  peers:\n    - name: phoenix\n      node_id: \"{}\"\n      \
             addr: \"10.0.0.2:47000\"\n      sealed_key: \"{}\"\n",
            GOOD.replace(
                "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
                "    destinations: [\"fed:phoenix/regional-chat\"]\n    security_mode: sealed",
            ),
            node_id_a(), sealed_key,
        );
        parse(&yaml).unwrap_or_else(|e| panic!("sealed route to a keyed peer should be valid: {e}"));
    }

    /// Rejection (b) takes priority when `federation` is entirely absent --
    /// same posture as the plain (non-sealed) `fed_destination_is_rejected_
    /// when_federation_block_is_absent` test above, just confirming a
    /// `sealed` route doesn't bypass that check.
    #[test]
    fn sealed_route_to_fed_destination_with_no_federation_block_is_rejected() {
        let yaml = GOOD.replace(
            "    destinations: [\"mocka:chan\", \"mockb:chan\"]",
            "    destinations: [\"fed:phoenix/regional-chat\"]\n    security_mode: sealed",
        );
        let err = parse(&yaml).unwrap_err();
        assert!(err.contains("general"), "err should name the route: {err}");
        assert!(err.contains("federation"), "err was: {err}");
    }

    /// v0.2 example config carries no `security_mode`/`privacy` keys at
    /// all -- every route must keep defaulting to "gateway" and the node
    /// floor must keep defaulting to no restriction, exactly as before this
    /// task's additions.
    #[test]
    fn example_config_has_no_privacy_block_and_every_route_defaults_to_gateway() {
        let raw = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/relayfabric.example.yaml"),
        ).unwrap();
        let cfg: Config = serde_yaml::from_str(&raw).unwrap();
        assert_eq!(cfg.privacy.minimum_security, "gateway");
        assert!(cfg.privacy.allow_gateway_decryption);
        assert!(cfg.privacy.allow_protocol_downgrade);
        for r in &cfg.routes {
            assert_eq!(r.security_mode, "gateway", "route '{}' should default to gateway", r.name);
            assert_eq!(r.allow_gateway_decryption, None, "route '{}' should default to None", r.name);
        }
        assert!(validate(&cfg).is_ok());
    }
}
