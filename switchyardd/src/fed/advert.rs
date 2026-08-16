//! Node Advertisements (design doc §1, SPEC §111.1, cycle G): a signed,
//! expiring capability document describing what a gateway can actually
//! do -- services (chat/store_forward/telemetry/federation...), the
//! protocols reaching each, and the security posture (translate/signed/
//! opaque). Mirrors `fed/sign.rs`'s structure: an explicit canonical-bytes
//! tuple (never the struct's own `Serialize`, so a future field addition
//! to `Advert` can never silently perturb what gets signed), a
//! domain-separated sign/verify pair (`fed/domains.rs::ADVERT_V1`), and a
//! golden vector locking the canonical encoding across versions.
//!
//! `build_from_config` is the other half: turning `Config` into an
//! `Advert` at config-LOAD time, from config-level facts only -- SPEC
//! §111.4's privacy invariant (tested below, `sentinel` sweep). Consumed
//! by fed exchange (`fed::conn`, Task 2: sign+send on connection-up and
//! on the refresh timer) and admin `GET /v1/discovery` (Task 3).
//!
//! Nothing outside this module's own tests calls any of the below yet --
//! consumed by fed exchange Task 2 (`build_from_config`/`sign` on
//! connection-up and the refresh timer, `verify` on the receive path) and
//! admin Task 3 (`GET /v1/discovery` serving verified stored adverts). A
//! single module-level `allow` here rather than one per item.
#![allow(dead_code)]

use super::domains;
use crate::config::Config;
use crate::node_identity::{self, NodeIdentity};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// A signed, expiring Node Advertisement (SPEC §111.1). `sig` is empty on
/// a freshly `build_from_config`'d advert -- `sign` fills it in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Advert {
    pub rf_version: u32,
    /// `"rf:" + 64 hex chars` -- the advertising node's own identity
    /// (`node_identity::NodeIdentity::node_id`).
    pub node_id: String,
    /// `node.name` verbatim (design §1). No length/charset validation is
    /// enforced by this cycle's `config::validate` -- an operator-chosen
    /// display string, carried through as-is.
    pub name: String,
    /// Service CLASSES (design §111.2: "chat"/"store_forward"/"telemetry"/
    /// ...), keyed by `PublicService::type` -- NEVER `PublicService::name`
    /// or any `RouteConfig::name` (§111.4: no route names beyond the
    /// service classes a `public_services` entry explicitly publishes).
    /// `"federation"` is always present (design §1: the node always
    /// carries federation, whether or not it publishes any service).
    pub services: BTreeMap<String, bool>,
    /// Protocol families reachable for those services, keyed by protocol
    /// name (e.g. `"lxmf"`) -- the union of every `public_services[].
    /// ingress`/`egress` list.
    pub protocols: BTreeMap<String, ProtoCaps>,
    pub security: SecurityCaps,
    /// Unix seconds this advert is no longer valid.
    pub expires: i64,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// Per-protocol capability flags (design §1). `files`/`max_payload` are
/// always `false`/`None` this cycle -- SOURCING RULE: an advert must be
/// buildable from `Config` alone at config-load time, never from a live
/// plugin handle, so there is no live "does this plugin actually support
/// attachments, and what's its max payload" fact available yet to source
/// these from. Live-capability enrichment (reading each enabled plugin's
/// declared attachment/max-payload capability) is future work, not this
/// cycle's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoCaps {
    /// This protocol appears in at least one `public_services[].ingress`.
    pub rx: bool,
    /// This protocol appears in at least one `public_services[].egress`.
    pub tx: bool,
    pub text: bool,
    pub files: bool,
    pub max_payload: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityCaps {
    pub translate: bool,
    pub signed: bool,
    pub opaque: bool,
}

/// Advert verification failures (mirrors `fed::sign::SigError`'s posture:
/// any failure here means the caller must reject/not-serve the advert).
#[derive(Debug, PartialEq, Eq)]
pub enum AdvertError {
    /// `expires` was <= 0 -- a shape sanity check on the field, not a
    /// wall-clock freshness check. Whether the advert is still fresh
    /// (`expires` greater than the current time) is the RECEIVE path's
    /// job (fed::conn, Task 2), since it needs the current time and this
    /// function deliberately doesn't take one -- `verify` only ever
    /// checks facts intrinsic to the advert itself.
    InvalidExpiry,
    /// The signature did not verify against `node_id`'s key over the
    /// domain-separated canonical bytes.
    BadSignature,
}

impl fmt::Display for AdvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvertError::InvalidExpiry => write!(f, "advert has a non-positive expires"),
            AdvertError::BadSignature => write!(f, "advert signature did not verify"),
        }
    }
}

impl std::error::Error for AdvertError {}

/// Deterministic CBOR tuple of the fields an advert signature covers
/// (design §1): `(rf_version, node_id, name, services, protocols,
/// (translate, signed, opaque), expires)`. `sig` is NOT included --
/// self-referential otherwise. Built as an explicit tuple, not by
/// serializing `Advert` itself, for the same reason `fed::sign::
/// canonical_bytes` is: a future field added to `Advert` must never
/// silently join or reorder what gets signed. `services`/`protocols`
/// being `BTreeMap`s gives deterministic (sorted) key order for free;
/// `security` is flattened to a raw bool tuple rather than letting
/// `SecurityCaps`'s own derived `Serialize` decide the encoding, so this
/// function -- not that struct's field order -- is the single source of
/// truth for the signed byte layout.
pub fn canonical_bytes(advert: &Advert) -> Vec<u8> {
    let tuple = (
        advert.rf_version,
        advert.node_id.as_str(),
        advert.name.as_str(),
        &advert.services,
        &advert.protocols,
        (advert.security.translate, advert.security.signed, advert.security.opaque),
        advert.expires,
    );
    let mut buf = Vec::new();
    ciborium::into_writer(&tuple, &mut buf)
        .expect("canonical tuple of primitive/collection fields always serializes");
    buf
}

/// `domains::ADVERT_V1 || canonical_bytes` -- the bytes an advert
/// signature actually covers. Duplicated from `fed::sign::
/// domain_separated` rather than shared (that helper is private to
/// `sign.rs`); same one-line concatenation every domain-separated signing
/// context in `fed/` uses.
fn advert_bytes(advert: &Advert) -> Vec<u8> {
    let canonical = canonical_bytes(advert);
    let mut msg = Vec::with_capacity(domains::ADVERT_V1.len() + canonical.len());
    msg.extend_from_slice(domains::ADVERT_V1);
    msg.extend_from_slice(&canonical);
    msg
}

/// Signs `advert` with `identity`, filling in `sig` (design §1: Ed25519
/// over `domains::ADVERT_V1`-prefixed canonical bytes). Consumes and
/// returns the advert -- the natural shape here, unlike
/// `sign::sign_origin`'s separate `OriginSig` return, since `Advert`
/// carries its own `sig` field directly rather than nesting a sub-struct.
pub fn sign(mut advert: Advert, identity: &NodeIdentity) -> Advert {
    advert.sig = identity.sign(&advert_bytes(&advert));
    advert
}

/// Verifies `advert.sig` against `advert.node_id`'s key over the
/// domain-separated canonical bytes, plus the `expires > 0` shape sanity
/// check (see `AdvertError::InvalidExpiry`'s doc comment for why that's
/// not a freshness check).
pub fn verify(advert: &Advert) -> Result<(), AdvertError> {
    if advert.expires <= 0 {
        return Err(AdvertError::InvalidExpiry);
    }
    if node_identity::verify(&advert.node_id, &advert_bytes(advert), &advert.sig) {
        Ok(())
    } else {
        Err(AdvertError::BadSignature)
    }
}

/// Builds this node's own (unsigned) advert from `cfg` -- design §1's
/// content-sourcing rule, tested exhaustively below (`build_from_config`
/// test module) alongside the §111.4 privacy sentinel sweep.
///
/// `None` when discovery is off (`cfg.discovery.mode == "disabled"`,
/// which is also the default for every pre-cycle-G config that has no
/// `discovery:` block at all -- `Config::discovery`'s `#[serde(default)]`
/// takes care of that).
///
/// Otherwise: `services` is the union of every `public_services[].type`
/// (never `.name` -- see `Advert::services`'s doc comment) plus
/// `"federation": true` unconditionally, so an empty `public_services`
/// still yields `{"federation": true}` (design §1: "it exists, carries
/// nothing publishable"). `protocols` is keyed by every protocol name
/// appearing in any `public_services[].ingress`/`.egress` list, with
/// `rx`/`tx` set independently per list membership; `text: true`,
/// `files: false`, `max_payload: None` for all of them this cycle (see
/// `ProtoCaps`'s doc comment -- live-capability enrichment is future
/// work, so this function reads only `cfg.public_services`, never
/// `cfg.plugins`, to build the protocols map). `security` is the fixed
/// `{translate: true, signed: true, opaque: false}` this cycle ships
/// (`opaque` becomes real in cycle H). `expires` is `now +
/// cfg.discovery.advert_ttl_secs`.
///
/// Trusts `cfg` is already `config::validate`d, same posture every other
/// `Config`-consuming function in this codebase takes -- in particular it
/// does NOT itself check `mode: "public"` requires `node.public`; that's
/// `validate`'s job, enforced before a `Config` this function ever sees
/// can exist.
pub fn build_from_config(cfg: &Config, node_id: &str, now: DateTime<Utc>) -> Option<Advert> {
    if cfg.discovery.mode == "disabled" {
        return None;
    }

    let mut services: BTreeMap<String, bool> = BTreeMap::new();
    services.insert("federation".to_string(), true);
    for svc in &cfg.public_services {
        services.insert(svc.r#type.clone(), true);
    }

    let mut rx: BTreeSet<&str> = BTreeSet::new();
    let mut tx: BTreeSet<&str> = BTreeSet::new();
    for svc in &cfg.public_services {
        rx.extend(svc.ingress.iter().map(String::as_str));
        tx.extend(svc.egress.iter().map(String::as_str));
    }
    let protocols: BTreeMap<String, ProtoCaps> = rx
        .union(&tx)
        .map(|proto| {
            (
                proto.to_string(),
                ProtoCaps {
                    rx: rx.contains(proto),
                    tx: tx.contains(proto),
                    text: true,
                    files: false,
                    max_payload: None,
                },
            )
        })
        .collect();

    let expires = (now + Duration::seconds(cfg.discovery.advert_ttl_secs as i64)).timestamp();

    Some(Advert {
        rf_version: 1,
        node_id: node_id.to_string(),
        name: cfg.node.name.clone(),
        services,
        protocols,
        security: SecurityCaps { translate: true, signed: true, opaque: false },
        expires,
        sig: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn identity(dir: &std::path::Path, name: &str) -> NodeIdentity {
        NodeIdentity::load_or_create(&dir.join(name)).unwrap()
    }

    fn fixed_advert() -> Advert {
        let mut services = BTreeMap::new();
        services.insert("chat".to_string(), true);
        services.insert("federation".to_string(), true);

        let mut protocols = BTreeMap::new();
        protocols.insert(
            "lxmf".to_string(),
            ProtoCaps { rx: true, tx: true, text: true, files: false, max_payload: None },
        );

        Advert {
            rf_version: 1,
            node_id: format!("rf:{}", "ab".repeat(32)),
            name: "DX.PE Pasadena".to_string(),
            services,
            protocols,
            security: SecurityCaps { translate: true, signed: true, opaque: false },
            expires: 1_786_838_400,
            sig: Vec::new(),
        }
    }

    // --- golden vector -----------------------------------------------

    #[test]
    fn canonical_bytes_golden_vector_is_locked() {
        let advert = fixed_advert();
        let hex: String =
            canonical_bytes(&advert).iter().map(|b| format!("{b:02x}")).collect();
        // Cross-version stability lock (design §1): if this ever changes,
        // that's a breaking wire-format event for advert signing, not a
        // test to casually update.
        let expected = "8701784372663a616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626e44582e5045205061736164656e61a26463686174f56a66656465726174696f6ef5a1646c786d66a5627278f5627478f56474657874f56566696c6573f46b6d61785f7061796c6f6164f683f5f5f41a6a80fd80";
        assert_eq!(hex, expected);
    }

    // --- sign/verify round-trip ----------------------------------------

    #[test]
    fn sign_and_verify_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut advert = fixed_advert();
        advert.node_id = id.node_id();
        let signed = sign(advert, &id);
        assert_eq!(verify(&signed), Ok(()));
        assert!(!signed.sig.is_empty());
    }

    #[test]
    fn verify_fails_for_non_positive_expires() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut advert = fixed_advert();
        advert.node_id = id.node_id();
        advert.expires = 0;
        let signed = sign(advert, &id);
        assert_eq!(verify(&signed), Err(AdvertError::InvalidExpiry));
    }

    // --- tamper matrix ---------------------------------------------------

    #[test]
    fn tamper_name_after_signing_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut advert = fixed_advert();
        advert.node_id = id.node_id();
        let mut signed = sign(advert, &id);
        assert_eq!(verify(&signed), Ok(()));

        signed.name.push('!');
        assert_eq!(verify(&signed), Err(AdvertError::BadSignature));
    }

    #[test]
    fn tamper_services_after_signing_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut advert = fixed_advert();
        advert.node_id = id.node_id();
        let mut signed = sign(advert, &id);
        assert_eq!(verify(&signed), Ok(()));

        signed.services.insert("store_forward".to_string(), true);
        assert_eq!(verify(&signed), Err(AdvertError::BadSignature));
    }

    #[test]
    fn tamper_protocols_after_signing_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut advert = fixed_advert();
        advert.node_id = id.node_id();
        let mut signed = sign(advert, &id);
        assert_eq!(verify(&signed), Ok(()));

        signed.protocols.get_mut("lxmf").unwrap().files = true;
        assert_eq!(verify(&signed), Err(AdvertError::BadSignature));
    }

    #[test]
    fn tamper_security_after_signing_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut advert = fixed_advert();
        advert.node_id = id.node_id();
        let mut signed = sign(advert, &id);
        assert_eq!(verify(&signed), Ok(()));

        signed.security.opaque = true;
        assert_eq!(verify(&signed), Err(AdvertError::BadSignature));
    }

    #[test]
    fn tamper_expires_after_signing_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut advert = fixed_advert();
        advert.node_id = id.node_id();
        let mut signed = sign(advert, &id);
        assert_eq!(verify(&signed), Ok(()));

        signed.expires += 1;
        assert_eq!(verify(&signed), Err(AdvertError::BadSignature));
    }

    #[test]
    fn tamper_node_id_after_signing_fails_verification() {
        // Re-pointing node_id to a DIFFERENT real identity's key must also
        // fail -- not just "no key parses" but "wrong key doesn't verify".
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let other = identity(dir.path(), "other");
        let mut advert = fixed_advert();
        advert.node_id = id.node_id();
        let mut signed = sign(advert, &id);
        assert_eq!(verify(&signed), Ok(()));

        signed.node_id = other.node_id();
        assert_eq!(verify(&signed), Err(AdvertError::BadSignature));
    }

    #[test]
    fn tamper_signature_byte_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut advert = fixed_advert();
        advert.node_id = id.node_id();
        let mut signed = sign(advert, &id);
        assert_eq!(verify(&signed), Ok(()));

        signed.sig[0] ^= 0xFF;
        assert_eq!(verify(&signed), Err(AdvertError::BadSignature));
    }

    // --- domain-prefix test ----------------------------------------------

    #[test]
    fn advert_signature_without_domain_prefix_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "origin");
        let mut advert = fixed_advert();
        advert.node_id = id.node_id();
        let raw_sig = id.sign(&canonical_bytes(&advert)); // no domain prefix
        advert.sig = raw_sig;
        assert_eq!(verify(&advert), Err(AdvertError::BadSignature));
    }

    // --- build_from_config sourcing matrix (design §1) --------------------

    fn base_yaml() -> &'static str {
        r#"
node:
  name: test-node
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
"#
    }

    fn now() -> DateTime<Utc> {
        "2026-08-16T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn build_from_config_is_none_when_discovery_block_absent() {
        let cfg = config::load_from_str(base_yaml()).unwrap();
        assert!(cfg.discovery.mode == "disabled");
        assert!(build_from_config(&cfg, "rf:whatever", now()).is_none());
    }

    #[test]
    fn build_from_config_is_none_when_discovery_mode_explicitly_disabled() {
        let yaml = format!("{}\ndiscovery:\n  mode: disabled\n", base_yaml());
        let cfg = config::load_from_str(&yaml).unwrap();
        assert!(build_from_config(&cfg, "rf:whatever", now()).is_none());
    }

    #[test]
    fn build_from_config_with_empty_public_services_advertises_federation_only() {
        let yaml = format!("{}\ndiscovery:\n  mode: federation\n", base_yaml());
        let cfg = config::load_from_str(&yaml).unwrap();
        let advert = build_from_config(&cfg, "rf:whatever", now()).unwrap();
        assert_eq!(advert.services, BTreeMap::from([("federation".to_string(), true)]));
        assert!(advert.protocols.is_empty());
    }

    #[test]
    fn build_from_config_with_full_public_services_sources_services_and_protocols() {
        let yaml = format!(
            "{}\ndiscovery:\n  mode: federation\npublic_services:\n  - name: regional-chat\n    \
             type: chat\n    ingress: [mocka]\n    egress: [mockb]\n  - name: telemetry-svc\n    \
             type: telemetry\n    ingress: [mockb]\n    egress: []\n",
            base_yaml()
        );
        let cfg = config::load_from_str(&yaml).unwrap();
        let advert = build_from_config(&cfg, "rf:whatever", now()).unwrap();

        assert_eq!(
            advert.services,
            BTreeMap::from([
                ("federation".to_string(), true),
                ("chat".to_string(), true),
                ("telemetry".to_string(), true),
            ])
        );
        // mocka: ingress-only in regional-chat, but ALSO listed as
        // telemetry-svc's ingress -- still rx-only (never appears in any
        // egress list).
        assert_eq!(
            advert.protocols.get("mocka"),
            Some(&ProtoCaps { rx: true, tx: false, text: true, files: false, max_payload: None })
        );
        // mockb: egress in regional-chat AND ingress in telemetry-svc --
        // union means both rx and tx end up true.
        assert_eq!(
            advert.protocols.get("mockb"),
            Some(&ProtoCaps { rx: true, tx: true, text: true, files: false, max_payload: None })
        );
    }

    #[test]
    fn build_from_config_uses_node_name_and_passed_in_node_id() {
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
  - name: regional-chat
    type: chat
    ingress: [mocka]
    egress: [mockb]
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
discovery:
  mode: public
"#;
        let cfg = config::load_from_str(yaml).unwrap();
        let advert = build_from_config(&cfg, "rf:distinct-node-id", now()).unwrap();
        assert_eq!(advert.name, "test-node");
        assert_eq!(advert.node_id, "rf:distinct-node-id");
    }

    #[test]
    fn build_from_config_security_is_the_fixed_cycle_g_posture() {
        let yaml = format!("{}\ndiscovery:\n  mode: federation\n", base_yaml());
        let cfg = config::load_from_str(&yaml).unwrap();
        let advert = build_from_config(&cfg, "rf:whatever", now()).unwrap();
        assert_eq!(
            advert.security,
            SecurityCaps { translate: true, signed: true, opaque: false }
        );
    }

    #[test]
    fn build_from_config_expires_is_now_plus_advert_ttl_secs() {
        let yaml = format!(
            "{}\ndiscovery:\n  mode: federation\n  advert_ttl_secs: 900\n",
            base_yaml()
        );
        let cfg = config::load_from_str(&yaml).unwrap();
        let advert = build_from_config(&cfg, "rf:whatever", now()).unwrap();
        assert_eq!(advert.expires, now().timestamp() + 900);
    }

    #[test]
    fn build_from_config_default_ttl_is_3600() {
        let yaml = format!("{}\ndiscovery:\n  mode: federation\n", base_yaml());
        let cfg = config::load_from_str(&yaml).unwrap();
        let advert = build_from_config(&cfg, "rf:whatever", now()).unwrap();
        assert_eq!(advert.expires, now().timestamp() + 3600);
    }

    // --- §111.4 privacy sentinel sweep ------------------------------------

    fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The sentinel test SPEC §111.4/design §1 exists for: a config
    /// carrying plugin secrets, a native-ref-looking value, and a
    /// filesystem socket path buried in a plugin's `config:` block (none
    /// of which `build_from_config` ever reads -- it only touches
    /// `cfg.node.name`, `cfg.discovery`, and `cfg.public_services`) must
    /// produce a serialized advert that contains NONE of those bytes,
    /// anywhere -- not just structurally absent from named fields, but
    /// absent from the raw wire bytes a receiver would actually see.
    #[test]
    fn advert_bytes_never_leak_plugin_secrets_native_refs_or_socket_paths() {
        const SECRET: &str = "SENTINEL-SECRET-SIGNAL-CLI-TOKEN-DO-NOT-LEAK";
        const NATIVE_REF: &str = "+15559998888";
        const SOCKET_PATH: &str = "/var/lib/relayfabric/very-secret-plugins.sock";

        let yaml = format!(
            r#"
node:
  name: sentinel-node
  data_dir: /tmp/relayfabric-test
plugins:
  mocka:
    enabled: true
    config:
      token: "{SECRET}"
      account: "{NATIVE_REF}"
      socket_path: "{SOCKET_PATH}"
  mockb:
    enabled: true
public_services:
  - name: regional-chat
    type: chat
    ingress: [mocka]
    egress: [mockb]
discovery:
  mode: federation
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#
        );
        let cfg = config::load_from_str(&yaml).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let id = identity(dir.path(), "sentinel");
        let advert = build_from_config(&cfg, &id.node_id(), now()).unwrap();
        let signed = sign(advert, &id);

        let mut serialized = Vec::new();
        ciborium::into_writer(&signed, &mut serialized).unwrap();

        for sentinel in [SECRET, NATIVE_REF, SOCKET_PATH, "general", "regional-chat"] {
            assert!(
                !bytes_contain(&serialized, sentinel.as_bytes()),
                "advert bytes leaked sentinel value {sentinel:?}"
            );
        }
    }
}
