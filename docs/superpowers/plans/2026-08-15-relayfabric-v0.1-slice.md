# RelayFabric v0.1 Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `switchyardd` + `switchyardctl` + plugin IPC, proven end-to-end with in-test mock plugins and a real MQTT plugin.

**Architecture:** Cargo workspace. Out-of-process plugins connect to the daemon over a Unix socket speaking length-prefixed CBOR frames (Plugin Protocol v1). The daemon normalizes inbound messages to the canonical envelope, dedups, routes (deny-by-default, ingress echo excluded), applies policy + capability transforms with HMAC route-scoped pseudonyms, and persists per-destination deliveries in SQLite with retry/backoff/TTL/DLQ. An axum admin API + Prometheus metrics is served on a second Unix socket; `switchyardctl` is a thin HTTP/1.0 client of it.

**Tech Stack:** Rust 2021, tokio, ciborium (CBOR), rusqlite (bundled), serde_yaml, uuid (v7), chrono, hmac+sha2, axum 0.8, rumqttc (MQTT plugin).

**Spec:** `docs/superpowers/specs/2026-08-15-relayfabric-v0.1-slice-design.md` (slice) and `docs/SPEC.md` (parent spec, § references below).

## Global Constraints

- Always pass `-j2` to cargo: `cargo build -j2`, `cargo test -j2`, `cargo clippy -j2`.
- Before EVERY commit: `cargo clippy -j2 --workspace --all-targets` must be warning-free; fix, don't allow.
- Commit messages: plain conventional style (`feat: …`, `test: …`). No AI/tool attribution of any kind.
- Plugin Protocol version is `1` everywhere (`relay_ipc::PROTOCOL_VERSION`).
- Logs and admin API responses NEVER include message bodies (spec §52). Log message IDs, routes, endpoints, sizes only.
- Deny by default: unrouted messages are dropped; unknown plugin names are refused at Hello (spec §38).
- Rust edition 2021 for every crate. Workspace-level dependency versions.
- Deliberate shortcuts carry a `// ponytail:` comment naming the ceiling and upgrade path.
- **Licensing:** no AGPL or restrictive/copyleft dependencies or copied code — permissive only (MIT/Apache-2.0/BSD/public domain); clean-room reimplement if a capability only exists under a restrictive license. Check the license of every crate before adding it. GPL software (e.g. signal-cli) may only ever be an external process over IPC, never linked. All deps pinned in this plan are MIT/Apache-2.0.

## File Structure

```
Cargo.toml                      workspace root
crates/relay-core/src/lib.rs    Envelope, Endpoint, Sender, Capabilities
crates/relay-ipc/src/lib.rs     frame codec + PluginToDaemon/DaemonToPlugin enums
switchyardd/src/main.rs         arg parse, startup sequence (§68)
switchyardd/src/config.rs       YAML config + --check-config validation (§58–59)
switchyardd/src/alias.rs        HMAC route-scoped pseudonyms + secret file (§20)
switchyardd/src/dedup.rs        TTL'd dedup cache (§28)
switchyardd/src/routes.rs       route matching, echo exclusion (§24)
switchyardd/src/policy.rs       policy engine: deny/drop_kinds/max_payload (§36–37)
switchyardd/src/transform.rs    "[ALIAS]\nbody" rendering + truncation (§17, §83)
switchyardd/src/storage.rs      SQLite messages/deliveries + queue queries (§40–41, §50)
switchyardd/src/queue.rs        backoff schedule + retry/DLQ decisions (§42–44)
switchyardd/src/metrics.rs      atomic counters + Prometheus text (§55)
switchyardd/src/engine.rs       ingress→route→queue→egress wiring, delivery pump
switchyardd/src/plugins.rs      plugin socket listener + process supervisor (§69)
switchyardd/src/admin.rs        axum admin API over UDS (§57)
switchyardd/tests/e2e.rs        end-to-end tests with in-test mock plugins
switchyardctl/src/main.rs       CLI over admin socket (§102)
plugins/mqtt/src/main.rs        relayfabric-mqtt (rumqttc, MQTT v5 no-local)
docs/relayfabric.example.yaml   annotated example config
```

Lessons folded in from the reviewed `rns-signal-gateway` (prior art): dedup key = hash(source|timestamp|content); deny-by-default membership; per-message error isolation so one bad frame never kills the daemon; atomic state writes; drop-with-note truncation; bounded fan-out.

---

### Task 1: Workspace scaffold + relay-core

**Files:**
- Create: `Cargo.toml` (workspace root), `.gitignore`
- Create: `crates/relay-core/Cargo.toml`, `crates/relay-core/src/lib.rs`

**Interfaces:**
- Produces (used by every later task):
  - `Endpoint { protocol: String, endpoint: String }` with `FromStr` (parses `"proto:endpoint"`, splitting on the FIRST `:`) and `Display` (`"proto:endpoint"`)
  - `Sender { native_ref: String }`
  - `Envelope { version: u8, id: Uuid, source: Endpoint, sender: Sender, kind: String, body: String, created_at/received_at/expires_at: DateTime<Utc>, reply_to: Option<Uuid>, hop_count: u8, hop_limit: u8 }` with `fn is_expired(&self, now: DateTime<Utc>) -> bool`
  - `Capabilities { text, direct_messages, groups, attachments, location, reactions, receipts, presence: bool, max_payload: Option<u64> }` implementing `Default` (all false, `text: true`, `max_payload: None`)

- [ ] **Step 1: Create workspace root**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/relay-core", "crates/relay-ipc", "switchyardd", "switchyardctl", "plugins/mqtt"]

[workspace.package]
edition = "2021"
license = "MIT"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
uuid = { version = "1", features = ["v7", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
tokio = { version = "1", features = ["full"] }
ciborium = "0.2"
rusqlite = { version = "0.32", features = ["bundled"] }
hmac = "0.12"
sha2 = "0.10"
hex = "0.4"
rand = "0.8"
axum = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
rumqttc = "0.24"
tempfile = "3"
relay-core = { path = "crates/relay-core" }
relay-ipc = { path = "crates/relay-ipc" }
```

`.gitignore`: `/target`

Comment out the not-yet-existing members (`crates/relay-ipc`, `switchyardd`, `switchyardctl`, `plugins/mqtt`) until their tasks create them — the workspace must build at every commit. Each later task uncomments its member.

`crates/relay-core/Cargo.toml`:
```toml
[package]
name = "relay-core"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
uuid.workspace = true
chrono.workspace = true
```

- [ ] **Step 2: Write the failing tests**

In `crates/relay-core/src/lib.rs` (types not yet written — tests first at the bottom):

```rust
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -j2 -p relay-core`
Expected: compile FAILURE (types not defined).

- [ ] **Step 4: Implement relay-core**

```rust
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -j2 -p relay-core`
Expected: 3 passed.

- [ ] **Step 6: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add Cargo.toml .gitignore crates/relay-core
git commit -m "feat: workspace scaffold and relay-core envelope types"
```

---

### Task 2: relay-ipc — frame codec + protocol messages

**Files:**
- Create: `crates/relay-ipc/Cargo.toml`, `crates/relay-ipc/src/lib.rs`
- Modify: root `Cargo.toml` (uncomment member)

**Interfaces:**
- Consumes: `relay_core::Capabilities`, `chrono::DateTime<Utc>`
- Produces:
  - `PROTOCOL_VERSION: u32 = 1`, `MAX_FRAME: u32 = 16 * 1024 * 1024`
  - `enum PluginToDaemon { Hello { plugin: String, version: String, protocol_version: u32, capabilities: Capabilities }, Inbound { endpoint: String, sender: String, kind: String, body: String, created_at: Option<DateTime<Utc>> }, DeliveryResult { corr: i64, delivered: bool, detail: Option<String> } }`
  - `enum DaemonToPlugin { HelloAck { protocol_version: u32, error: Option<String> }, Send { corr: i64, endpoint: String, kind: String, body: String }, Shutdown }`
  - `async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()>`
  - `async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> io::Result<T>`
  - `corr` is the daemon's delivery-row id: `Send.corr` must be echoed back verbatim in `DeliveryResult.corr` (one message can have several deliveries, even on one plugin).

- [ ] **Step 1: Create crate**

`crates/relay-ipc/Cargo.toml`:
```toml
[package]
name = "relay-ipc"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
relay-core.workspace = true
serde.workspace = true
chrono.workspace = true
ciborium.workspace = true
tokio = { workspace = true }
```

Uncomment `crates/relay-ipc` in the root workspace members.

- [ ] **Step 2: Write the failing tests**

Bottom of `crates/relay-ipc/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use relay_core::Capabilities;

    #[tokio::test]
    async fn roundtrips_a_frame() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let msg = PluginToDaemon::Hello {
            plugin: "mqtt".into(),
            version: "0.1.0".into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: Capabilities::default(),
        };
        write_frame(&mut a, &msg).await.unwrap();
        let got: PluginToDaemon = read_frame(&mut b).await.unwrap();
        match got {
            PluginToDaemon::Hello { plugin, protocol_version, .. } => {
                assert_eq!(plugin, "mqtt");
                assert_eq!(protocol_version, 1);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_oversize_frame() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // hand-write a header claiming a frame larger than MAX_FRAME
        use tokio::io::AsyncWriteExt;
        a.write_all(&(MAX_FRAME + 1).to_be_bytes()).await.unwrap();
        let got: std::io::Result<PluginToDaemon> = read_frame(&mut b).await;
        assert!(got.is_err());
    }

    #[tokio::test]
    async fn corr_survives_send_result_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, &DaemonToPlugin::Send {
            corr: 42, endpoint: "chan".into(), kind: "text".into(), body: "hi".into(),
        }).await.unwrap();
        let DaemonToPlugin::Send { corr, .. } = read_frame(&mut b).await.unwrap() else {
            panic!("wrong variant");
        };
        assert_eq!(corr, 42);
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -j2 -p relay-ipc`
Expected: compile FAILURE.

- [ ] **Step 4: Implement**

```rust
//! RelayFabric Plugin Protocol v1: 4-byte big-endian length prefix + CBOR body
//! over a Unix domain socket (spec §9). Language-neutral by construction.

use chrono::{DateTime, Utc};
use relay_core::Capabilities;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum PluginToDaemon {
    Hello {
        plugin: String,
        version: String,
        protocol_version: u32,
        capabilities: Capabilities,
    },
    Inbound {
        endpoint: String,
        sender: String,
        kind: String,
        body: String,
        created_at: Option<DateTime<Utc>>,
    },
    DeliveryResult {
        corr: i64,
        delivered: bool,
        detail: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DaemonToPlugin {
    HelloAck { protocol_version: u32, error: Option<String> },
    Send { corr: i64, endpoint: String, kind: String, body: String },
    Shutdown,
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> io::Result<()> {
    let mut body = Vec::new();
    ciborium::into_writer(msg, &mut body).map_err(io::Error::other)?;
    let len = u32::try_from(body.len()).map_err(io::Error::other)?;
    if len > MAX_FRAME {
        return Err(io::Error::other("frame exceeds MAX_FRAME"));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    r: &mut R,
) -> io::Result<T> {
    let mut hdr = [0u8; 4];
    r.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes(hdr);
    if len > MAX_FRAME {
        return Err(io::Error::other("frame exceeds MAX_FRAME"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    ciborium::from_reader(body.as_slice()).map_err(io::Error::other)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -j2 -p relay-ipc`
Expected: 3 passed.

- [ ] **Step 6: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add Cargo.toml crates/relay-ipc
git commit -m "feat: plugin IPC protocol v1 (CBOR frames)"
```

---

### Task 3: switchyardd crate + config loading and validation

**Files:**
- Create: `switchyardd/Cargo.toml`, `switchyardd/src/main.rs`, `switchyardd/src/config.rs`
- Modify: root `Cargo.toml` (uncomment member)

**Interfaces:**
- Consumes: `relay_core::Endpoint`
- Produces:
  - `Config { node: NodeConfig, plugins: BTreeMap<String, PluginConfig>, routes: Vec<RouteConfig>, policies: Vec<Policy>, ttl_default_secs: u64 (86400), dedup_ttl_secs: u64 (86400), hop_limit: u8 (8) }`
  - `NodeConfig { name: String, data_dir: PathBuf }`
  - `PluginConfig { enabled: bool, command: Option<String>, config: serde_yaml::Value }` — `command: None` means externally managed (the plugin process connects on its own; spec §103 allows either)
  - `RouteConfig { name: String, sources: Vec<Endpoint>, destinations: Vec<Endpoint> }` (endpoints given as `"proto:endpoint"` strings in YAML, parsed at load)
  - `Policy` (defined here as a config struct, evaluated in Task 6): `Policy { name: String, r#match: PolicyMatch { destination_protocol: Vec<String> }, rules: PolicyRules { max_payload: Option<usize>, drop_kinds: Vec<String>, deny: bool } }`
  - `fn load(path: &Path) -> Result<Config, String>` — parse + `validate()`
  - `fn validate(cfg: &Config) -> Result<(), String>` — duplicate route names; every route endpoint's protocol must be an enabled plugin
  - main supports `--config <path>` (default `/etc/relayfabric/relayfabric.yaml`) and `--check-config`

- [ ] **Step 1: Create crate**

`switchyardd/Cargo.toml`:
```toml
[package]
name = "switchyardd"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
relay-core.workspace = true
relay-ipc.workspace = true
serde.workspace = true
serde_json.workspace = true
serde_yaml.workspace = true
uuid.workspace = true
chrono.workspace = true
tokio.workspace = true
rusqlite.workspace = true
hmac.workspace = true
sha2.workspace = true
hex.workspace = true
rand.workspace = true
axum.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

Uncomment `switchyardd` in the root workspace members. Stub `src/main.rs`:

```rust
mod config;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut config_path = String::from("/etc/relayfabric/relayfabric.yaml");
    let mut check_only = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config_path = args.next().expect("--config needs a path"),
            "--check-config" => check_only = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let cfg = match config::load(std::path::Path::new(&config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        }
    };
    if check_only {
        println!("configuration valid: {} route(s), {} plugin(s)",
                 cfg.routes.len(), cfg.plugins.len());
        return;
    }
    let _ = cfg; // daemon startup arrives in Task 9
}
```

- [ ] **Step 2: Write the failing tests**

Bottom of `switchyardd/src/config.rs`:

```rust
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
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
policies:
  - name: small
    match:
      destination_protocol: [mockb]
    rules:
      max_payload: 200
      drop_kinds: [location]
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
        assert_eq!(cfg.policies[0].rules.max_payload, Some(200));
        assert!(cfg.plugins["mocka"].command.is_none());
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -j2 -p switchyardd config`
Expected: compile FAILURE.

- [ ] **Step 4: Implement config.rs**

```rust
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
}

fn default_ttl() -> u64 { 86_400 }
fn default_hop_limit() -> u8 { 8 }

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
    Ok(())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -j2 -p switchyardd config`
Expected: 4 passed.

- [ ] **Step 6: Verify --check-config end-to-end**

```bash
cargo build -j2 -p switchyardd
printf 'node:\n  name: t\n  data_dir: /tmp/rf\nplugins:\n  m:\n    enabled: true\nroutes:\n  - name: r\n    sources: ["m:a"]\n    destinations: ["m:b"]\n' > /tmp/rf-check.yaml
./target/debug/switchyardd --config /tmp/rf-check.yaml --check-config
```
Expected: `configuration valid: 1 route(s), 1 plugin(s)`, exit 0. A broken file must exit 1.

- [ ] **Step 7: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add Cargo.toml switchyardd
git commit -m "feat: switchyardd config loading and --check-config validation"
```

---

### Task 4: Route-scoped pseudonyms (alias.rs)

**Files:**
- Create: `switchyardd/src/alias.rs`
- Modify: `switchyardd/src/main.rs` (add `mod alias;`)

**Interfaces:**
- Produces:
  - `struct Aliaser` — holds a 32-byte HMAC key
  - `Aliaser::load_or_create(path: &Path) -> std::io::Result<Aliaser>` — reads the hex key file, or generates 32 random bytes, writes hex with mode 0600, then loads (spec §51: secret lives in a strict-permission file, never YAML)
  - `Aliaser::alias(&self, protocol: &str, native_ref: &str, scope: &str) -> String` — returns `PREFIX-XXXX`, e.g. `MESH-7F21`: prefix = first 4 chars of protocol, uppercased; 4 hex chars from HMAC-SHA256(key, `protocol|native_ref|scope`) (spec §20)

- [ ] **Step 1: Write the failing tests**

Bottom of `switchyardd/src/alias.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn aliaser() -> Aliaser {
        Aliaser { key: [7u8; 32] }
    }

    #[test]
    fn alias_is_stable_within_scope() {
        let a = aliaser();
        assert_eq!(
            a.alias("meshtastic", "!abcd1234", "route-a"),
            a.alias("meshtastic", "!abcd1234", "route-a"),
        );
    }

    #[test]
    fn alias_differs_across_scopes_and_senders() {
        let a = aliaser();
        let base = a.alias("meshtastic", "!abcd1234", "route-a");
        assert_ne!(base, a.alias("meshtastic", "!abcd1234", "route-b"));
        assert_ne!(base, a.alias("meshtastic", "!ffff0000", "route-a"));
    }

    #[test]
    fn alias_format_is_prefix_dash_4hex() {
        let alias = aliaser().alias("meshtastic", "!abcd1234", "r");
        let (prefix, hexpart) = alias.split_once('-').unwrap();
        assert_eq!(prefix, "MESH");
        assert_eq!(hexpart.len(), 4);
        assert!(hexpart.chars().all(|c| c.is_ascii_hexdigit() && !c.is_lowercase()));
        // short protocol names keep their full name
        assert!(aliaser().alias("mqtt", "x", "r").starts_with("MQTT-"));
    }

    #[test]
    fn secret_file_roundtrip_and_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alias.key");
        let a = Aliaser::load_or_create(&path).unwrap();
        let b = Aliaser::load_or_create(&path).unwrap();
        assert_eq!(a.alias("p", "n", "s"), b.alias("p", "n", "s"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -j2 -p switchyardd alias`
Expected: compile FAILURE.

- [ ] **Step 3: Implement alias.rs**

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io;
use std::path::Path;

pub struct Aliaser {
    pub(crate) key: [u8; 32],
}

impl Aliaser {
    pub fn load_or_create(path: &Path) -> io::Result<Aliaser> {
        if !path.exists() {
            let key: [u8; 32] = rand::random();
            std::fs::write(path, hex::encode(key))?;
            let mut perms = std::fs::metadata(path)?.permissions();
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        let raw = std::fs::read_to_string(path)?;
        let bytes = hex::decode(raw.trim()).map_err(io::Error::other)?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| io::Error::other("alias key must be 32 bytes of hex"))?;
        Ok(Aliaser { key })
    }

    pub fn alias(&self, protocol: &str, native_ref: &str, scope: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("hmac accepts any key len");
        mac.update(format!("{protocol}|{native_ref}|{scope}").as_bytes());
        let out = mac.finalize().into_bytes();
        let prefix: String = protocol.chars().take(4).collect::<String>().to_uppercase();
        // ponytail: 16-bit alias space; collisions merge personas within a
        // scope. Widen to 6 hex chars if a deployment ever grows past ~hundreds
        // of senders per route.
        format!("{prefix}-{:02X}{:02X}", out[0], out[1])
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -j2 -p switchyardd alias`
Expected: 4 passed.

- [ ] **Step 5: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add switchyardd/src
git commit -m "feat: HMAC route-scoped pseudonyms with secret key file"
```

---

### Task 5: Deduplication cache (dedup.rs)

**Files:**
- Create: `switchyardd/src/dedup.rs`
- Modify: `switchyardd/src/main.rs` (add `mod dedup;`)

**Interfaces:**
- Produces:
  - `fn key(protocol: &str, sender: &str, endpoint: &str, body: &str, created_at: Option<DateTime<Utc>>) -> String` — SHA-256 hex of `protocol|sender|endpoint|created_at_secs|body` (spec §28 fallback key; timestamp omitted when the plugin didn't supply one, matching the rns-signal-gateway approach)
  - `struct Dedup` with `Dedup::new(ttl: Duration) -> Dedup` and `fn check(&mut self, key: &str, now: Instant) -> bool` — true = new (recorded), false = duplicate. Prunes expired entries on each call.

- [ ] **Step 1: Write the failing tests**

Bottom of `switchyardd/src/dedup.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn first_seen_is_new_repeat_is_duplicate() {
        let mut d = Dedup::new(Duration::from_secs(60));
        let now = Instant::now();
        assert!(d.check("k1", now));
        assert!(!d.check("k1", now));
        assert!(d.check("k2", now));
    }

    #[test]
    fn entries_expire_after_ttl() {
        let mut d = Dedup::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(d.check("k", t0));
        assert!(!d.check("k", t0 + Duration::from_secs(59)));
        assert!(d.check("k", t0 + Duration::from_secs(61)));
    }

    #[test]
    fn key_varies_by_every_component() {
        let base = key("p", "s", "e", "b", None);
        assert_ne!(base, key("q", "s", "e", "b", None));
        assert_ne!(base, key("p", "t", "e", "b", None));
        assert_ne!(base, key("p", "s", "f", "b", None));
        assert_ne!(base, key("p", "s", "e", "c", None));
        assert_eq!(base, key("p", "s", "e", "b", None));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -j2 -p switchyardd dedup`
Expected: compile FAILURE.

- [ ] **Step 3: Implement dedup.rs**

```rust
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub fn key(
    protocol: &str,
    sender: &str,
    endpoint: &str,
    body: &str,
    created_at: Option<DateTime<Utc>>,
) -> String {
    let ts = created_at.map(|t| t.timestamp().to_string()).unwrap_or_default();
    hex::encode(Sha256::digest(
        format!("{protocol}|{sender}|{endpoint}|{ts}|{body}").as_bytes(),
    ))
}

pub struct Dedup {
    ttl: Duration,
    seen: HashMap<String, Instant>,
}

impl Dedup {
    pub fn new(ttl: Duration) -> Dedup {
        Dedup { ttl, seen: HashMap::new() }
    }

    /// True if new (and records it), false if already seen.
    pub fn check(&mut self, key: &str, now: Instant) -> bool {
        // ponytail: O(n) prune per call, in-memory only (restart forgets the
        // cache). Fine at gateway volumes; move to the sqlite dedup table if
        // restart-replay ever bites.
        self.seen.retain(|_, t| now.duration_since(*t) < self.ttl);
        if self.seen.contains_key(key) {
            return false;
        }
        self.seen.insert(key.to_string(), now);
        true
    }
}
```

Note: `Instant` in tests is advanced by adding `Duration`s; `now.duration_since(*t)` with a future `now` works because both are derived from the same `Instant::now()` base.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -j2 -p switchyardd dedup`
Expected: 3 passed.

- [ ] **Step 5: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add switchyardd/src
git commit -m "feat: TTL'd message deduplication cache"
```

---

### Task 6: Routing (routes.rs) + policy engine (policy.rs) + transform (transform.rs)

**Files:**
- Create: `switchyardd/src/routes.rs`, `switchyardd/src/policy.rs`, `switchyardd/src/transform.rs`
- Modify: `switchyardd/src/main.rs` (add the three `mod`s)

**Interfaces:**
- Consumes: `config::{RouteConfig, Policy}`, `relay_core::{Endpoint, Envelope}`
- Produces:
  - `routes::route<'a>(routes: &'a [RouteConfig], source: &Endpoint) -> Vec<(&'a str, &'a Endpoint)>` — for every route whose `sources` contains `source`, yield `(route_name, destination)` for each destination EXCEPT the ingress endpoint itself (spec §24 echo exclusion). No matching route → empty vec (deny by default, spec §38).
  - `policy::evaluate<'a>(policies: &'a [Policy], env: &Envelope, dest: &Endpoint) -> Decision<'a>` where `enum Decision<'a> { Allow { max_payload: Option<usize> }, Deny { policy: &'a str } }` — first matching deny/drop_kinds wins; `max_payload` is the minimum across matching policies.
  - `transform::render(alias: &str, body: &str, max_payload: Option<usize>) -> String` — `"[{alias}]\n{body}"`, truncated on a char boundary to `max_payload` bytes with a trailing `…` when cut (spec §17, §83).

- [ ] **Step 1: Write the failing tests**

Bottom of `switchyardd/src/routes.rs`:

```rust
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
```

Bottom of `switchyardd/src/policy.rs`:

```rust
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
        assert!(matches!(evaluate(&[strip.clone()], &env("location"), &dest()), Decision::Deny { .. }));
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
```

Bottom of `switchyardd/src/transform.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_alias_tag() {
        assert_eq!(render("MESH-7F21", "hello", None), "[MESH-7F21]\nhello");
    }

    #[test]
    fn truncates_on_char_boundary_with_marker() {
        let out = render("A-0000", "héllo wörld this is long", Some(20));
        assert!(out.len() <= 20, "len {} > 20", out.len());
        assert!(out.ends_with('…'));
        assert!(out.starts_with("[A-0000]\n"));
    }

    #[test]
    fn no_truncation_when_it_fits() {
        assert_eq!(render("A-0000", "hi", Some(200)), "[A-0000]\nhi");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -j2 -p switchyardd routes policy transform` (three invocations or one `cargo test -j2 -p switchyardd`)
Expected: compile FAILURE.

- [ ] **Step 3: Implement the three modules**

`switchyardd/src/routes.rs`:

```rust
use crate::config::RouteConfig;
use relay_core::Endpoint;

/// Deny by default: only explicitly routed (source → destinations) pairs
/// flow, and the ingress endpoint never echoes back to itself (spec §24, §38).
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
```

`switchyardd/src/policy.rs`:

```rust
use crate::config::Policy;
use relay_core::{Endpoint, Envelope};

#[derive(Debug)]
pub enum Decision<'a> {
    Allow { max_payload: Option<usize> },
    Deny { policy: &'a str },
}

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
```

`switchyardd/src/transform.rs`:

```rust
/// Render the destination-facing body: origin tag + payload, truncated to
/// max_payload bytes on a char boundary with a visible marker (spec §17, §83).
pub fn render(alias: &str, body: &str, max_payload: Option<usize>) -> String {
    let full = format!("[{alias}]\n{body}");
    let Some(limit) = max_payload else { return full };
    if full.len() <= limit {
        return full;
    }
    let budget = limit.saturating_sub('…'.len_utf8());
    let mut cut = budget.min(full.len());
    while cut > 0 && !full.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &full[..cut])
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -j2 -p switchyardd`
Expected: all module tests pass (config 4, alias 4, dedup 3, routes 2, policy 4, transform 3).

- [ ] **Step 5: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add switchyardd/src
git commit -m "feat: routing with echo exclusion, policy engine, egress transform"
```

---

### Task 7: SQLite storage + queue semantics (storage.rs, queue.rs)

**Files:**
- Create: `switchyardd/src/storage.rs`, `switchyardd/src/queue.rs`
- Modify: `switchyardd/src/main.rs` (add `mod storage; mod queue;`)

**Interfaces:**
- Consumes: `relay_core::{Endpoint, Envelope}`
- Produces (queue.rs, pure):
  - `queue::MAX_ATTEMPTS: u32 = 8`
  - `queue::backoff(attempt: u32) -> std::time::Duration` — schedule 5s, 30s, 2m, 10m, then 1h for every later attempt (spec §42)
- Produces (storage.rs):
  - `struct Store` (owns a `rusqlite::Connection`; the daemon wraps it in `Mutex<Store>` — ponytail: one writer is plenty at radio volumes)
  - `Store::open(path: &Path) -> rusqlite::Result<Store>` — creates schema, enables WAL
  - `fn insert_message(&self, env: &Envelope) -> rusqlite::Result<()>` — envelope as JSON blob
  - `fn get_message(&self, id: Uuid) -> rusqlite::Result<Option<Envelope>>`
  - `fn insert_delivery(&self, message_id: Uuid, route: &str, dest: &Endpoint, next_attempt: DateTime<Utc>, expires_at: DateTime<Utc>) -> rusqlite::Result<i64>` — returns rowid (the IPC `corr`)
  - `fn due_deliveries(&self, now: DateTime<Utc>, limit: usize) -> rusqlite::Result<Vec<Delivery>>` — state `pending` AND `next_attempt <= now`
  - `fn mark_attempting(&self, id: i64) -> rusqlite::Result<()>` — sets state, increments `attempt_count`, stamps `attempted_at`
  - `fn mark_delivered(&self, id: i64) -> rusqlite::Result<()>`
  - `fn mark_retry(&self, id: i64, next_attempt: DateTime<Utc>) -> rusqlite::Result<()>` — back to `pending`
  - `fn mark_terminal(&self, id: i64, state: &str, reason: &str) -> rusqlite::Result<()>` — `expired` / `dead_letter` / `failed` with reason code (spec §44 codes: `TTL_EXPIRED`, `POLICY_DENIED`, `PLUGIN_UNAVAILABLE`, `RETRY_EXHAUSTED`, `DESTINATION_UNKNOWN`)
  - `fn recover(&self) -> rusqlite::Result<usize>` — `attempting` → `pending` (startup, spec §68)
  - `fn reclaim_stale(&self, older_than: DateTime<Utc>) -> rusqlite::Result<usize>` — `attempting` rows attempted before the cutoff → `pending` (plugin died mid-send)
  - `fn queue_counts(&self) -> rusqlite::Result<Vec<(String, i64)>>` — rows per state
  - `fn deliveries_for(&self, message_id: Uuid) -> rusqlite::Result<Vec<Delivery>>` — for trace
  - `struct Delivery { id: i64, message_id: Uuid, route: String, destination: Endpoint, attempt_count: u32, state: String, reason: Option<String>, next_attempt: DateTime<Utc>, expires_at: DateTime<Utc> }`

Schema (in `Store::open`):

```sql
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  envelope TEXT NOT NULL,           -- JSON; body never logged, but stored for delivery
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id TEXT NOT NULL REFERENCES messages(id),
  route TEXT NOT NULL,
  dest_protocol TEXT NOT NULL,
  dest_endpoint TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'pending',
  reason TEXT,
  next_attempt TEXT NOT NULL,
  attempted_at TEXT,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(state, next_attempt);
```

Timestamps stored as RFC3339 TEXT (`chrono` `to_rfc3339()` / `parse_from_rfc3339`), which sorts correctly lexicographically.

- [ ] **Step 1: Write the failing tests**

Bottom of `switchyardd/src/queue.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn backoff_schedule_matches_spec() {
        assert_eq!(backoff(1), Duration::from_secs(5));
        assert_eq!(backoff(2), Duration::from_secs(30));
        assert_eq!(backoff(3), Duration::from_secs(120));
        assert_eq!(backoff(4), Duration::from_secs(600));
        assert_eq!(backoff(5), Duration::from_secs(3600));
        assert_eq!(backoff(99), Duration::from_secs(3600));
    }
}
```

Bottom of `switchyardd/src/storage.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use relay_core::{Endpoint, Envelope, Sender};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("test.db")).unwrap();
        (dir, s)
    }

    fn env() -> Envelope {
        let now = Utc::now();
        Envelope::new(
            "mocka:chan".parse().unwrap(),
            Sender { native_ref: "!a".into() },
            "text".into(), "hello".into(), now, now + Duration::hours(1), 8,
        )
    }

    fn dest() -> Endpoint { "mockb:chan".parse().unwrap() }

    #[test]
    fn message_roundtrip() {
        let (_d, s) = store();
        let e = env();
        s.insert_message(&e).unwrap();
        let got = s.get_message(e.id).unwrap().unwrap();
        assert_eq!(got.body, "hello");
        assert_eq!(got.id, e.id);
        assert!(s.get_message(uuid::Uuid::now_v7()).unwrap().is_none());
    }

    #[test]
    fn due_deliveries_respect_next_attempt() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at).unwrap();
        let _future = s
            .insert_delivery(e.id, "general", &dest(), now + Duration::hours(1), e.expires_at)
            .unwrap();
        let due = s.due_deliveries(now, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, id);
        assert_eq!(due[0].destination, dest());
        assert_eq!(due[0].state, "pending");
    }

    #[test]
    fn state_transitions() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at).unwrap();

        s.mark_attempting(id).unwrap();
        assert!(s.due_deliveries(now, 10).unwrap().is_empty());
        let d = &s.deliveries_for(e.id).unwrap()[0];
        assert_eq!((d.state.as_str(), d.attempt_count), ("attempting", 1));

        s.mark_retry(id, now + Duration::seconds(5)).unwrap();
        assert_eq!(s.deliveries_for(e.id).unwrap()[0].state, "pending");

        s.mark_attempting(id).unwrap();
        s.mark_delivered(id).unwrap();
        let d = &s.deliveries_for(e.id).unwrap()[0];
        assert_eq!((d.state.as_str(), d.attempt_count), ("delivered", 2));

        let id2 = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at).unwrap();
        s.mark_terminal(id2, "dead_letter", "RETRY_EXHAUSTED").unwrap();
        let d2 = s.deliveries_for(e.id).unwrap().into_iter().find(|d| d.id == id2).unwrap();
        assert_eq!(d2.reason.as_deref(), Some("RETRY_EXHAUSTED"));
    }

    #[test]
    fn recover_and_reclaim_requeue_attempting() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        let id = s.insert_delivery(e.id, "general", &dest(), now, e.expires_at).unwrap();
        s.mark_attempting(id).unwrap();
        assert_eq!(s.recover().unwrap(), 1);
        assert_eq!(s.deliveries_for(e.id).unwrap()[0].state, "pending");

        s.mark_attempting(id).unwrap();
        assert_eq!(s.reclaim_stale(now + Duration::seconds(90)).unwrap(), 1);
        assert_eq!(s.reclaim_stale(now - Duration::seconds(90)).unwrap(), 0);
    }

    #[test]
    fn queue_counts_by_state() {
        let (_d, s) = store();
        let e = env();
        let now = Utc::now();
        s.insert_message(&e).unwrap();
        s.insert_delivery(e.id, "r", &dest(), now, e.expires_at).unwrap();
        let id2 = s.insert_delivery(e.id, "r", &dest(), now, e.expires_at).unwrap();
        s.mark_terminal(id2, "dead_letter", "POLICY_DENIED").unwrap();
        let counts = s.queue_counts().unwrap();
        assert!(counts.contains(&("pending".to_string(), 1)));
        assert!(counts.contains(&("dead_letter".to_string(), 1)));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -j2 -p switchyardd storage queue`
Expected: compile FAILURE.

- [ ] **Step 3: Implement queue.rs**

```rust
use std::time::Duration;

pub const MAX_ATTEMPTS: u32 = 8;

/// Exponential-ish backoff per spec §42: 5s, 30s, 2m, 10m, then 1h forever.
pub fn backoff(attempt: u32) -> Duration {
    Duration::from_secs(match attempt {
        0 | 1 => 5,
        2 => 30,
        3 => 120,
        4 => 600,
        _ => 3600,
    })
}
```

- [ ] **Step 4: Implement storage.rs**

```rust
use chrono::{DateTime, Utc};
use relay_core::{Endpoint, Envelope};
use rusqlite::{params, Connection};
use std::path::Path;
use uuid::Uuid;

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct Delivery {
    pub id: i64,
    pub message_id: Uuid,
    pub route: String,
    pub destination: Endpoint,
    pub attempt_count: u32,
    pub state: String,
    pub reason: Option<String>,
    pub next_attempt: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  envelope TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id TEXT NOT NULL REFERENCES messages(id),
  route TEXT NOT NULL,
  dest_protocol TEXT NOT NULL,
  dest_endpoint TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'pending',
  reason TEXT,
  next_attempt TEXT NOT NULL,
  attempted_at TEXT,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(state, next_attempt);
";

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339()
}

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).map(|t| t.with_timezone(&Utc)).unwrap_or_default()
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Store { conn })
    }

    pub fn insert_message(&self, env: &Envelope) -> rusqlite::Result<()> {
        let json = serde_json::to_string(env).expect("envelope serializes");
        self.conn.execute(
            "INSERT OR IGNORE INTO messages (id, envelope, created_at) VALUES (?1, ?2, ?3)",
            params![env.id.to_string(), json, ts(env.created_at)],
        )?;
        Ok(())
    }

    pub fn get_message(&self, id: Uuid) -> rusqlite::Result<Option<Envelope>> {
        let mut stmt = self.conn.prepare("SELECT envelope FROM messages WHERE id = ?1")?;
        let mut rows = stmt.query(params![id.to_string()])?;
        match rows.next()? {
            Some(row) => {
                let json: String = row.get(0)?;
                Ok(serde_json::from_str(&json).ok())
            }
            None => Ok(None),
        }
    }

    pub fn insert_delivery(
        &self,
        message_id: Uuid,
        route: &str,
        dest: &Endpoint,
        next_attempt: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO deliveries
               (message_id, route, dest_protocol, dest_endpoint, next_attempt, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![message_id.to_string(), route, dest.protocol, dest.endpoint,
                    ts(next_attempt), ts(expires_at)],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    fn delivery_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Delivery> {
        Ok(Delivery {
            id: row.get(0)?,
            message_id: row.get::<_, String>(1)?.parse().unwrap_or_default(),
            route: row.get(2)?,
            destination: Endpoint { protocol: row.get(3)?, endpoint: row.get(4)? },
            attempt_count: row.get(5)?,
            state: row.get(6)?,
            reason: row.get(7)?,
            next_attempt: parse_ts(&row.get::<_, String>(8)?),
            expires_at: parse_ts(&row.get::<_, String>(9)?),
        })
    }

    const DELIVERY_COLS: &'static str =
        "id, message_id, route, dest_protocol, dest_endpoint, attempt_count,
         state, reason, next_attempt, expires_at";

    pub fn due_deliveries(
        &self,
        now: DateTime<Utc>,
        limit: usize,
    ) -> rusqlite::Result<Vec<Delivery>> {
        let sql = format!(
            "SELECT {} FROM deliveries
             WHERE state = 'pending' AND next_attempt <= ?1
             ORDER BY next_attempt LIMIT ?2",
            Self::DELIVERY_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![ts(now), limit as i64], Self::delivery_from_row)?;
        rows.collect()
    }

    pub fn mark_attempting(&self, id: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'attempting',
                attempt_count = attempt_count + 1, attempted_at = ?2
             WHERE id = ?1",
            params![id, ts(Utc::now())],
        )?;
        Ok(())
    }

    pub fn mark_delivered(&self, id: i64) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'delivered' WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn mark_retry(&self, id: i64, next_attempt: DateTime<Utc>) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'pending', next_attempt = ?2 WHERE id = ?1",
            params![id, ts(next_attempt)],
        )?;
        Ok(())
    }

    pub fn mark_terminal(&self, id: i64, state: &str, reason: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE deliveries SET state = ?2, reason = ?3 WHERE id = ?1",
            params![id, state, reason],
        )?;
        Ok(())
    }

    pub fn recover(&self) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'pending' WHERE state = 'attempting'", [])
    }

    pub fn reclaim_stale(&self, older_than: DateTime<Utc>) -> rusqlite::Result<usize> {
        self.conn.execute(
            "UPDATE deliveries SET state = 'pending'
             WHERE state = 'attempting' AND attempted_at < ?1",
            params![ts(older_than)],
        )
    }

    pub fn queue_counts(&self) -> rusqlite::Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT state, COUNT(*) FROM deliveries GROUP BY state")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    pub fn deliveries_for(&self, message_id: Uuid) -> rusqlite::Result<Vec<Delivery>> {
        let sql = format!(
            "SELECT {} FROM deliveries WHERE message_id = ?1 ORDER BY id",
            Self::DELIVERY_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![message_id.to_string()], Self::delivery_from_row)?;
        rows.collect()
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -j2 -p switchyardd`
Expected: all pass (adds queue 1, storage 5).

- [ ] **Step 6: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add switchyardd/src
git commit -m "feat: sqlite message store and delivery queue with retry states"
```

---

### Task 8: Metrics (metrics.rs)

**Files:**
- Create: `switchyardd/src/metrics.rs`
- Modify: `switchyardd/src/main.rs` (add `mod metrics;`)

**Interfaces:**
- Produces:
  - `static INGRESS, EGRESS, DROPPED, DUPLICATES, POLICY_DENIALS: AtomicU64` (module-level, `pub`)
  - `fn inc(c: &AtomicU64)` — relaxed add 1
  - `fn render(queue_counts: &[(String, i64)], plugin_up: &[(String, bool)]) -> String` — Prometheus text exposition (spec §55 names)

- [ ] **Step 1: Write the failing test**

Bottom of `switchyardd/src/metrics.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        inc(&INGRESS);
        let out = render(
            &[("pending".into(), 3), ("dead_letter".into(), 1)],
            &[("mqtt".into(), true), ("mocka".into(), false)],
        );
        assert!(out.contains("relayfabric_messages_ingress_total "));
        assert!(out.contains("relayfabric_queue_depth{state=\"pending\"} 3"));
        assert!(out.contains("relayfabric_queue_depth{state=\"dead_letter\"} 1"));
        assert!(out.contains("relayfabric_plugin_up{plugin=\"mqtt\"} 1"));
        assert!(out.contains("relayfabric_plugin_up{plugin=\"mocka\"} 0"));
        // presence only: other tests in the same process may bump counters
        assert!(out.contains("relayfabric_policy_denials_total"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -j2 -p switchyardd metrics`
Expected: compile FAILURE.

- [ ] **Step 3: Implement metrics.rs**

```rust
// ponytail: five atomics and a format! — swap for the `prometheus` crate only
// if labels/histograms are ever actually needed (delivery latency histogram
// deferred with them).
use std::sync::atomic::{AtomicU64, Ordering};

pub static INGRESS: AtomicU64 = AtomicU64::new(0);
pub static EGRESS: AtomicU64 = AtomicU64::new(0);
pub static DROPPED: AtomicU64 = AtomicU64::new(0);
pub static DUPLICATES: AtomicU64 = AtomicU64::new(0);
pub static POLICY_DENIALS: AtomicU64 = AtomicU64::new(0);

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub fn render(queue_counts: &[(String, i64)], plugin_up: &[(String, bool)]) -> String {
    let mut out = String::new();
    let counters = [
        ("relayfabric_messages_ingress_total", &INGRESS),
        ("relayfabric_messages_egress_total", &EGRESS),
        ("relayfabric_messages_dropped_total", &DROPPED),
        ("relayfabric_duplicate_messages_total", &DUPLICATES),
        ("relayfabric_policy_denials_total", &POLICY_DENIALS),
    ];
    for (name, c) in counters {
        out.push_str(&format!("# TYPE {name} counter\n{name} {}\n", c.load(Ordering::Relaxed)));
    }
    out.push_str("# TYPE relayfabric_queue_depth gauge\n");
    for (state, n) in queue_counts {
        out.push_str(&format!("relayfabric_queue_depth{{state=\"{state}\"}} {n}\n"));
    }
    out.push_str("# TYPE relayfabric_plugin_up gauge\n");
    for (plugin, up) in plugin_up {
        out.push_str(&format!(
            "relayfabric_plugin_up{{plugin=\"{plugin}\"}} {}\n", u8::from(*up)));
    }
    out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -j2 -p switchyardd metrics`
Expected: PASS.

- [ ] **Step 5: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add switchyardd/src
git commit -m "feat: prometheus metrics counters and text rendering"
```

---

### Task 9: Engine wiring — ingress, delivery pump, plugin server, supervisor, daemon startup

**Files:**
- Create: `switchyardd/src/engine.rs`, `switchyardd/src/plugins.rs`
- Modify: `switchyardd/src/main.rs` (full daemon startup, spec §68 order)

**Interfaces:**
- Consumes: everything from Tasks 1–8.
- Produces:
  - `engine::Daemon { cfg: Config, store: Mutex<Store>, dedup: Mutex<Dedup>, aliaser: Aliaser, plugins: Mutex<HashMap<String, PluginHandle>> }` — shared as `Arc<Daemon>`; Task 10's admin API reads `cfg`, `store`, `plugins`.
  - `engine::PluginHandle { tx: tokio::sync::mpsc::Sender<DaemonToPlugin>, capabilities: Capabilities, connected: bool }`
  - `engine::handle_inbound(d: &Daemon, plugin: &str, endpoint: String, sender: String, kind: String, body: String, created_at: Option<DateTime<Utc>>)` — dedup → envelope → route → persist deliveries
  - `engine::handle_result(d: &Daemon, corr: i64, delivered: bool, detail: Option<String>)`
  - `engine::pump(d: Arc<Daemon>)` — 500ms loop: reclaim stale, fetch due, policy/transform/send
  - `plugins::listen(d: Arc<Daemon>, listener: tokio::net::UnixListener)` — accept loop
  - `plugins::supervise(d: Arc<Daemon>, name: String, command: String, socket: PathBuf)` — spawn/restart with 1s/5s/30s/2m backoff (spec §69)
  - Socket paths: `<data_dir>/plugins.sock` and `<data_dir>/admin.sock`; alias key `<data_dir>/alias.key`; database `<data_dir>/relayfabric.db`.
  - Spawned plugins receive env vars `RELAYFABRIC_SOCKET`, `RELAYFABRIC_PLUGIN_NAME`, `RELAYFABRIC_PLUGIN_CONFIG` (the plugin's `config:` YAML mapping re-serialized as JSON).

Engine behavior is validated by the Task 12 e2e tests; this task's own test is a startup smoke test plus one unit test for the ingress path using an in-memory daemon (no sockets).

- [ ] **Step 1: Write the failing unit test**

Bottom of `switchyardd/src/engine.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, NodeConfig, PluginConfig, RouteConfig};
    use std::collections::BTreeMap;

    fn test_daemon(dir: &std::path::Path) -> Daemon {
        let mut plugins = BTreeMap::new();
        for name in ["mocka", "mockb"] {
            plugins.insert(name.to_string(), PluginConfig {
                enabled: true, command: None, config: serde_yaml::Value::Null,
            });
        }
        let cfg = Config {
            node: NodeConfig { name: "t".into(), data_dir: dir.to_path_buf() },
            plugins,
            routes: vec![RouteConfig {
                name: "general".into(),
                sources: vec!["mocka:chan".parse().unwrap(), "mockb:chan".parse().unwrap()],
                destinations: vec!["mocka:chan".parse().unwrap(), "mockb:chan".parse().unwrap()],
            }],
            policies: vec![],
            ttl_default_secs: 3600,
            dedup_ttl_secs: 3600,
            hop_limit: 8,
        };
        Daemon::new(cfg, dir).unwrap()
    }

    #[test]
    fn inbound_routes_to_other_endpoint_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let d = test_daemon(dir.path());
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None);
        // one delivery row, to mockb, none echoed to mocka
        let store = d.store.lock().unwrap();
        let counts = store.queue_counts().unwrap();
        assert_eq!(counts, vec![("pending".to_string(), 1)]);
        let due = store.due_deliveries(chrono::Utc::now(), 10).unwrap();
        assert_eq!(due[0].destination.protocol, "mockb");
        drop(store);
        // duplicate is dropped
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None);
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(),
                   vec![("pending".to_string(), 1)]);
        // unrouted endpoint is dropped (deny by default)
        handle_inbound(&d, "mocka", "elsewhere".into(), "!a".into(), "text".into(),
                       "hi".into(), None);
        assert_eq!(d.store.lock().unwrap().queue_counts().unwrap(),
                   vec![("pending".to_string(), 1)]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -j2 -p switchyardd engine`
Expected: compile FAILURE.

- [ ] **Step 3: Implement engine.rs**

```rust
use crate::config::Config;
use crate::storage::Store;
use crate::{alias, dedup, metrics, policy, queue, routes, storage, transform};
use alias::Aliaser;
use chrono::{DateTime, Duration as CDuration, Utc};
use relay_core::{Capabilities, Endpoint, Envelope, Sender};
use relay_ipc::DaemonToPlugin;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub struct PluginHandle {
    pub tx: mpsc::Sender<DaemonToPlugin>,
    pub capabilities: Capabilities,
    pub connected: bool,
}

pub struct Daemon {
    pub cfg: Config,
    pub store: Mutex<Store>,
    pub dedup: Mutex<dedup::Dedup>,
    pub aliaser: Aliaser,
    pub plugins: Mutex<HashMap<String, PluginHandle>>,
}

impl Daemon {
    pub fn new(cfg: Config, data_dir: &Path) -> std::io::Result<Daemon> {
        std::fs::create_dir_all(data_dir)?;
        let store = Store::open(&data_dir.join("relayfabric.db"))
            .map_err(std::io::Error::other)?;
        let recovered = store.recover().map_err(std::io::Error::other)?;
        if recovered > 0 {
            info!(recovered, "requeued in-flight deliveries from previous run");
        }
        let aliaser = Aliaser::load_or_create(&data_dir.join("alias.key"))?;
        let ttl = std::time::Duration::from_secs(cfg.dedup_ttl_secs);
        Ok(Daemon {
            cfg,
            store: Mutex::new(store),
            dedup: Mutex::new(dedup::Dedup::new(ttl)),
            aliaser,
            plugins: Mutex::new(HashMap::new()),
        })
    }
}

pub fn handle_inbound(
    d: &Daemon,
    plugin: &str,
    endpoint: String,
    sender: String,
    kind: String,
    body: String,
    created_at: Option<DateTime<Utc>>,
) {
    metrics::inc(&metrics::INGRESS);
    let key = dedup::key(plugin, &sender, &endpoint, &body, created_at);
    if !d.dedup.lock().unwrap().check(&key, Instant::now()) {
        metrics::inc(&metrics::DUPLICATES);
        return;
    }
    let now = Utc::now();
    let source = Endpoint { protocol: plugin.to_string(), endpoint };
    let targets: Vec<(String, Endpoint)> = routes::route(&d.cfg.routes, &source)
        .into_iter()
        .map(|(r, e)| (r.to_string(), e.clone()))
        .collect();
    if targets.is_empty() {
        metrics::inc(&metrics::DROPPED);
        warn!(%source, "dropping unrouted message (deny by default)");
        return;
    }
    let env = Envelope::new(
        source,
        Sender { native_ref: sender },
        kind,
        body,
        created_at.unwrap_or(now),
        now + CDuration::seconds(d.cfg.ttl_default_secs as i64),
        d.cfg.hop_limit,
    );
    let store = d.store.lock().unwrap();
    if let Err(e) = store.insert_message(&env) {
        warn!(error = %e, "failed to persist message");
        return;
    }
    for (route, dest) in &targets {
        if let Err(e) = store.insert_delivery(env.id, route, dest, now, env.expires_at) {
            warn!(error = %e, "failed to enqueue delivery");
        }
    }
    info!(id = %env.id, source = %env.source, targets = targets.len(), "message accepted");
}

pub fn handle_result(d: &Daemon, corr: i64, delivered: bool, detail: Option<String>) {
    let store = d.store.lock().unwrap();
    if delivered {
        metrics::inc(&metrics::EGRESS);
        let _ = store.mark_delivered(corr);
        info!(delivery = corr, "delivered");
        return;
    }
    // look up attempt count to decide retry vs dead-letter
    let attempts = store
        .deliveries_for_id(corr)
        .map(|del| del.attempt_count)
        .unwrap_or(queue::MAX_ATTEMPTS);
    if attempts >= queue::MAX_ATTEMPTS {
        let _ = store.mark_terminal(corr, "dead_letter", "RETRY_EXHAUSTED");
        warn!(delivery = corr, detail = detail.as_deref().unwrap_or(""), "dead-lettered");
    } else {
        let next = Utc::now()
            + CDuration::from_std(queue::backoff(attempts)).unwrap_or(CDuration::seconds(5));
        let _ = store.mark_retry(corr, next);
        info!(delivery = corr, attempts, "delivery failed, will retry");
    }
}

pub async fn pump(d: Arc<Daemon>) {
    loop {
        let now = Utc::now();
        let due = {
            let store = d.store.lock().unwrap();
            let _ = store.reclaim_stale(now - CDuration::seconds(60));
            store.due_deliveries(now, 32).unwrap_or_default()
        };
        for del in due {
            process_due(&d, del, now).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn process_due(d: &Arc<Daemon>, del: storage::Delivery, now: DateTime<Utc>) {
    let env = match d.store.lock().unwrap().get_message(del.message_id) {
        Ok(Some(e)) => e,
        _ => {
            let _ = d.store.lock().unwrap()
                .mark_terminal(del.id, "failed", "DESTINATION_UNKNOWN");
            return;
        }
    };
    if env.is_expired(now) {
        let _ = d.store.lock().unwrap().mark_terminal(del.id, "expired", "TTL_EXPIRED");
        return;
    }
    match policy::evaluate(&d.cfg.policies, &env, &del.destination) {
        policy::Decision::Deny { policy } => {
            metrics::inc(&metrics::POLICY_DENIALS);
            let _ = d.store.lock().unwrap()
                .mark_terminal(del.id, "dead_letter", "POLICY_DENIED");
            info!(delivery = del.id, policy, "policy denied");
        }
        policy::Decision::Allow { max_payload } => {
            // capability + policy limits combine to the tighter one
            let (tx, cap_limit) = {
                let plugins = d.plugins.lock().unwrap();
                match plugins.get(&del.destination.protocol).filter(|h| h.connected) {
                    Some(h) => (
                        Some(h.tx.clone()),
                        h.capabilities.max_payload.map(|v| v as usize),
                    ),
                    None => (None, None),
                }
            };
            let Some(tx) = tx else {
                // plugin not connected: nudge next_attempt forward, stay pending
                let _ = d.store.lock().unwrap()
                    .mark_retry(del.id, now + CDuration::seconds(5));
                return;
            };
            let limit = match (max_payload, cap_limit) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let alias = d.aliaser.alias(
                &env.source.protocol, &env.sender.native_ref, &del.route);
            let body = transform::render(&alias, &env.body, limit);
            let _ = d.store.lock().unwrap().mark_attempting(del.id);
            let send = DaemonToPlugin::Send {
                corr: del.id,
                endpoint: del.destination.endpoint.clone(),
                kind: env.kind.clone(),
                body,
            };
            if tx.send(send).await.is_err() {
                // channel closed under us; requeue
                let _ = d.store.lock().unwrap()
                    .mark_retry(del.id, now + CDuration::seconds(5));
            }
        }
    }
}
```

Also add to `storage.rs` (needed by `handle_result`):

```rust
    pub fn deliveries_for_id(&self, id: i64) -> Option<Delivery> {
        let sql = format!("SELECT {} FROM deliveries WHERE id = ?1", Self::DELIVERY_COLS);
        self.conn
            .prepare(&sql)
            .ok()?
            .query_row(params![id], Self::delivery_from_row)
            .ok()
    }
```

- [ ] **Step 4: Implement plugins.rs**

```rust
use crate::engine::{self, Daemon, PluginHandle};
use relay_ipc::{read_frame, write_frame, DaemonToPlugin, PluginToDaemon, PROTOCOL_VERSION};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tracing::{info, warn};

pub async fn listen(d: Arc<Daemon>, listener: UnixListener) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let d = d.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(d, stream).await {
                        warn!(error = %e, "plugin connection ended");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "plugin accept failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn handle_conn(
    d: Arc<Daemon>,
    stream: tokio::net::UnixStream,
) -> std::io::Result<()> {
    let (mut r, mut w) = stream.into_split();
    let hello: PluginToDaemon = read_frame(&mut r).await?;
    let PluginToDaemon::Hello { plugin, protocol_version, capabilities, .. } = hello else {
        return Err(std::io::Error::other("first frame must be Hello"));
    };
    // trust boundary: only configured+enabled plugin names may attach
    let allowed = d.cfg.plugins.get(&plugin).map(|p| p.enabled).unwrap_or(false);
    if !allowed || protocol_version != PROTOCOL_VERSION {
        let err = if allowed { "unsupported protocol version" } else { "unknown plugin" };
        write_frame(&mut w, &DaemonToPlugin::HelloAck {
            protocol_version: PROTOCOL_VERSION, error: Some(err.into()),
        }).await?;
        return Err(std::io::Error::other(format!("{plugin}: {err}")));
    }
    write_frame(&mut w, &DaemonToPlugin::HelloAck {
        protocol_version: PROTOCOL_VERSION, error: None,
    }).await?;

    // bounded outbound channel: backpressure instead of unbounded memory (§45)
    let (tx, mut rx) = mpsc::channel::<DaemonToPlugin>(256);
    d.plugins.lock().unwrap().insert(plugin.clone(), PluginHandle {
        tx, capabilities, connected: true,
    });
    info!(plugin, "plugin connected");

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_frame(&mut w, &msg).await.is_err() {
                break;
            }
        }
    });

    let result = loop {
        match read_frame::<_, PluginToDaemon>(&mut r).await {
            Ok(PluginToDaemon::Inbound { endpoint, sender, kind, body, created_at }) => {
                engine::handle_inbound(&d, &plugin, endpoint, sender, kind, body, created_at);
            }
            Ok(PluginToDaemon::DeliveryResult { corr, delivered, detail }) => {
                engine::handle_result(&d, corr, delivered, detail);
            }
            Ok(PluginToDaemon::Hello { .. }) => {} // ignore repeat hello
            Err(e) => break e,
        }
    };
    if let Some(h) = d.plugins.lock().unwrap().get_mut(&plugin) {
        h.connected = false;
    }
    writer.abort();
    info!(plugin, "plugin disconnected");
    Err(result)
}

pub async fn supervise(d: Arc<Daemon>, name: String, command: String, socket: PathBuf) {
    let cfg_json = d.cfg.plugins.get(&name)
        .map(|p| serde_json::to_string(&p.config).unwrap_or_default())
        .unwrap_or_default();
    let backoffs = [1u64, 5, 30, 120]; // spec §69
    let mut strikes = 0usize;
    loop {
        info!(plugin = name, "starting plugin process");
        let child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .env("RELAYFABRIC_SOCKET", &socket)
            .env("RELAYFABRIC_PLUGIN_NAME", &name)
            .env("RELAYFABRIC_PLUGIN_CONFIG", &cfg_json)
            .spawn();
        let started = Instant::now();
        match child {
            Ok(mut c) => { let _ = c.wait().await; }
            Err(e) => warn!(plugin = name, error = %e, "spawn failed"),
        }
        if started.elapsed() > Duration::from_secs(60) {
            strikes = 0; // a healthy run resets the backoff ladder
        }
        let delay = backoffs[strikes.min(backoffs.len() - 1)];
        strikes += 1;
        warn!(plugin = name, delay, "plugin exited; restarting after backoff");
        tokio::time::sleep(Duration::from_secs(delay)).await;
    }
}
```

- [ ] **Step 5: Wire main.rs (startup order per spec §68)**

Replace the `let _ = cfg;` stub:

```rust
mod admin; // Task 10 — add the mod line there; omit here if doing tasks in order
mod alias;
mod config;
mod dedup;
mod engine;
mod metrics;
mod plugins;
mod policy;
mod queue;
mod routes;
mod storage;
mod transform;

use std::sync::Arc;

fn main() {
    // ... existing arg parsing and --check-config from Task 3 ...
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let data_dir = cfg.node.data_dir.clone();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let daemon = Arc::new(engine::Daemon::new(cfg, &data_dir).expect("daemon init"));
        let plugin_sock = data_dir.join("plugins.sock");
        let _ = std::fs::remove_file(&plugin_sock);
        let listener = tokio::net::UnixListener::bind(&plugin_sock).expect("bind plugin socket");
        tokio::spawn(plugins::listen(daemon.clone(), listener));
        for (name, pc) in &daemon.cfg.plugins {
            if pc.enabled {
                if let Some(cmd) = &pc.command {
                    tokio::spawn(plugins::supervise(
                        daemon.clone(), name.clone(), cmd.clone(), plugin_sock.clone()));
                }
            }
        }
        tokio::spawn(engine::pump(daemon.clone()));
        // admin::serve added in Task 10:
        // tokio::spawn(admin::serve(daemon.clone(), data_dir.join("admin.sock")));
        tracing::info!(node = daemon.cfg.node.name, "switchyardd running");
        tokio::signal::ctrl_c().await.expect("ctrl_c");
        tracing::info!("shutting down");
    });
}
```

- [ ] **Step 6: Run tests + startup smoke**

```bash
cargo test -j2 -p switchyardd
cargo build -j2 -p switchyardd
printf 'node:\n  name: t\n  data_dir: /tmp/rf-smoke\nplugins:\n  m:\n    enabled: true\nroutes: []\n' > /tmp/rf-smoke.yaml
timeout 2 ./target/debug/switchyardd --config /tmp/rf-smoke.yaml; test -S /tmp/rf-smoke/plugins.sock && echo SOCKET-OK
```
Expected: tests pass; `SOCKET-OK` printed.

- [ ] **Step 7: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add switchyardd/src
git commit -m "feat: daemon engine, plugin server, supervisor, startup wiring"
```

---

### Task 10: Admin API over Unix socket (admin.rs)

**Files:**
- Create: `switchyardd/src/admin.rs`
- Modify: `switchyardd/src/main.rs` (add `mod admin;` and uncomment the `admin::serve` spawn from Task 9)

**Interfaces:**
- Consumes: `engine::Daemon`, `metrics::render`, `storage` queries
- Produces:
  - `admin::serve(d: Arc<Daemon>, socket: PathBuf)` — axum over `tokio::net::UnixListener` (axum 0.8 `axum::serve` accepts it directly)
  - `admin::router(d: Arc<Daemon>) -> axum::Router` — separated from `serve` so tests can drive it in-process with `tower::ServiceExt::oneshot` (add dev-dependencies `tower = { version = "0.5", features = ["util"] }` and `http-body-util = "0.1"`)
  - Endpoints (spec §57 subset; all JSON except `/metrics`):
    - `GET /v1/status` → `{ "node": <name>, "plugins": { name: bool }, "queue": { state: count } }`
    - `GET /v1/plugins` → `{ name: { "connected": bool, "capabilities": {...} } }`
    - `GET /v1/routes` → `[ { "name", "sources": ["p:e"], "destinations": ["p:e"] } ]`
    - `GET /v1/queue` → `{ state: count }`
    - `GET /v1/messages/{id}` → trace: envelope metadata WITHOUT body (id, source, kind, timestamps, body_bytes) + deliveries array; 404 if unknown
    - `GET /metrics` → Prometheus text

- [ ] **Step 1: Write the failing tests**

Bottom of `switchyardd/src/admin.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{handle_inbound, Daemon};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn get(router: axum::Router, path: &str) -> (u16, String) {
        let resp = router
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn daemon() -> Arc<Daemon> {
        // reuse the engine test constructor shape: two mock plugins + one route
        let dir = tempfile::tempdir().unwrap();
        let d = crate::engine::tests_support::test_daemon(dir.path());
        std::mem::forget(dir); // keep the tempdir alive for the test process
        Arc::new(d)
    }

    #[tokio::test]
    async fn status_reports_node_and_queue() {
        let d = daemon();
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "hello".into(), None);
        let (code, body) = get(router(d), "/v1/status").await;
        assert_eq!(code, 200);
        assert!(body.contains("\"node\":\"t\""));
        assert!(body.contains("\"pending\":1"));
    }

    #[tokio::test]
    async fn trace_omits_body_and_404s_unknown() {
        let d = daemon();
        handle_inbound(&d, "mocka", "chan".into(), "!a".into(), "text".into(),
                       "secret-content".into(), None);
        let id = d.store.lock().unwrap()
            .due_deliveries(chrono::Utc::now(), 1).unwrap()[0].message_id;
        let (code, body) = get(router(d.clone()), &format!("/v1/messages/{id}")).await;
        assert_eq!(code, 200);
        assert!(!body.contains("secret-content"), "trace leaked message body");
        assert!(body.contains("\"deliveries\""));
        let (code, _) = get(router(d), &format!("/v1/messages/{}", uuid::Uuid::now_v7())).await;
        assert_eq!(code, 404);
    }

    #[tokio::test]
    async fn metrics_render() {
        let (code, body) = get(router(daemon()), "/metrics").await;
        assert_eq!(code, 200);
        assert!(body.contains("relayfabric_messages_ingress_total"));
    }
}
```

Move the Task 9 test helper into a shared spot so both test modules use it — in `engine.rs`, wrap the existing `test_daemon` function (the full body written in Task 9 Step 1, unchanged) in a `#[cfg(test)] pub mod tests_support { ... }` block with `pub fn test_daemon`, and have the Task 9 `tests` module call `tests_support::test_daemon` instead of holding its own copy. No logic changes — this is a cut-and-paste move of the function Task 9 already wrote.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -j2 -p switchyardd admin`
Expected: compile FAILURE.

- [ ] **Step 3: Implement admin.rs**

```rust
use crate::engine::Daemon;
use crate::metrics;
use axum::extract::{Path as AxPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

pub fn router(d: Arc<Daemon>) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/plugins", get(plugins))
        .route("/v1/routes", get(routes))
        .route("/v1/queue", get(queue))
        .route("/v1/messages/{id}", get(trace))
        .route("/metrics", get(metrics_text))
        .with_state(d)
}

pub async fn serve(d: Arc<Daemon>, socket: PathBuf) {
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind admin socket");
    axum::serve(listener, router(d)).await.expect("admin serve");
}

fn queue_map(d: &Daemon) -> BTreeMap<String, i64> {
    d.store.lock().unwrap().queue_counts().unwrap_or_default().into_iter().collect()
}

fn plugin_state(d: &Daemon) -> Vec<(String, bool)> {
    let connected = d.plugins.lock().unwrap();
    d.cfg.plugins.iter()
        .filter(|(_, p)| p.enabled)
        .map(|(name, _)| {
            (name.clone(), connected.get(name).map(|h| h.connected).unwrap_or(false))
        })
        .collect()
}

async fn status(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let plugins: BTreeMap<_, _> = plugin_state(&d).into_iter().collect();
    Json(json!({ "node": d.cfg.node.name, "plugins": plugins, "queue": queue_map(&d) }))
}

async fn plugins(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let handles = d.plugins.lock().unwrap();
    let out: BTreeMap<String, serde_json::Value> = d.cfg.plugins.iter()
        .filter(|(_, p)| p.enabled)
        .map(|(name, _)| {
            let h = handles.get(name);
            (name.clone(), json!({
                "connected": h.map(|h| h.connected).unwrap_or(false),
                "capabilities": h.map(|h| serde_json::to_value(&h.capabilities).unwrap()),
            }))
        })
        .collect();
    Json(out)
}

async fn routes(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let out: Vec<_> = d.cfg.routes.iter().map(|r| json!({
        "name": r.name,
        "sources": r.sources.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        "destinations": r.destinations.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
    })).collect();
    Json(out)
}

async fn queue(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    Json(queue_map(&d))
}

async fn trace(
    State(d): State<Arc<Daemon>>,
    AxPath(id): AxPath<Uuid>,
) -> impl IntoResponse {
    let store = d.store.lock().unwrap();
    let Ok(Some(env)) = store.get_message(id) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "unknown message"})));
    };
    let deliveries: Vec<_> = store.deliveries_for(id).unwrap_or_default().iter()
        .map(|del| json!({
            "route": del.route,
            "destination": del.destination.to_string(),
            "state": del.state,
            "attempts": del.attempt_count,
            "reason": del.reason,
        }))
        .collect();
    // spec §90: trace without content — body is summarized, never included
    (StatusCode::OK, Json(json!({
        "id": env.id,
        "source": env.source.to_string(),
        "kind": env.kind,
        "created_at": env.created_at,
        "received_at": env.received_at,
        "expires_at": env.expires_at,
        "body_bytes": env.body.len(),
        "deliveries": deliveries,
    })))
}

async fn metrics_text(State(d): State<Arc<Daemon>>) -> impl IntoResponse {
    let q = d.store.lock().unwrap().queue_counts().unwrap_or_default();
    metrics::render(&q, &plugin_state(&d))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -j2 -p switchyardd`
Expected: all pass.

- [ ] **Step 5: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add switchyardd
git commit -m "feat: admin API and metrics over unix socket"
```

---

### Task 11: switchyardctl

**Files:**
- Create: `switchyardctl/Cargo.toml`, `switchyardctl/src/main.rs`
- Modify: root `Cargo.toml` (uncomment member)

**Interfaces:**
- Consumes: the admin API (Task 10) over `<data_dir>/admin.sock`
- Produces: CLI commands `status`, `plugins`, `routes`, `queue`, `trace <message-id>`; global flag `--socket <path>` (default `/var/lib/relayfabric/admin.sock`). Exits 0 on success, 1 on connection/HTTP error, 2 on usage error.

- [ ] **Step 1: Create crate**

`switchyardctl/Cargo.toml`:
```toml
[package]
name = "switchyardctl"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
serde_json.workspace = true
```

- [ ] **Step 2: Write the failing tests**

Bottom of `switchyardctl/src/main.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_commands_to_paths() {
        assert_eq!(path_for(&["status".into()]).unwrap(), "/v1/status");
        assert_eq!(path_for(&["plugins".into()]).unwrap(), "/v1/plugins");
        assert_eq!(path_for(&["routes".into()]).unwrap(), "/v1/routes");
        assert_eq!(path_for(&["queue".into()]).unwrap(), "/v1/queue");
        assert_eq!(
            path_for(&["trace".into(), "01890000-0000-7000-8000-000000000000".into()]).unwrap(),
            "/v1/messages/01890000-0000-7000-8000-000000000000"
        );
        assert!(path_for(&[]).is_err());
        assert!(path_for(&["trace".into()]).is_err());
        assert!(path_for(&["bogus".into()]).is_err());
    }

    #[test]
    fn strips_http_response_headers() {
        let raw = "HTTP/1.0 200 OK\r\ncontent-type: application/json\r\n\r\n{\"a\":1}";
        assert_eq!(body_of(raw).unwrap(), "{\"a\":1}");
        assert!(body_of("HTTP/1.0 404 Not Found\r\n\r\n{}").is_err());
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -j2 -p switchyardctl`
Expected: compile FAILURE.

- [ ] **Step 4: Implement main.rs**

```rust
//! Thin client for the switchyardd admin API.
// ponytail: hand-rolled HTTP/1.0 over UnixStream — zero client deps, and the
// server closes the connection after each response. Swap for a real client
// only when the API needs POSTs with bodies.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

fn path_for(args: &[String]) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("status") => Ok("/v1/status".into()),
        Some("plugins") => Ok("/v1/plugins".into()),
        Some("routes") => Ok("/v1/routes".into()),
        Some("queue") => Ok("/v1/queue".into()),
        Some("trace") => match args.get(1) {
            Some(id) => Ok(format!("/v1/messages/{id}")),
            None => Err("usage: switchyardctl trace <message-id>".into()),
        },
        _ => Err("usage: switchyardctl [--socket <path>] \
                  status|plugins|routes|queue|trace <id>".into()),
    }
}

fn body_of(raw: &str) -> Result<String, String> {
    let (head, body) = raw.split_once("\r\n\r\n").ok_or("malformed HTTP response")?;
    let status = head.split_whitespace().nth(1).unwrap_or("0");
    if status != "200" {
        return Err(format!("HTTP {status}: {body}"));
    }
    Ok(body.to_string())
}

fn fetch(socket: &str, path: &str) -> Result<String, String> {
    let mut s = UnixStream::connect(socket)
        .map_err(|e| format!("cannot connect to {socket}: {e}"))?;
    write!(s, "GET {path} HTTP/1.0\r\nhost: localhost\r\n\r\n").map_err(|e| e.to_string())?;
    let mut raw = String::new();
    s.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    body_of(&raw)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = String::from("/var/lib/relayfabric/admin.sock");
    if args.first().map(String::as_str) == Some("--socket") {
        args.remove(0);
        socket = if args.is_empty() { socket } else { args.remove(0) };
    }
    let path = match path_for(&args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    match fetch(&socket, &path) {
        Ok(body) => {
            let pretty = serde_json::from_str::<serde_json::Value>(&body)
                .and_then(|v| serde_json::to_string_pretty(&v))
                .unwrap_or(body);
            println!("{pretty}");
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -j2 -p switchyardctl`
Expected: 2 passed.

- [ ] **Step 6: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add Cargo.toml switchyardctl
git commit -m "feat: switchyardctl admin CLI"
```

---

### Task 12: End-to-end integration tests

**Files:**
- Create: `switchyardd/tests/e2e.rs`

**Interfaces:**
- Consumes: the `switchyardd` binary (`env!("CARGO_BIN_EXE_switchyardd")`), `relay-ipc` frames, the admin socket. The tests ARE the mock plugins: they connect to `plugins.sock` and speak Plugin Protocol v1 directly — no mock plugin binary exists (deleted from the design as unnecessary).

- [ ] **Step 1: Write the tests (they are the deliverable — no impl step)**

`switchyardd/tests/e2e.rs`:

```rust
use relay_core::Capabilities;
use relay_ipc::{read_frame, write_frame, DaemonToPlugin, PluginToDaemon, PROTOCOL_VERSION};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::time::timeout;

struct TestDaemon {
    child: Child,
    dir: tempfile::TempDir,
}

impl TestDaemon {
    fn plugin_sock(&self) -> PathBuf { self.dir.path().join("data/plugins.sock") }
    fn admin_sock(&self) -> PathBuf { self.dir.path().join("data/admin.sock") }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

const CONFIG: &str = r#"
node:
  name: e2e
  data_dir: DATA_DIR
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
"#;

fn start_daemon(dir: tempfile::TempDir) -> TestDaemon {
    let data = dir.path().join("data");
    let cfg_path = dir.path().join("relayfabric.yaml");
    std::fs::write(&cfg_path, CONFIG.replace("DATA_DIR", data.to_str().unwrap())).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_switchyardd"))
        .arg("--config").arg(&cfg_path)
        .spawn()
        .unwrap();
    TestDaemon { child, dir }
}

async fn wait_for(path: &Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("socket {} never appeared", path.display());
}

async fn connect_plugin(sock: &Path, name: &str) -> (OwnedReadHalf, OwnedWriteHalf) {
    let stream = UnixStream::connect(sock).await.unwrap();
    let (mut r, mut w) = stream.into_split();
    write_frame(&mut w, &PluginToDaemon::Hello {
        plugin: name.into(),
        version: "0".into(),
        protocol_version: PROTOCOL_VERSION,
        capabilities: Capabilities { max_payload: Some(200), ..Default::default() },
    }).await.unwrap();
    let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
    match ack {
        DaemonToPlugin::HelloAck { error: None, .. } => {}
        other => panic!("bad hello ack: {other:?}"),
    }
    (r, w)
}

async fn inbound(w: &mut OwnedWriteHalf, endpoint: &str, sender: &str, body: &str) {
    write_frame(w, &PluginToDaemon::Inbound {
        endpoint: endpoint.into(),
        sender: sender.into(),
        kind: "text".into(),
        body: body.into(),
        created_at: Some(chrono::Utc::now()),
    }).await.unwrap();
}

async fn expect_send(r: &mut OwnedReadHalf) -> (i64, String, String) {
    let msg: DaemonToPlugin = timeout(Duration::from_secs(10), read_frame(r))
        .await.expect("timed out waiting for Send").unwrap();
    match msg {
        DaemonToPlugin::Send { corr, endpoint, body, .. } => (corr, endpoint, body),
        other => panic!("expected Send, got {other:?}"),
    }
}

async fn admin_get(sock: &Path, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = UnixStream::connect(sock).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.0\r\nhost: x\r\n\r\n").as_bytes()).await.unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).await.unwrap();
    raw.split_once("\r\n\r\n").map(|x| x.1.to_string()).unwrap_or_default()
}

#[tokio::test]
async fn bridges_dedups_and_suppresses_echo() {
    let d = start_daemon(tempfile::tempdir().unwrap());
    wait_for(&d.plugin_sock()).await;
    let (mut ra, mut wa) = connect_plugin(&d.plugin_sock(), "mocka").await;
    let (mut rb, mut wb) = connect_plugin(&d.plugin_sock(), "mockb").await;

    // A → B with pseudonymized origin tag
    inbound(&mut wa, "chan", "!abcd1234", "hello from a").await;
    let (corr, endpoint, body) = expect_send(&mut rb).await;
    assert_eq!(endpoint, "chan");
    assert!(body.starts_with("[MOCK"), "body was: {body}");
    assert!(body.contains("hello from a"));
    assert!(!body.contains("!abcd1234"), "native id leaked: {body}");
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr, delivered: true, detail: None,
    }).await.unwrap();

    // exact duplicate is dropped: no second Send on B
    inbound(&mut wa, "chan", "!abcd1234", "hello from a").await;
    assert!(
        timeout(Duration::from_secs(2), read_frame::<_, DaemonToPlugin>(&mut rb))
            .await.is_err(),
        "duplicate was bridged"
    );

    // no echo back to A (reply direction still works)
    assert!(
        timeout(Duration::from_millis(500), read_frame::<_, DaemonToPlugin>(&mut ra))
            .await.is_err(),
        "message echoed to its ingress endpoint"
    );
    inbound(&mut wb, "chan", "peer-b", "reply from b").await;
    let (_, _, body) = expect_send(&mut ra).await;
    assert!(body.contains("reply from b"));

    // trace shows delivered state, no content
    let status = admin_get(&d.admin_sock(), "/v1/status").await;
    assert!(status.contains("\"delivered\""), "status was: {status}");
    assert!(!status.contains("hello from a"));
}

#[tokio::test]
async fn queues_for_offline_plugin_and_survives_restart() {
    let mut d = start_daemon(tempfile::tempdir().unwrap());
    wait_for(&d.plugin_sock()).await;
    let (_ra, mut wa) = connect_plugin(&d.plugin_sock(), "mocka").await;

    // B is not connected: delivery must queue
    inbound(&mut wa, "chan", "!abcd1234", "parked message").await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let queue = admin_get(&d.admin_sock(), "/v1/queue").await;
    assert!(queue.contains("\"pending\":1"), "queue was: {queue}");

    // hard-kill the daemon and restart on the same data_dir
    d.child.kill().unwrap();
    d.child.wait().unwrap();
    // remove the stale socket file so wait_for sees the NEW daemon's bind
    let _ = std::fs::remove_file(d.plugin_sock());
    let cfg_path = d.dir.path().join("relayfabric.yaml");
    d.child = Command::new(env!("CARGO_BIN_EXE_switchyardd"))
        .arg("--config").arg(&cfg_path)
        .spawn().unwrap();
    wait_for(&d.plugin_sock()).await;

    // B connects after restart and receives the parked message (spec §68)
    let (mut rb, mut wb) = connect_plugin(&d.plugin_sock(), "mockb").await;
    let (corr, _, body) = expect_send(&mut rb).await;
    assert!(body.contains("parked message"));
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr, delivered: true, detail: None,
    }).await.unwrap();
}

#[tokio::test]
async fn rejects_unknown_plugin_name() {
    let d = start_daemon(tempfile::tempdir().unwrap());
    wait_for(&d.plugin_sock()).await;
    let stream = UnixStream::connect(&d.plugin_sock()).await.unwrap();
    let (mut r, mut w) = stream.into_split();
    write_frame(&mut w, &PluginToDaemon::Hello {
        plugin: "intruder".into(),
        version: "0".into(),
        protocol_version: PROTOCOL_VERSION,
        capabilities: Capabilities::default(),
    }).await.unwrap();
    let DaemonToPlugin::HelloAck { error: Some(_), .. } = read_frame(&mut r).await.unwrap()
    else { panic!("unknown plugin was accepted") };
}
```

Note for the daemon under test: sockets live at `<data_dir>/plugins.sock` per Task 9; the test uses `dir/data` as data_dir so a restart reuses the same SQLite file. `wait_for` polls for the socket file. Failed-delivery retry timing (5s first backoff) is why `expect_send` allows 10s.

- [ ] **Step 2: Run the tests**

Run: `cargo test -j2 -p switchyardd --test e2e`
Expected: 3 passed. If `bridges_dedups_and_suppresses_echo` flakes on timing, the fix is polling loops, not longer sleeps — the only fixed sleeps allowed are the two negative assertions.

- [ ] **Step 3: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add switchyardd/tests
git commit -m "test: end-to-end bridge, dedup, echo-suppression, restart recovery"
```

---

### Task 13: MQTT plugin (relayfabric-mqtt)

**Files:**
- Create: `plugins/mqtt/Cargo.toml`, `plugins/mqtt/src/main.rs`
- Modify: root `Cargo.toml` (uncomment member)

**Interfaces:**
- Consumes: `relay-ipc` protocol; env vars `RELAYFABRIC_SOCKET`, `RELAYFABRIC_PLUGIN_NAME`, `RELAYFABRIC_PLUGIN_CONFIG`
- Produces: binary `relayfabric-mqtt`. Endpoint = MQTT topic. Config JSON: `{ "broker": "mqtt://host:port", "topics": ["chat/general"], "client_id": "relayfabric" }`. Uses MQTT v5 with the **No Local** subscription option so the broker never echoes our own publishes back (loop prevention at the transport, complementing daemon-side echo exclusion). Inbound `sender` is the topic (MQTT publishes carry no sender identity — ponytail: alias is stable per topic, good enough until MQTT v5 user-properties are worth parsing).

- [ ] **Step 1: Create crate**

`plugins/mqtt/Cargo.toml`:
```toml
[package]
name = "relayfabric-mqtt"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[[bin]]
name = "relayfabric-mqtt"
path = "src/main.rs"

[dependencies]
relay-core.workspace = true
relay-ipc.workspace = true
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
tokio.workspace = true
rumqttc.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

- [ ] **Step 2: Write the failing unit tests**

Bottom of `plugins/mqtt/src/main.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_broker_url() {
        assert_eq!(parse_broker("mqtt://10.0.0.5:1883").unwrap(), ("10.0.0.5".into(), 1883));
        assert_eq!(parse_broker("mqtt://broker.local").unwrap(), ("broker.local".into(), 1883));
        assert!(parse_broker("http://x").is_err());
    }

    #[test]
    fn config_defaults() {
        let cfg: PluginCfg = serde_json::from_str(
            r#"{"broker":"mqtt://127.0.0.1:1883","topics":["a/b"]}"#).unwrap();
        assert_eq!(cfg.client_id, "relayfabric");
        assert_eq!(cfg.topics, vec!["a/b"]);
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -j2 -p relayfabric-mqtt`
Expected: compile FAILURE.

- [ ] **Step 4: Implement main.rs**

```rust
//! RelayFabric MQTT plugin: topics ↔ fabric endpoints over MQTT v5.

use relay_core::Capabilities;
use relay_ipc::{read_frame, write_frame, DaemonToPlugin, PluginToDaemon, PROTOCOL_VERSION};
use rumqttc::v5::mqttbytes::v5::Filter;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::{AsyncClient, Event, Incoming, MqttOptions};
use serde::Deserialize;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct PluginCfg {
    broker: String,
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default = "default_client_id")]
    client_id: String,
}

fn default_client_id() -> String { "relayfabric".into() }

fn parse_broker(url: &str) -> Result<(String, u16), String> {
    let rest = url.strip_prefix("mqtt://").ok_or("broker must be mqtt://host[:port]")?;
    match rest.split_once(':') {
        Some((host, port)) => Ok((host.into(),
            port.parse().map_err(|_| "bad port".to_string())?)),
        None => Ok((rest.into(), 1883)),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    let socket = std::env::var("RELAYFABRIC_SOCKET").expect("RELAYFABRIC_SOCKET");
    let name = std::env::var("RELAYFABRIC_PLUGIN_NAME").unwrap_or_else(|_| "mqtt".into());
    let cfg: PluginCfg = serde_json::from_str(
        &std::env::var("RELAYFABRIC_PLUGIN_CONFIG").expect("RELAYFABRIC_PLUGIN_CONFIG"),
    ).expect("valid plugin config JSON");

    let (host, port) = parse_broker(&cfg.broker).expect("broker url");
    let mut opts = MqttOptions::new(&cfg.client_id, host, port);
    opts.set_keep_alive(Duration::from_secs(30));
    let (client, mut eventloop) = AsyncClient::new(opts, 64);

    let stream = tokio::net::UnixStream::connect(&socket).await.expect("daemon socket");
    let (mut r, mut w) = stream.into_split();
    write_frame(&mut w, &PluginToDaemon::Hello {
        plugin: name.clone(),
        version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: PROTOCOL_VERSION,
        capabilities: Capabilities {
            groups: true, max_payload: Some(64_000), ..Default::default()
        },
    }).await.expect("hello");
    match read_frame::<_, DaemonToPlugin>(&mut r).await.expect("hello ack") {
        DaemonToPlugin::HelloAck { error: None, .. } => info!("registered with switchyardd"),
        DaemonToPlugin::HelloAck { error: Some(e), .. } => panic!("daemon refused us: {e}"),
        other => panic!("unexpected ack: {other:?}"),
    }

    // No Local: broker must not echo our own publishes (MQTT v5) — the
    // transport-level half of loop prevention.
    let filters: Vec<Filter> = cfg.topics.iter().map(|t| {
        let mut f = Filter::new(t.clone(), QoS::AtLeastOnce);
        f.nolocal = true;
        f
    }).collect();
    if !filters.is_empty() {
        client.subscribe_many(filters).await.expect("subscribe");
    }

    loop {
        tokio::select! {
            event = eventloop.poll() => match event {
                Ok(Event::Incoming(Incoming::Publish(p))) => {
                    let topic = String::from_utf8_lossy(&p.topic).into_owned();
                    let body = String::from_utf8_lossy(&p.payload).into_owned();
                    let msg = PluginToDaemon::Inbound {
                        endpoint: topic.clone(),
                        sender: topic, // MQTT has no per-message sender identity
                        kind: "text".into(),
                        body,
                        created_at: Some(chrono::Utc::now()),
                    };
                    if write_frame(&mut w, &msg).await.is_err() {
                        warn!("daemon connection lost");
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(error = %e, "mqtt error, reconnecting in 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            },
            frame = read_frame::<_, DaemonToPlugin>(&mut r) => match frame {
                Ok(DaemonToPlugin::Send { corr, endpoint, body, .. }) => {
                    let ok = client
                        .publish(endpoint, QoS::AtLeastOnce, false, body.into_bytes())
                        .await
                        .is_ok();
                    let result = PluginToDaemon::DeliveryResult {
                        corr, delivered: ok,
                        detail: (!ok).then(|| "publish failed".into()),
                    };
                    if write_frame(&mut w, &result).await.is_err() {
                        return;
                    }
                }
                Ok(DaemonToPlugin::Shutdown) | Err(_) => return,
                Ok(_) => {}
            },
        }
    }
}
```

If the rumqttc 0.24 v5 API differs on `Filter` construction (`nolocal` field vs builder), check `docs.rs/rumqttc` for the pinned version and adjust — the requirement that survives any API shape: v5 subscribe with No Local set.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -j2 -p relayfabric-mqtt`
Expected: 2 passed.

- [ ] **Step 6: Live smoke test (skips without a broker)**

Append to the tests module:

```rust
    /// Live check against a local broker; run with: cargo test -j2 -p relayfabric-mqtt -- --ignored
    #[test]
    #[ignore = "needs an MQTT broker on 127.0.0.1:1883 and a running switchyardd"]
    fn live_smoke() {
        // documented manual procedure, asserted by eye:
        // 1. mosquitto -p 1883
        // 2. switchyardd --config docs/relayfabric.example.yaml (mqtt enabled,
        //    route mqtt:chat/a <-> mqtt:chat/b)
        // 3. mosquitto_pub -t chat/a -m "ping"
        // 4. mosquitto_sub -t chat/b   → expect "[MQTT-XXXX]\nping"
    }
```

- [ ] **Step 7: Clippy + commit**

```bash
cargo clippy -j2 --workspace --all-targets
git add Cargo.toml plugins/mqtt
git commit -m "feat: MQTT plugin with v5 no-local loop prevention"
```

---

### Task 14: Example config, README, final sweep

**Files:**
- Create: `docs/relayfabric.example.yaml`
- Modify: `README.md`

- [ ] **Step 1: Write the example config**

`docs/relayfabric.example.yaml`:

```yaml
# RelayFabric example configuration. Deny by default: nothing is bridged
# unless a route says so (spec §38). Validate with: switchyardd --check-config
node:
  name: example-gateway
  data_dir: /var/lib/relayfabric

plugins:
  mqtt:
    enabled: true
    # Managed by switchyardd; omit `command` to run the plugin yourself
    # (it connects to <data_dir>/plugins.sock using RELAYFABRIC_SOCKET).
    command: relayfabric-mqtt
    config:
      broker: mqtt://127.0.0.1:1883
      topics: [chat/a, chat/b]

routes:
  - name: demo
    sources: ["mqtt:chat/a", "mqtt:chat/b"]
    destinations: ["mqtt:chat/a", "mqtt:chat/b"]

policies:
  - name: small-payloads
    match:
      destination_protocol: [mqtt]
    rules:
      max_payload: 4096
      drop_kinds: [location]   # location never crosses by default (spec §74)

# TTLs and limits (seconds)
ttl_default_secs: 86400
dedup_ttl_secs: 86400
hop_limit: 8
```

- [ ] **Step 2: Write the README**

Replace `README.md` body with: one-paragraph project description (from spec §1), status line ("v0.1 slice: core daemon + MQTT plugin; LXMF/Signal/Meshtastic plugins are next"), build (`cargo build -j2 --release`), quick start (example config + mosquitto demo from Task 13's live smoke), pointers to `docs/SPEC.md` and `docs/webui-notes.md`, license note (MIT, permissive-only dependency policy). Keep it under 80 lines.

- [ ] **Step 3: Full verification sweep**

```bash
cargo test -j2 --workspace
cargo clippy -j2 --workspace --all-targets
cargo build -j2 --release
```
Expected: all tests pass, zero clippy warnings, release build clean.

- [ ] **Step 4: Commit**

```bash
git add docs/relayfabric.example.yaml README.md
git commit -m "docs: example config and README for v0.1 slice"
```

---

## Spec coverage self-check (for the reviewer)

| Spec item | Where |
|---|---|
| Canonical envelope §12–14 | Task 1 |
| Plugin IPC v1, CBOR over UDS §9–11 | Task 2 |
| Config + --check-config §58–59 | Task 3 |
| Route-scoped pseudonyms §19–20, secret handling §51 | Task 4 |
| Deduplication §28 | Task 5 |
| Routing, echo exclusion, deny-by-default §24, §38 | Task 6 |
| Policy engine + transform §17, §36–37, §83 | Task 6 |
| Persistence, queue states §40–41, §50 | Task 7 |
| Retry backoff, TTL, DLQ §42–44 | Tasks 7, 9 |
| Backpressure (bounded channels) §45 | Task 9 |
| Restart recovery §68 | Tasks 7, 9, 12 |
| Plugin supervision §69 | Task 9 |
| Admin API §57, trace §90, content-free logging §52 | Task 10 |
| Metrics §55 | Tasks 8, 10 |
| switchyardctl §102 | Task 11 |
| Loop prevention §27 | Tasks 6 (echo), 12 (test), 13 (MQTT no-local) |
| MQTT plugin §8 | Task 13 |

Deferred beyond this slice (per the slice design doc): LXMF/Signal/Meshtastic plugins, identity linking, federation, SIGNED/OPAQUE modes, attachments, rate limiting, audit table, hot reload, plugin manifests/sandboxing.

