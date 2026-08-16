use relay_core::Capabilities;
use relay_ipc::{read_frame, write_frame, DaemonToPlugin, IpcAttachment, PluginToDaemon, PROTOCOL_VERSION};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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

// mockc exists only for the attachment tests (attachments-capability-false
// destination). It rides its own "achan" endpoint on a separate "attach"
// route so it never becomes an extra pending destination for the plain
// "general"/"chan" tests below — those assert exact queue counts, which an
// unconnected third destination on the same route would silently inflate.
const CONFIG: &str = r#"
node:
  name: e2e
  data_dir: DATA_DIR
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
  mockc:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan", "mockb:chan"]
    destinations: ["mocka:chan", "mockb:chan"]
  - name: attach
    sources: ["mocka:achan"]
    destinations: ["mockb:achan", "mockc:achan"]
"#;

// spec §112.8: a per-sender budget of 1 message/minute on the same "general"
// route shape as CONFIG (minus mockc/attach, which this test doesn't need).
const RATE_LIMITED_CONFIG: &str = r#"
node:
  name: e2e-ratelimit
  data_dir: DATA_DIR
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
limits:
  per_sender:
    messages_per_minute: 1
    bytes_per_hour: 0
"#;

// identity-linking full-flow e2e (design §Lifecycle/§Rendering): "general"
// opts into identity_mode: linked so the round-trip's rendering step has
// something to observe. mocka plays plugin A (direct-capable — receives the
// SendDirect challenge and confirms it); mockb plays plugin B (an ordinary
// destination, used only to observe the pseudonym<->display_name swap).
const IDENTITY_CONFIG: &str = r#"
node:
  name: e2e-identity
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
    identity_mode: linked
"#;

// keep test output pristine: the daemon logs via tracing to stdout/stderr,
// which is irrelevant noise for these tests and must not pollute `cargo test`
// output.
fn spawn_daemon(cfg_path: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_switchyardd"))
        .arg("--config").arg(cfg_path)
        .env("RUST_LOG", "error")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn start_daemon(dir: tempfile::TempDir) -> TestDaemon {
    start_daemon_with_config(dir, CONFIG)
}

fn start_daemon_with_config(dir: tempfile::TempDir, config: &str) -> TestDaemon {
    let data = dir.path().join("data");
    let cfg_path = dir.path().join("relayfabric.yaml");
    std::fs::write(&cfg_path, config.replace("DATA_DIR", data.to_str().unwrap())).unwrap();
    let child = spawn_daemon(&cfg_path);
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

async fn connect_plugin_with_caps(
    sock: &Path,
    name: &str,
    capabilities: Capabilities,
) -> (OwnedReadHalf, OwnedWriteHalf) {
    let stream = UnixStream::connect(sock).await.unwrap();
    let (mut r, mut w) = stream.into_split();
    write_frame(&mut w, &PluginToDaemon::Hello {
        plugin: name.into(),
        version: "0".into(),
        protocol_version: PROTOCOL_VERSION,
        capabilities,
    }).await.unwrap();
    let ack: DaemonToPlugin = read_frame(&mut r).await.unwrap();
    match ack {
        DaemonToPlugin::HelloAck { error: None, .. } => {}
        other => panic!("bad hello ack: {other:?}"),
    }
    (r, w)
}

async fn connect_plugin(sock: &Path, name: &str) -> (OwnedReadHalf, OwnedWriteHalf) {
    connect_plugin_with_caps(
        sock, name, Capabilities { max_payload: Some(200), ..Default::default() },
    ).await
}

// created_at is caller-supplied (rather than sampled fresh inside this
// helper) so that a genuine "exact duplicate" resend can reuse the same
// instant: the daemon's dedup key incorporates created_at truncated to
// whole seconds (spec §28's timestamp_window), so two logically-identical
// resends generated moments apart by wall-clock `Utc::now()` calls can
// straddle a second boundary and land in different windows, which the
// daemon then — correctly — treats as distinct messages rather than a
// duplicate.
async fn inbound(
    w: &mut OwnedWriteHalf,
    endpoint: &str,
    sender: &str,
    body: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) {
    inbound_with_attachments(w, endpoint, sender, body, created_at, vec![]).await;
}

async fn inbound_with_attachments(
    w: &mut OwnedWriteHalf,
    endpoint: &str,
    sender: &str,
    body: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    attachments: Vec<IpcAttachment>,
) {
    inbound_with_priority(w, endpoint, sender, body, created_at, attachments, None).await;
}

#[allow(clippy::too_many_arguments)]
async fn inbound_with_priority(
    w: &mut OwnedWriteHalf,
    endpoint: &str,
    sender: &str,
    body: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    attachments: Vec<IpcAttachment>,
    priority: Option<&str>,
) {
    write_frame(w, &PluginToDaemon::Inbound {
        endpoint: endpoint.into(),
        sender: sender.into(),
        kind: "text".into(),
        body: body.into(),
        created_at: Some(created_at),
        attachments,
        priority: priority.map(String::from),
    }).await.unwrap();
}

async fn expect_send(r: &mut OwnedReadHalf) -> (i64, String, String, Vec<IpcAttachment>) {
    let msg: DaemonToPlugin = timeout(Duration::from_secs(10), read_frame(r))
        .await.expect("timed out waiting for Send").unwrap();
    match msg {
        DaemonToPlugin::Send { corr, endpoint, body, attachments, .. } =>
            (corr, endpoint, body, attachments),
        other => panic!("expected Send, got {other:?}"),
    }
}

async fn expect_send_direct(r: &mut OwnedReadHalf) -> (i64, String, String) {
    let msg: DaemonToPlugin = timeout(Duration::from_secs(10), read_frame(r))
        .await.expect("timed out waiting for SendDirect").unwrap();
    match msg {
        DaemonToPlugin::SendDirect { corr, native_ref, body } => (corr, native_ref, body),
        other => panic!("expected SendDirect, got {other:?}"),
    }
}

async fn admin_get(sock: &Path, path: &str) -> String {
    admin_request(sock, "GET", path, None).await.1
}

/// Hand-rolled HTTP/1.0 request over the admin socket, mirroring
/// switchyardctl's `fetch()` (POST/DELETE with a `Content-Length`-framed
/// JSON body) — switchyardctl is a separate binary crate, so its private
/// helpers aren't importable here; this reproduces the same wire framing
/// directly against a live daemon. Returns (status, body).
async fn admin_request(sock: &Path, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = UnixStream::connect(sock).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.0\r\nhost: x\r\n");
    match body {
        Some(b) => head.push_str(&format!(
            "content-type: application/json\r\ncontent-length: {}\r\n\r\n{b}", b.len(),
        )),
        None => head.push_str("\r\n"),
    }
    s.write_all(head.as_bytes()).await.unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).await.unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let status: u16 = head.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
    (status, body.to_string())
}

/// Polls an admin endpoint every 100ms (up to ~5s) until the response body
/// contains `needle`. Used in place of a fixed settle-sleep: the pump loop
/// and delivery-state writes are async, so a positive assertion must poll
/// for readiness rather than guess a sleep duration.
async fn poll_until_contains(sock: &Path, path: &str, needle: &str) -> String {
    let mut last = String::new();
    for _ in 0..50 {
        last = admin_get(sock, path).await;
        if last.contains(needle) {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {path} to contain {needle:?}; last body: {last}");
}

#[tokio::test]
async fn bridges_dedups_and_suppresses_echo() {
    let d = start_daemon(tempfile::tempdir().unwrap());
    wait_for(&d.plugin_sock()).await;
    let (mut ra, mut wa) = connect_plugin(&d.plugin_sock(), "mocka").await;
    let (mut rb, mut wb) = connect_plugin(&d.plugin_sock(), "mockb").await;

    // A → B with pseudonymized origin tag
    let sent_at = chrono::Utc::now();
    inbound(&mut wa, "chan", "!abcd1234", "hello from a", sent_at).await;
    let (corr, endpoint, body, _) = expect_send(&mut rb).await;
    assert_eq!(endpoint, "chan");
    assert!(body.starts_with("[MOCK"), "body was: {body}");
    assert!(body.contains("hello from a"));
    assert!(!body.contains("!abcd1234"), "native id leaked: {body}");
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr, delivered: true, detail: None,
    }).await.unwrap();

    // exact duplicate is dropped: no second Send on B (same created_at as
    // the original — an "exact" duplicate is identical in every dedup-key
    // field, not just body text)
    inbound(&mut wa, "chan", "!abcd1234", "hello from a", sent_at).await;
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
    inbound(&mut wb, "chan", "peer-b", "reply from b", chrono::Utc::now()).await;
    let (_, _, body, _) = expect_send(&mut ra).await;
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
    inbound(&mut wa, "chan", "!abcd1234", "parked message", chrono::Utc::now()).await;
    let queue = poll_until_contains(&d.admin_sock(), "/v1/queue", "\"pending\":1").await;
    assert!(queue.contains("\"pending\":1"), "queue was: {queue}");

    // a second, attachment-carrying message also queues while B is offline;
    // its bytes must survive a hard daemon kill+restart intact (CAS blob
    // written to disk, not held only in memory).
    let payload = b"bytes that must survive a daemon restart".to_vec();
    let expected_sha = hex::encode(Sha256::digest(&payload));
    inbound_with_attachments(&mut wa, "chan", "!abcd1234", "parked with attachment",
        chrono::Utc::now(),
        vec![IpcAttachment {
            filename: "restart.bin".into(),
            mime: "application/octet-stream".into(),
            data: payload.clone(),
        }],
    ).await;
    let cas_path = d.dir.path().join("data/attachments").join(&expected_sha);
    // handle_inbound writes the CAS blob synchronously before the delivery
    // row exists, but frame delivery + processing is still async from this
    // test's point of view: poll rather than assert immediately.
    wait_for(&cas_path).await;

    // hard-kill the daemon and restart on the same data_dir
    d.child.kill().unwrap();
    d.child.wait().unwrap();
    // remove the stale socket file so wait_for sees the NEW daemon's bind
    let _ = std::fs::remove_file(d.plugin_sock());
    let cfg_path = d.dir.path().join("relayfabric.yaml");
    d.child = spawn_daemon(&cfg_path);
    wait_for(&d.plugin_sock()).await;

    assert!(cas_path.exists(), "attachment blob did not survive the daemon kill+restart");

    // B connects after restart (with the attachments capability, so the
    // queued attachment actually rides along) and receives both parked
    // messages in order (spec §68).
    let (mut rb, mut wb) = connect_plugin_with_caps(&d.plugin_sock(), "mockb",
        Capabilities { max_payload: Some(200), attachments: true, ..Default::default() }).await;

    let (corr1, _, body1, attachments1) = expect_send(&mut rb).await;
    assert!(body1.contains("parked message"));
    assert!(attachments1.is_empty());
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr: corr1, delivered: true, detail: None,
    }).await.unwrap();

    let (corr2, _, body2, attachments2) = expect_send(&mut rb).await;
    assert!(body2.contains("parked with attachment"));
    assert_eq!(attachments2.len(), 1);
    assert_eq!(attachments2[0].data, payload, "attachment bytes were not intact after restart");
    assert_eq!(hex::encode(Sha256::digest(&attachments2[0].data)), expected_sha);
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr: corr2, delivered: true, detail: None,
    }).await.unwrap();
}

/// Covers Task 4's priority scheduling end to end (spec §39): several
/// bulk-priority messages queue for an offline plugin, then one
/// emergency-priority message queues last. Once the plugin connects, the
/// emergency message must be the FIRST Send it receives despite having
/// arrived after all the bulk ones — `due_deliveries`'s `ORDER BY priority
/// ASC, next_attempt ASC` overriding pure arrival order is the whole point
/// of this task.
#[tokio::test]
async fn emergency_priority_overtakes_bulk_priority_for_an_offline_plugin() {
    let d = start_daemon(tempfile::tempdir().unwrap());
    wait_for(&d.plugin_sock()).await;
    let (_ra, mut wa) = connect_plugin(&d.plugin_sock(), "mocka").await;

    // B is not connected: three bulk-priority messages queue first...
    for body in ["bulk one", "bulk two", "bulk three"] {
        inbound_with_priority(
            &mut wa, "chan", "!abcd1234", body, chrono::Utc::now(), vec![], Some("bulk"),
        ).await;
    }
    // ...then one emergency-priority message queues last.
    inbound_with_priority(
        &mut wa, "chan", "!abcd1234", "emergency evacuation notice", chrono::Utc::now(),
        vec![], Some("emergency"),
    ).await;

    let queue = poll_until_contains(&d.admin_sock(), "/v1/queue", "\"pending\":4").await;
    assert!(queue.contains("\"pending\":4"), "queue was: {queue}");

    // B connects: despite arriving last, the emergency message must be the
    // FIRST Send delivered.
    let (mut rb, mut wb) = connect_plugin(&d.plugin_sock(), "mockb").await;
    let (corr, _, body, _) = expect_send(&mut rb).await;
    assert!(body.contains("emergency evacuation notice"),
        "emergency message did not arrive first, body was: {body}");
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr, delivered: true, detail: None,
    }).await.unwrap();

    // the three bulk messages still follow, in some order, none lost.
    for _ in 0..3 {
        let (corr, _, body, _) = expect_send(&mut rb).await;
        assert!(body.contains("bulk "), "expected a bulk message, body was: {body}");
        write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
            corr, delivered: true, detail: None,
        }).await.unwrap();
    }
}

/// Covers Task 4's egress capability/policy split: the SAME inbound message
/// (carrying one attachment) fans out over the "attach" route to two
/// destinations that differ only in the `attachments` capability. B
/// declares it and must receive the attachment bytes unchanged (sha check);
/// C doesn't and must receive a body-only `[attachment omitted]` note with
/// no attachment data at all.
#[tokio::test]
async fn attachment_egress_is_capability_aware() {
    let d = start_daemon(tempfile::tempdir().unwrap());
    wait_for(&d.plugin_sock()).await;
    let (_ra, mut wa) = connect_plugin(&d.plugin_sock(), "mocka").await;
    let (mut rb, mut wb) = connect_plugin_with_caps(&d.plugin_sock(), "mockb",
        Capabilities { max_payload: Some(200), attachments: true, ..Default::default() }).await;
    let (mut rc, mut wc) = connect_plugin_with_caps(&d.plugin_sock(), "mockc",
        Capabilities { max_payload: Some(200), attachments: false, ..Default::default() }).await;

    let payload = b"\x89PNGfake-image-bytes-not-really-a-png".to_vec();
    let expected_sha = hex::encode(Sha256::digest(&payload));
    inbound_with_attachments(&mut wa, "achan", "!abcd1234", "look at this",
        chrono::Utc::now(),
        vec![IpcAttachment {
            filename: "photo.png".into(),
            mime: "image/png".into(),
            data: payload.clone(),
        }],
    ).await;

    // B: attachments capability true -> bytes ride along unchanged.
    let (corr_b, _, body_b, attachments_b) = expect_send(&mut rb).await;
    assert_eq!(attachments_b.len(), 1);
    assert_eq!(attachments_b[0].filename, "photo.png");
    assert_eq!(attachments_b[0].data, payload, "attachment bytes were altered in transit");
    assert_eq!(hex::encode(Sha256::digest(&attachments_b[0].data)), expected_sha);
    assert!(!body_b.contains("[attachment omitted]"), "body was: {body_b}");

    // C: attachments capability false -> stripped, noted, no attachment data.
    let (corr_c, _, body_c, attachments_c) = expect_send(&mut rc).await;
    assert!(attachments_c.is_empty(), "C lacks the attachments capability");
    assert!(body_c.contains("[attachment omitted]"), "body was: {body_c}");

    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr: corr_b, delivered: true, detail: None,
    }).await.unwrap();
    write_frame(&mut wc, &PluginToDaemon::DeliveryResult {
        corr: corr_c, delivered: true, detail: None,
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

/// Covers spec §112.3's public-gating validation at the binary level (not
/// just `config::validate`'s unit tests): a `node.public: true` config whose
/// `general` route has a destination protocol ("mockb") not covered by any
/// `public_services` egress must make `--check-config` fail loudly — exit 1
/// with stderr naming the uncovered route and protocol — rather than the
/// daemon silently starting in a misconfigured, non-compliant public state.
#[test]
fn check_config_rejects_a_public_node_with_an_uncovered_route() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let cfg_path = dir.path().join("relayfabric.yaml");
    let config = format!(
        r#"
node:
  name: e2e-public-gating
  public: true
  data_dir: {}
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
public_services:
  - name: partial-coverage
    type: chat
    ingress: [mocka]
    egress: []
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#,
        data.to_str().unwrap()
    );
    std::fs::write(&cfg_path, config).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_switchyardd"))
        .arg("--config").arg(&cfg_path)
        .arg("--check-config")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "check-config must exit 1 on an uncovered route");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("general"), "stderr should name the route: {stderr}");
    assert!(stderr.contains("mockb"), "stderr should name the uncovered protocol: {stderr}");
}

/// Covers spec §112.8's "unlimited on a public node isn't silently assumed
/// safe" note at the binary level: a `node.public: true` config that's
/// otherwise valid (routes fully covered by `public_services`) but leaves
/// every `per_sender`/`global` limit at its 0 (unlimited) default must still
/// pass `--check-config` (warning, not error — exit 0), while printing a
/// stderr warning pointing at SPEC §112.8.
#[test]
fn check_config_warns_on_public_node_with_no_limits_but_still_passes() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let cfg_path = dir.path().join("relayfabric.yaml");
    let config = format!(
        r#"
node:
  name: e2e-public-no-limits
  public: true
  data_dir: {}
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
public_services:
  - name: full-coverage
    type: chat
    ingress: [mocka]
    egress: [mockb]
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#,
        data.to_str().unwrap()
    );
    std::fs::write(&cfg_path, config).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_switchyardd"))
        .arg("--config").arg(&cfg_path)
        .arg("--check-config")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0),
        "a covered public config with unset limits must still pass check-config");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("node.public is true but limits are unset (unlimited); see SPEC §112.8"),
        "stderr should carry the unlimited-public-node warning: {stderr}");
}

/// Covers spec §112.8's per-sender rate limit end to end: with
/// `messages_per_minute: 1` configured, a second inbound from the SAME
/// sender within the same minute must never produce a `Send` to the
/// destination mock — it's dropped at ingress (`engine::handle_inbound`),
/// before routing ever runs, distinct from a queued-but-undelivered message.
#[tokio::test]
async fn sender_rate_limit_drops_the_second_inbound_from_the_same_sender() {
    let d = start_daemon_with_config(tempfile::tempdir().unwrap(), RATE_LIMITED_CONFIG);
    wait_for(&d.plugin_sock()).await;
    let (_ra, mut wa) = connect_plugin(&d.plugin_sock(), "mocka").await;
    let (mut rb, _wb) = connect_plugin(&d.plugin_sock(), "mockb").await;

    inbound(&mut wa, "chan", "!abcd1234", "first", chrono::Utc::now()).await;
    let (_, _, body, _) = expect_send(&mut rb).await;
    assert!(body.contains("first"), "body was: {body}");

    // second message, same sender, within the same 1/minute window: must
    // never arrive as a Send.
    inbound(&mut wa, "chan", "!abcd1234", "second", chrono::Utc::now()).await;
    assert!(
        timeout(Duration::from_secs(2), read_frame::<_, DaemonToPlugin>(&mut rb))
            .await.is_err(),
        "rate-limited message was bridged anyway"
    );
}

/// Full identity-linking round trip (design §Lifecycle/§Rendering, spec
/// §19/§21/§22/§95): initiate via the admin socket, the challenge code
/// arrives at the target plugin (A) as a `SendDirect`, A replies with the
/// code to confirm, the link shows up (masked, code absent) at
/// `/v1/identities`, a subsequent linked-mode route delivery renders A's
/// `display_name` at B instead of the pseudonym, and unlinking reverts
/// rendering to the pseudonym on the very next delivery.
#[tokio::test]
async fn identity_linking_full_flow_initiate_confirm_link_render_and_unlink() {
    let d = start_daemon_with_config(tempfile::tempdir().unwrap(), IDENTITY_CONFIG);
    wait_for(&d.plugin_sock()).await;

    // Plugin A ("mocka"): direct-capable — this is who the challenge targets
    // and who confirms it.
    let (mut ra, mut wa) = connect_plugin_with_caps(&d.plugin_sock(), "mocka",
        Capabilities { max_payload: Some(200), direct_messages: true, ..Default::default() }).await;
    // Plugin B ("mockb"): an ordinary destination on the "general" route,
    // used only to observe the rendered tag.
    let (mut rb, mut wb) = connect_plugin(&d.plugin_sock(), "mockb").await;

    // ---- 1. Initiate via the admin socket -------------------------------
    let link_req = serde_json::json!({
        "requester": "mockb:!bob-secret",
        "target": "mocka:!alice-secret",
        "display_name": "Jascha",
    }).to_string();
    let (status, resp_body) =
        admin_request(&d.admin_sock(), "POST", "/v1/identities/link", Some(&link_req)).await;
    assert_eq!(status, 202, "body was: {resp_body}");
    assert!(!resp_body.contains("!bob-secret"),
        "the requester's full ref must never leak in the 202 response: {resp_body}");
    let challenge_id = serde_json::from_str::<serde_json::Value>(&resp_body).unwrap()
        ["challenge_id"].as_i64().unwrap();
    assert!(challenge_id > 0);

    // ---- 2. SendDirect with the code arrives at A ------------------------
    let (corr, native_ref, sd_body) = expect_send_direct(&mut ra).await;
    assert_eq!(native_ref, "!alice-secret", "the target's native ref must be the SendDirect destination");
    assert!(sd_body.contains("RelayFabric verification code:"), "body was: {sd_body}");
    assert!(!sd_body.contains("!bob-secret"),
        "the requester's full ref must never appear in the challenge body: {sd_body}");
    let code = sd_body.split("code: ").nth(1).unwrap().split(' ').next().unwrap().to_string();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
    write_frame(&mut wa, &PluginToDaemon::DeliveryResult {
        corr, delivered: true, detail: None,
    }).await.unwrap();

    // ---- 3. A replies with the code to confirm ----------------------------
    inbound(&mut wa, "chan", "!alice-secret", &code, chrono::Utc::now()).await;

    // ---- 4. Poll /v1/identities until the link appears (masked, no code) --
    let identities =
        poll_until_contains(&d.admin_sock(), "/v1/identities", "\"display_name\":\"Jascha\"").await;
    assert!(!identities.contains(&code), "the code must never appear in an API response: {identities}");
    assert!(!identities.contains("!alice-secret"), "full target ref leaked: {identities}");
    assert!(!identities.contains("!bob-secret"), "full requester ref leaked: {identities}");
    let link_id = serde_json::from_str::<serde_json::Value>(&identities).unwrap()
        ["links"][0]["id"].as_i64().unwrap();

    // Drain A's best-effort confirmation notice so it doesn't stray into a
    // later read (and, while here, check its body too: still no secrets).
    let (confirm_corr, _, confirm_body) = expect_send_direct(&mut ra).await;
    assert!(!confirm_body.contains("!bob-secret"),
        "the requester's full ref must never appear in a confirmation notice: {confirm_body}");
    write_frame(&mut wa, &PluginToDaemon::DeliveryResult {
        corr: confirm_corr, delivered: true, detail: None,
    }).await.unwrap();

    // ---- 5. Linked-mode route delivery renders the display_name at B -----
    inbound(&mut wa, "chan", "!alice-secret", "hello team", chrono::Utc::now()).await;
    let (corr_b, _, body_b, _) = expect_send(&mut rb).await;
    assert!(body_b.starts_with("[Jascha]\n"), "body was: {body_b}");
    assert!(body_b.contains("hello team"));
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr: corr_b, delivered: true, detail: None,
    }).await.unwrap();

    // ---- 6. DELETE the link ------------------------------------------------
    let (status, _) = admin_request(
        &d.admin_sock(), "DELETE", &format!("/v1/identities/link/{link_id}"), None,
    ).await;
    assert_eq!(status, 204);

    // ---- 7. Next message from the same identity renders the pseudonym -----
    inbound(&mut wa, "chan", "!alice-secret", "hello again", chrono::Utc::now()).await;
    let (_, _, body_after_unlink, _) = expect_send(&mut rb).await;
    assert!(!body_after_unlink.contains("Jascha"),
        "after unlink, rendering must revert to the pseudonym: {body_after_unlink}");
    assert!(body_after_unlink.starts_with("[MOCK"), "body was: {body_after_unlink}");
}

// ---- config secret references (Task 3, design §2 / SPEC §51, §59) --------

/// Covers SPEC §59's "secrets references" `--check-config` validation at
/// the binary level: an unresolvable `${env:...}` reference in a plugin's
/// `config:` block must make `--check-config` fail loudly -- exit 1, with
/// stderr naming the reference form -- and, critically, must never echo
/// any value (there isn't one to leak here, since resolution failed, but
/// the reference form itself is the only thing allowed to appear).
#[test]
fn check_config_rejects_an_unresolvable_secret_reference_naming_the_reference() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let cfg_path = dir.path().join("relayfabric.yaml");
    let config = format!(
        r#"
node:
  name: e2e-secret-missing
  data_dir: {}
plugins:
  mocka:
    enabled: true
    config:
      token: "${{env:RF_E2E_CHECK_CONFIG_MISSING}}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#,
        data.to_str().unwrap()
    );
    std::fs::write(&cfg_path, config).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_switchyardd"))
        .arg("--config").arg(&cfg_path)
        .arg("--check-config")
        // ensure the referenced var really is unset for this child, no
        // matter what's in the outer test process's own environment.
        .env_remove("RF_E2E_CHECK_CONFIG_MISSING")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "check-config must exit 1 on an unresolvable secret ref");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("${env:RF_E2E_CHECK_CONFIG_MISSING}"),
        "stderr should name the reference form: {stderr}");
}

/// Covers the redaction half of the same invariant: when the reference
/// DOES resolve, `--check-config` success output must never print the
/// resolved value -- only the unresolved reference form (if anything at
/// all) may appear anywhere in stdout/stderr.
#[test]
fn check_config_succeeds_and_never_prints_the_resolved_secret_value() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let cfg_path = dir.path().join("relayfabric.yaml");
    let config = format!(
        r#"
node:
  name: e2e-secret-present
  data_dir: {}
plugins:
  mocka:
    enabled: true
    config:
      token: "${{env:RF_E2E_CHECK_CONFIG_PRESENT}}"
  mockb:
    enabled: true
routes:
  - name: general
    sources: ["mocka:chan"]
    destinations: ["mockb:chan"]
"#,
        data.to_str().unwrap()
    );
    std::fs::write(&cfg_path, config).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_switchyardd"))
        .arg("--config").arg(&cfg_path)
        .arg("--check-config")
        .env("RF_E2E_CHECK_CONFIG_PRESENT", "sentinel-checkconfig-77ab")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0), "check-config must pass once the reference resolves");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("sentinel-checkconfig-77ab"), "resolved secret leaked on stdout: {stdout}");
    assert!(!stderr.contains("sentinel-checkconfig-77ab"), "resolved secret leaked on stderr: {stderr}");
}

/// The core Task 3 invariant end to end: the RESOLVED secret value must
/// reach the plugin process, which reads it from the `RELAYFABRIC_PLUGIN_CONFIG`
/// env var `plugins::supervise` sets at spawn (design §2). Rather than
/// asserting against the in-memory `Config` (which `config.rs`'s own unit
/// tests already cover), this spawns the REAL daemon binary with a real
/// `command:` plugin and captures what actually lands in that plugin
/// process's environment -- the true IPC-adjacent handoff, not a stand-in.
#[tokio::test]
async fn plugin_config_secret_ref_resolves_to_real_value_over_supervise_env_var() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let out_file = dir.path().join("captured-plugin-config.txt");
    let cfg_path = dir.path().join("relayfabric.yaml");
    let config = format!(
        r#"
node:
  name: e2e-secret-forward
  data_dir: {}
plugins:
  mocka:
    enabled: true
    command: printenv RELAYFABRIC_PLUGIN_CONFIG > {}
    config:
      token: "${{env:RF_E2E_SUPERVISE_SECRET}}"
"#,
        data.to_str().unwrap(),
        out_file.to_str().unwrap(),
    );
    std::fs::write(&cfg_path, config).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_switchyardd"))
        .arg("--config").arg(&cfg_path)
        .env("RUST_LOG", "error")
        .env("RF_E2E_SUPERVISE_SECRET", "sentinel-supervise-e2e-9f3c")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    wait_for(&out_file).await;
    // the plugin process's shell redirect can still be mid-flush right as
    // the file first appears; poll for non-empty content rather than
    // asserting immediately.
    let mut captured = String::new();
    for _ in 0..50 {
        captured = std::fs::read_to_string(&out_file).unwrap_or_default();
        if !captured.trim().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    let _ = child.wait();

    assert!(captured.contains("sentinel-supervise-e2e-9f3c"),
        "resolved secret must reach the plugin process's env: {captured:?}");
    assert!(!captured.contains("${env:"),
        "the unresolved reference form must never cross into the plugin's env: {captured:?}");
}
