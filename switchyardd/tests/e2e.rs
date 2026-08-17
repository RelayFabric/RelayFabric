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

// Task 5's full-workflow e2e (design §Testing): one route, two plugins --
// deliberately smaller than CONFIG above (no third "attach" route/plugin),
// since this test's whole point is a SECOND route the workflow itself adds
// via PUT /v1/config, not anything pre-wired.
const WEBUI_WORKFLOW_CONFIG: &str = r#"
node:
  name: e2e-webui-workflow
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
"#;

// Transport-class cycle Task 4 (design §3/§113.4, e2e): "mixed" fans one
// inbound message out to two destinations that differ only in transport
// class -- mockb is pinned to Meshtastic (237 B payload cap, images/video
// forbidden) via the transports: block; mockc has NO entry at all and
// resolves to the TerrestrialInternet default (non-constraining, per
// `Config::transport_policy`'s documented backward-compat anchor). Mirrors
// `attachment_egress_is_capability_aware`'s fan-out shape, swapping the
// capability axis for the transport-class axis.
const TRANSPORT_CLASS_CONFIG: &str = r#"
node:
  name: e2e-transport-class
  data_dir: DATA_DIR
plugins:
  mocka:
    enabled: true
  mockb:
    enabled: true
  mockc:
    enabled: true
routes:
  - name: mixed
    sources: ["mocka:achan"]
    destinations: ["mockb:achan", "mockc:achan"]
transports:
  mockb: { class: meshtastic }
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

/// Like `admin_request`, but also returns the raw response head (status
/// line + headers, lowercased) — none of the existing callers have ever
/// needed a header (only status + body), so this is kept separate rather
/// than changing `admin_request`'s widely-used signature. Task 3 (design
/// §3) needs this once, to assert `/docs` is actually served as
/// `text/html`.
async fn admin_get_with_head(sock: &Path, path: &str) -> (u16, String, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = UnixStream::connect(sock).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.0\r\nhost: x\r\n\r\n").as_bytes()).await.unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).await.unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let status: u16 = head.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
    (status, head.to_lowercase(), body.to_string())
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

/// Opens a raw HTTP/1.0 SSE connection to `/v1/events`, mirroring
/// `events_stream_over_http_1_0_flushes_incrementally_not_buffered_to_eof`'s
/// wire framing (switchyardctl is a separate binary crate, unreachable from
/// here -- see that test's doc comment). Returns the still-open stream; the
/// caller drives it with `poll_stream_until_contains` below rather than ever
/// reading to EOF, since `/v1/events` streams for as long as the daemon is
/// alive.
async fn open_events_stream(sock: &Path) -> UnixStream {
    use tokio::io::AsyncWriteExt;
    let mut s = UnixStream::connect(sock).await.unwrap();
    s.write_all(b"GET /v1/events HTTP/1.0\r\nhost: x\r\n\r\n").await.unwrap();
    s
}

/// Polls an already-open SSE stream (`open_events_stream`) with a bounded
/// per-attempt read timeout, appending every byte read into `collected`,
/// until `collected` contains `needle` -- the same "poll rather than
/// sleep-and-hope" convention as `poll_until_contains`, adapted for a
/// stream that never reaches EOF on its own while the daemon is alive.
async fn poll_stream_until_contains(s: &mut UnixStream, collected: &mut String, needle: &str) {
    poll_stream_until_count(s, collected, needle, 1).await;
}

/// Like `poll_stream_until_contains`, but waits until `needle` has appeared
/// at least `min_count` times -- for asserting a REPEAT of an event type the
/// buffer already contains (e.g. rollback's second `config_applied`).
async fn poll_stream_until_count(
    s: &mut UnixStream, collected: &mut String, needle: &str, min_count: usize,
) {
    use tokio::io::AsyncReadExt;
    if collected.matches(needle).count() >= min_count {
        return;
    }
    let mut buf = [0u8; 4096];
    for _ in 0..100 {
        match timeout(Duration::from_millis(100), s.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF -- shouldn't happen while the daemon is alive
            Ok(Ok(n)) => {
                collected.push_str(&String::from_utf8_lossy(&buf[..n]));
                if collected.matches(needle).count() >= min_count {
                    return;
                }
            }
            Ok(Err(e)) => panic!("SSE read error: {e}"),
            Err(_) => continue, // no bytes ready this tick -- keep polling
        }
    }
    panic!("timed out waiting for SSE stream to contain {needle:?} x{min_count}; collected so far: {collected}");
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

/// Transport-class cycle Task 4 (design §3/§113.4, e2e): the destination
/// plugin's TRANSPORT -- not just its protocol `Capabilities` -- degrades
/// an outgoing message. mockb is pinned to Meshtastic (237 B payload cap,
/// images/video forbidden); mockc has no `transports:` entry at all and
/// resolves to the non-constraining TerrestrialInternet default. Each
/// inbound message fans out to both over the "mixed" route.
///
/// Two sends split the two composed behaviors so each is asserted on its
/// own terms rather than fighting each other for space in the same body:
/// - send 1 (short body + image): proves image->note demotion LITERALLY --
///   mockb's body contains the exact `"[image '<file>' omitted --
///   constrained transport]"` note and carries zero attachments; mockc
///   gets the image intact and no demotion note.
/// - send 2 (oversize body + video): proves the payload-cap composition
///   min(plugin cap, transport cap) -- mockb's body is hard-capped to
///   Meshtastic's 237 B with a visible ellipsis tail (the demotion note,
///   appended AFTER the body in `engine::process_due`, is itself truncated
///   away by that same cap here -- render() keeps the FRONT of the
///   assembled string, so a body already exceeding the cap always evicts
///   any note behind it; that's exactly why send 1 above, not this one, is
///   what proves the note text survives). mockc's body arrives byte-for-
///   byte untruncated, since its transport imposes no cap.
///
/// `relayfabric_transport_demoted_total` is polled after each send and
/// asserted at an EXACT count (unlike the unit-test caution documented on
/// `load_attachments`'s callers in engine.rs) because this e2e test spawns
/// its own daemon subprocess -- the counter isn't shared with any other
/// test.
#[tokio::test]
async fn transport_class_constrained_route_demotes_media() {
    let d = start_daemon_with_config(tempfile::tempdir().unwrap(), TRANSPORT_CLASS_CONFIG);
    wait_for(&d.plugin_sock()).await;
    let (_ra, mut wa) = connect_plugin(&d.plugin_sock(), "mocka").await;
    let (mut rb, mut wb) = connect_plugin_with_caps(&d.plugin_sock(), "mockb",
        Capabilities { attachments: true, ..Default::default() }).await;
    let (mut rc, mut wc) = connect_plugin_with_caps(&d.plugin_sock(), "mockc",
        Capabilities { attachments: true, ..Default::default() }).await;

    // ---- send 1: short body + image -- proves the literal note text and
    // selective (image-only) demotion.
    let payload = b"\x89PNGfake-image-bytes-not-really-a-png".to_vec();
    let expected_sha = hex::encode(Sha256::digest(&payload));
    inbound_with_attachments(&mut wa, "achan", "!abcd1234", "constrained link test",
        chrono::Utc::now(),
        vec![IpcAttachment {
            filename: "photo.png".into(),
            mime: "image/png".into(),
            data: payload.clone(),
        }],
    ).await;

    let (corr_b1, _, body_b1, att_b1) = expect_send(&mut rb).await;
    assert!(att_b1.is_empty(), "an image must never reach a transport that forbids images");
    assert!(body_b1.contains("[image 'photo.png' omitted — constrained transport]"),
        "body was: {body_b1}");
    assert!(body_b1.len() <= 237,
        "body must stay within the Meshtastic transport cap: {} bytes", body_b1.len());
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr: corr_b1, delivered: true, detail: None,
    }).await.unwrap();

    let (corr_c1, _, body_c1, att_c1) = expect_send(&mut rc).await;
    assert_eq!(att_c1.len(), 1, "the internet-default sibling must still receive the image");
    assert_eq!(att_c1[0].data, payload, "attachment bytes were altered in transit");
    assert_eq!(hex::encode(Sha256::digest(&att_c1[0].data)), expected_sha);
    assert!(body_c1.contains("constrained link test"), "body was: {body_c1}");
    assert!(!body_c1.contains("omitted"),
        "the non-constraining sibling must apply no demotion: {body_c1}");
    write_frame(&mut wc, &PluginToDaemon::DeliveryResult {
        corr: corr_c1, delivered: true, detail: None,
    }).await.unwrap();

    poll_until_contains(&d.admin_sock(), "/metrics", "relayfabric_transport_demoted_total 1").await;

    // ---- send 2: oversize body + video -- proves the payload-cap
    // composition (transport cap tighter than the plugin's own, which is
    // unset here i.e. unlimited).
    let big_body = "Y".repeat(2000);
    inbound_with_attachments(&mut wa, "achan", "!abcd1234", &big_body,
        chrono::Utc::now(),
        vec![IpcAttachment {
            filename: "clip.mp4".into(),
            mime: "video/mp4".into(),
            data: vec![3u8; 40],
        }],
    ).await;

    let (corr_b2, _, body_b2, att_b2) = expect_send(&mut rb).await;
    assert!(att_b2.is_empty(), "a video must never reach a transport that forbids video");
    assert!(body_b2.len() <= 237,
        "body must be capped to the tighter TRANSPORT limit, not left unbounded: {} bytes",
        body_b2.len());
    assert!(body_b2.ends_with('…'), "an oversize body must show visible truncation: {body_b2}");
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr: corr_b2, delivered: true, detail: None,
    }).await.unwrap();

    let (corr_c2, _, body_c2, att_c2) = expect_send(&mut rc).await;
    assert_eq!(att_c2.len(), 1, "the internet-default sibling must receive the video too");
    assert!(body_c2.contains(&big_body),
        "the non-constraining sibling must deliver the body byte-for-byte, untruncated: len {}",
        body_c2.len());
    write_frame(&mut wc, &PluginToDaemon::DeliveryResult {
        corr: corr_c2, delivered: true, detail: None,
    }).await.unwrap();

    poll_until_contains(&d.admin_sock(), "/metrics", "relayfabric_transport_demoted_total 2").await;
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

/// SSE over HTTP/1.0 (design §4's ctl transport choice): proves the core
/// assumption switchyardctl's `events` command (switchyardctl/src/main.rs)
/// relies on -- that axum/hyper flushes a `Content-Length`-less streaming
/// body to an HTTP/1.0 client INCREMENTALLY, as `/v1/events`'s underlying
/// broadcast stream produces frames, rather than buffering everything until
/// the connection closes (which never happens on its own here: `/v1/events`
/// streams for as long as the daemon is alive). switchyardctl is a separate
/// binary crate with no access to switchyardd's internals (see
/// `admin_request`'s doc comment above), so this reproduces the same wire
/// framing directly against a live daemon instead of exercising the
/// `switchyardctl events` binary itself. Reads with a bounded per-attempt
/// timeout instead of `read_to_string`-to-EOF (unlike every other
/// `admin_request` caller in this file) precisely because EOF is never
/// reached while this test holds the connection open.
#[tokio::test]
async fn events_stream_over_http_1_0_flushes_incrementally_not_buffered_to_eof() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let d = start_daemon(tempfile::tempdir().unwrap());
    wait_for(&d.plugin_sock()).await;
    wait_for(&d.admin_sock()).await;
    let (_ra, mut wa) = connect_plugin(&d.plugin_sock(), "mocka").await;

    let mut s = UnixStream::connect(&d.admin_sock()).await.unwrap();
    s.write_all(b"GET /v1/events HTTP/1.0\r\nhost: x\r\n\r\n").await.unwrap();

    // Drive a real ingress event through the live daemon AFTER the request
    // is already on the wire.
    inbound(&mut wa, "chan", "!e2e-sender", "hello over sse", chrono::Utc::now()).await;

    // Read incrementally with a bounded timeout per attempt: this must NOT
    // hang waiting for EOF, since the connection never closes on its own
    // while `d` is alive -- a buffer-until-EOF read (like `admin_request`'s)
    // would hang here forever.
    let mut buf = [0u8; 4096];
    let mut collected = String::new();
    for _ in 0..100 {
        match timeout(Duration::from_millis(100), s.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                collected.push_str(&String::from_utf8_lossy(&buf[..n]));
                if collected.contains("event: ingress") {
                    break;
                }
            }
            Ok(Err(e)) => panic!("read error: {e}"),
            Err(_) => continue, // no bytes ready yet this tick -- keep polling
        }
    }

    assert!(collected.contains("event: ingress"), "stream: {collected}");
    assert!(collected.contains("\"routes\":[\"general\"]"), "stream: {collected}");
    assert!(!collected.contains("!e2e-sender"), "full native ref leaked: {collected}");
    assert!(!collected.contains("hello over sse"), "message body leaked: {collected}");
}

/// Task 5's full-workflow e2e (design §Testing): boots a daemon with one
/// route, reads the live config back byte-for-byte, opens an SSE connection,
/// PUTs a mutated config that adds a second route, drives a message over
/// that brand-new route with no restart, confirms the workflow's three
/// signature events (`config_applied`, `ingress`, `delivery`) all arrived on
/// the SSE feed, then rolls the config back and confirms the added route is
/// gone -- CONTROLLER RULING (pre-flight): a message aimed at the
/// now-rolled-back route matches ZERO routes post-rollback (the route no
/// longer exists to dead-letter against), so the negative assertion is
/// "never arrives as a Send", not "arrives as a dead letter".
#[tokio::test]
async fn config_apply_reload_and_events_full_workflow() {
    let dir = tempfile::tempdir().unwrap();
    let d = start_daemon_with_config(dir, WEBUI_WORKFLOW_CONFIG);
    wait_for(&d.plugin_sock()).await;
    wait_for(&d.admin_sock()).await;
    let (_ra, mut wa) = connect_plugin(&d.plugin_sock(), "mocka").await;
    let (mut rb, mut wb) = connect_plugin(&d.plugin_sock(), "mockb").await;

    // ---- 1. GET /v1/config byte-equals the file on disk -------------------
    let cfg_path = d.dir.path().join("relayfabric.yaml");
    let original_text = std::fs::read_to_string(&cfg_path).unwrap();
    let served = admin_get(&d.admin_sock(), "/v1/config").await;
    assert_eq!(served, original_text, "GET /v1/config must serve the file verbatim");

    // ---- 2. open the SSE connection BEFORE the mutation --------------------
    let mut sse = open_events_stream(&d.admin_sock()).await;
    let mut sse_buf = String::new();

    // ---- 3. PUT a mutated config adding a second route ("extra"), reusing
    // the already-enabled mocka/mockb -- restart_required must be empty
    // (design §1: a route-only change never needs a restart).
    let mutated_text = format!(
        "{original_text}  - name: extra\n    sources: [\"mocka:newchan\"]\n    destinations: [\"mockb:chan\"]\n"
    );
    let (status, body) =
        admin_request(&d.admin_sock(), "PUT", "/v1/config", Some(&mutated_text)).await;
    assert_eq!(status, 200, "body was: {body}");
    assert_eq!(body, "{\"applied\":true,\"restart_required\":[]}",
        "adding a route alone must never require a restart: {body}");

    // the new route is visible immediately (the PUT handler applies before
    // responding -- no poll needed for this read).
    let routes_after_put = admin_get(&d.admin_sock(), "/v1/routes").await;
    assert!(routes_after_put.contains("\"name\":\"extra\""),
        "new route missing from /v1/routes: {routes_after_put}");

    // SSE must have already seen config_applied with an empty restart list.
    poll_stream_until_contains(&mut sse, &mut sse_buf, "event: config_applied").await;
    assert!(sse_buf.contains("\"restart_required\":[]"), "sse: {sse_buf}");

    // ---- 4. drive a message over the NEW route -- live, no restart --------
    inbound(&mut wa, "newchan", "!e2e-workflow-sender", "hello via the new route",
        chrono::Utc::now()).await;
    let (corr, endpoint, body, _) = expect_send(&mut rb).await;
    // `endpoint` here is the DESTINATION channel ("extra" route's
    // `mockb:chan`), not the source endpoint ("newchan") the inbound
    // arrived on -- those are independent namespaces.
    assert_eq!(endpoint, "chan");
    assert!(body.contains("hello via the new route"), "body was: {body}");
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr, delivered: true, detail: None,
    }).await.unwrap();

    // SSE must have seen the ingress (routed onto "extra") and the delivery
    // (delivered, on "extra") for this exact message.
    poll_stream_until_contains(&mut sse, &mut sse_buf, "event: ingress").await;
    assert!(sse_buf.contains("\"routes\":[\"extra\"]"), "sse: {sse_buf}");
    poll_stream_until_contains(&mut sse, &mut sse_buf, "event: delivery").await;
    assert!(sse_buf.contains("\"route\":\"extra\""), "sse: {sse_buf}");
    assert!(sse_buf.contains("\"state\":\"delivered\""), "sse: {sse_buf}");
    assert!(!sse_buf.contains("!e2e-workflow-sender"), "full native ref leaked: {sse_buf}");
    assert!(!sse_buf.contains("hello via the new route"), "message body leaked: {sse_buf}");

    // ---- 5. rollback: old (one-route) config becomes live again -----------
    let (status, body) =
        admin_request(&d.admin_sock(), "POST", "/v1/config/rollback", None).await;
    assert_eq!(status, 200, "body was: {body}");
    assert_eq!(body, "{\"applied\":true,\"restart_required\":[]}", "body was: {body}");

    let config_after_rollback = admin_get(&d.admin_sock(), "/v1/config").await;
    assert_eq!(config_after_rollback, original_text,
        "rollback must restore the original config text verbatim");

    let routes_after_rollback = admin_get(&d.admin_sock(), "/v1/routes").await;
    assert!(!routes_after_rollback.contains("\"name\":\"extra\""),
        "rolled-back route must no longer be listed: {routes_after_rollback}");

    // Rollback re-applies the previous config through the same apply_config
    // path as PUT, so the stream must carry a SECOND config_applied event.
    poll_stream_until_count(&mut sse, &mut sse_buf, "event: config_applied", 2).await;

    // ---- 6. bounded negative: a message aimed at the now-gone route is ----
    // dropped (matches zero routes), never bridged as a Send -- NOT a dead
    // letter, since the route itself no longer exists (CONTROLLER RULING).
    inbound(&mut wa, "newchan", "!e2e-workflow-sender", "should never arrive post-rollback",
        chrono::Utc::now()).await;
    assert!(
        timeout(Duration::from_secs(2), read_frame::<_, DaemonToPlugin>(&mut rb)).await.is_err(),
        "a message on the rolled-back route's endpoint was bridged anyway"
    );
}

// ---- federation: two real daemons, bidirectional, trust-denied, loop -----

/// Pre-generates an Ed25519 node identity and writes it directly to
/// `<data_dir>/identity/node.key` in the exact format `node_identity::
/// NodeIdentity::load_or_create` expects (hex-encoded 32-byte seed, 0600) --
/// so this daemon's node_id is known to the TEST before it ever boots.
/// Federation config requires every peer's `node_id` up front
/// (`federation.peers[].node_id`), and the test below has THREE mutually-
/// referencing daemons: A needs B's node_id, B needs A's, C needs A's --
/// there's no boot order that lets every config be written only after
/// every node_id is first learned live via `/v1/status`. Returns the
/// node_id ("rf:" + 64 hex chars), exactly what `node_identity::
/// NodeIdentity::node_id` would compute for the same seed.
fn precreate_node_identity(data_dir: &Path) -> String {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let identity_dir = data_dir.join("identity");
    std::fs::create_dir_all(&identity_dir).unwrap();
    let seed: [u8; 32] = rand::random();
    let mut f = std::fs::OpenOptions::new()
        .write(true).create_new(true).mode(0o600)
        .open(identity_dir.join("node.key")).unwrap();
    f.write_all(hex::encode(seed).as_bytes()).unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    format!("rf:{}", hex::encode(signing_key.verifying_key().to_bytes()))
}

/// Pre-generates a sealed-routing X25519 keypair (cycle H, Task 6, design
/// §1/§4) and writes the secret directly to `<data_dir>/sealed.key` in the
/// exact on-disk format `fed::sealkey::SealedKey::load_or_create` expects
/// (raw 32-byte hex, 0600, create_new) -- the same
/// "known-to-the-test-before-the-owning-daemon-boots" shape as
/// `precreate_node_identity` above, and for the identical reason: a
/// sealed-mode route's peer config must carry a CONFIG-PINNED `sealed_key`
/// (design §1/§113.2 -- `--check-config` cannot see advert-learned keys at
/// load time), so the origin's config has to be written with the
/// destination's PUBLIC sealed key already known, before the destination
/// daemon has ever run to generate/publish one itself. Returns the 64-hex-
/// char public key exactly as `federation.peers[].sealed_key` expects it.
fn precreate_sealed_key(data_dir: &Path) -> String {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::create_dir_all(data_dir).unwrap();
    let secret_bytes: [u8; 32] = rand::random();
    let mut f = std::fs::OpenOptions::new()
        .write(true).create_new(true).mode(0o600)
        .open(data_dir.join("sealed.key")).unwrap();
    f.write_all(hex::encode(secret_bytes).as_bytes()).unwrap();
    let public = crypto_box::SecretKey::from_bytes(secret_bytes).public_key().to_bytes();
    hex::encode(public)
}

/// Binds an ephemeral TCP port, reads back the OS-assigned port, then
/// immediately drops the listener -- the federation config text needs a
/// concrete, currently-free port to template into `federation.listen`
/// before the daemon that will actually bind it has even been spawned.
/// Small race window between the drop here and the daemon's own bind
/// (another process could in principle grab the same port in between);
/// acceptable for a test.
fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Sums every value in the `{state: count}` aggregate `GET /v1/queue` body
/// -- used by the loop-guard scenario below to assert the TOTAL delivery
/// row count across every state settles to a small, non-growing number,
/// without needing to enumerate every state name up front.
fn total_queue_count(body: &str) -> i64 {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v.as_object().unwrap().values().map(|n| n.as_i64().unwrap()).sum()
}

/// Polls `total_queue_count` on `sock` every ~200ms until it reads the SAME
/// value `REQUIRED_STREAK` (5) consecutive times in a row -- any change
/// resets the streak -- bounded at `max_wait` overall. The crate's own
/// "poll rather than sleep-and-hope" convention (see
/// `poll_until_contains`/`poll_stream_until_count` above), specialized for
/// "prove a value has genuinely stopped changing" (a real storm would never
/// stabilize) rather than "wait for a value to first appear". Panics if it
/// never stabilizes within `max_wait`; returns the stable total.
async fn poll_until_queue_count_stable(sock: &Path, max_wait: Duration) -> i64 {
    const REQUIRED_STREAK: usize = 5;
    const INTERVAL: Duration = Duration::from_millis(200);
    let deadline = tokio::time::Instant::now() + max_wait;
    let mut last: Option<i64> = None;
    let mut streak = 0usize;
    loop {
        let value = total_queue_count(&admin_get(sock, "/v1/queue").await);
        if Some(value) == last {
            streak += 1;
        } else {
            last = Some(value);
            streak = 1;
        }
        if streak >= REQUIRED_STREAK {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "queue count on {} never stabilized within {max_wait:?} (currently {value}, streak {streak})",
            sock.display()
        );
        tokio::time::sleep(INTERVAL).await;
    }
}

/// Polls `GET /v1/federation` (JSON-parsed, not a raw substring match --
/// `FederationPeerItem`'s `connected`/`name` fields aren't adjacent in the
/// serialized object, and this needs to distinguish a SPECIFIC named peer's
/// connected state from any other peer entry the same response might carry,
/// unlike every other `poll_until_contains` caller in this file which only
/// ever has one peer to wait on) until `name`'s entry reports
/// `connected: true`. Cycle H, Task 6: the sealed-routing e2e below has TWO
/// peers (b, c) connecting to the same listener, so a plain substring poll
/// for `"connected":true` would pass as soon as EITHER one came up.
async fn wait_for_fed_peer_connected(sock: &Path, name: &str) {
    for _ in 0..50 {
        let body = admin_get(sock, "/v1/federation").await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        if v["peers"].as_array().unwrap().iter()
            .any(|p| p["name"] == name && p["connected"] == true) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("peer {name:?} on {} never showed connected:true", sock.display());
}

/// Design §Testing's two-real-daemon federation e2e. Noise identity binding
/// itself is T1/T4's job (`fed::noise`/`fed::conn`'s own unit + in-memory
/// duplex tests) -- this test starts from an already-authenticated pair and
/// focuses on what only a REAL two-process round trip can prove: daemon A
/// listens, daemon B dials out to A (each with its own mock plugin and a
/// route whose destinations include a `fed:` leg into the other's
/// `federation.ingress_routes`); a message A -> B and the reverse B -> A
/// each arrive rendered (pseudonymous alias tag, never the raw native ref)
/// and drive both the sender-side delivery row to `delivered` (via the
/// receiver's `Fed::Ack`, independent of the receiving mock plugin's own
/// `DeliveryResult`) and A's SSE feed (`federation` up + `delivery`
/// events); a third daemon C, dialing A but never listed in A's
/// `federation.peers`/`trusted`, completes the Noise handshake fine but has
/// its envelope `TRUST_DENIED` -- per Task 4's binding ruling this is a
/// `Persistence::NoPersist` rejection (nothing written to storage), so it's
/// asserted via `FED_REJECTED` ticking up on `GET /metrics` plus a bounded
/// negative (the message never reaches A's mock plugin), never via
/// `/v1/queue?state=dead_letter`; and a loop config (A's own `loop` route
/// federates only to B, B's federates back to A, both list `loop` in their
/// own `ingress_routes`) sends one inbound message that reaches B's mock
/// plugin exactly once and settles to a small, non-growing total
/// delivery-row count on both sides -- proving the dedup/hop-cap loop guard
/// (design §5, already unit-proven at the `fed_ingress` level for the
/// exact-hop-cap-boundary and dedup-replay cases) also holds over a REAL
/// two-daemon round trip, not just in-process.
#[tokio::test]
async fn federation_two_daemons_bidirectional_with_trust_and_loop_guards() {
    // ---- 0. identities + the one real TCP port this test needs ------------
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let dir_c = tempfile::tempdir().unwrap();
    let data_a = dir_a.path().join("data");
    let data_b = dir_b.path().join("data");
    let data_c = dir_c.path().join("data");
    let node_id_a = precreate_node_identity(&data_a);
    let node_id_b = precreate_node_identity(&data_b);
    let _node_id_c = precreate_node_identity(&data_c); // deliberately unused by A's config

    let a_port = free_tcp_port();
    let a_addr = format!("127.0.0.1:{a_port}");

    // ---- 1. daemon A: listener, federates "a-in"/"loop" from b ------------
    let config_a = format!(
        r#"
node:
  name: e2e-fed-a
  data_dir: DATA_DIR
plugins:
  mocka:
    enabled: true
routes:
  - name: a-out
    sources: ["mocka:outchan"]
    destinations: ["fed:b/b-in"]
  - name: a-in
    sources: []
    destinations: ["mocka:inchan"]
  - name: loop
    sources: ["mocka:loopchan"]
    destinations: ["fed:b/loop"]
federation:
  listen: "{a_addr}"
  ingress_routes: [a-in, loop]
  peers:
    - name: b
      node_id: "{node_id_b}"
      addr: "127.0.0.1:1"
"#
    );
    let d_a = start_daemon_with_config(dir_a, &config_a);
    wait_for(&d_a.plugin_sock()).await;
    wait_for(&d_a.admin_sock()).await;
    let (mut ra, mut wa) = connect_plugin(&d_a.plugin_sock(), "mocka").await;

    // Open A's SSE stream BEFORE B ever connects, so the "federation up"
    // event for peer b lands in the buffer this test polls below.
    let mut sse_a = open_events_stream(&d_a.admin_sock()).await;
    let mut sse_a_buf = String::new();

    // ---- 2. daemon B: dials A, federates "b-in"/"loop" from a -------------
    let config_b = format!(
        r#"
node:
  name: e2e-fed-b
  data_dir: DATA_DIR
plugins:
  mockb:
    enabled: true
routes:
  - name: b-out
    sources: ["mockb:outchan"]
    destinations: ["fed:a/a-in"]
  - name: b-in
    sources: []
    destinations: ["mockb:inchan"]
  - name: loop
    sources: []
    destinations: ["mockb:loopchan", "fed:a/loop"]
federation:
  ingress_routes: [b-in, loop]
  peers:
    - name: a
      node_id: "{node_id_a}"
      addr: "{a_addr}"
"#
    );
    let d_b = start_daemon_with_config(dir_b, &config_b);
    wait_for(&d_b.plugin_sock()).await;
    wait_for(&d_b.admin_sock()).await;
    let (mut rb, mut wb) = connect_plugin(&d_b.plugin_sock(), "mockb").await;

    // B's outbound dialer connects to A on its first (zero-delay) attempt;
    // wait for A to see it live before driving any federated traffic.
    poll_until_contains(&d_a.admin_sock(), "/v1/federation", "\"connected\":true").await;

    poll_stream_until_contains(&mut sse_a, &mut sse_a_buf, "event: federation").await;
    assert!(sse_a_buf.contains("\"peer\":\"b\""), "sse: {sse_a_buf}");
    assert!(sse_a_buf.contains("\"up\":true"), "sse: {sse_a_buf}");

    // ---- 3. A -> B: rendered at B, pseudonymous, A's delivery marked -------
    // delivered by B's Fed::Ack (independent of B's own mock plugin's
    // DeliveryResult, which only settles B's LOCAL "b-in" row).
    inbound(&mut wa, "outchan", "!a-secret", "hello from a to b via fed", chrono::Utc::now()).await;
    let (corr_b, endpoint_b, body_b, _) = expect_send(&mut rb).await;
    assert_eq!(endpoint_b, "inchan");
    assert!(body_b.starts_with("[MOCK"), "body was: {body_b}");
    assert!(body_b.contains("hello from a to b via fed"), "body was: {body_b}");
    assert!(!body_b.contains("!a-secret"), "native ref leaked across federation: {body_b}");
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr: corr_b, delivered: true, detail: None,
    }).await.unwrap();

    poll_until_contains(&d_a.admin_sock(), "/v1/queue?state=delivered", "\"route\":\"a-out\"").await;

    poll_stream_until_contains(&mut sse_a, &mut sse_a_buf, "event: delivery").await;
    assert!(sse_a_buf.contains("\"route\":\"a-out\""), "sse: {sse_a_buf}");
    assert!(sse_a_buf.contains("\"state\":\"delivered\""), "sse: {sse_a_buf}");

    // ---- 4. B -> A: the reverse direction -----------------------------------
    inbound(&mut wb, "outchan", "!b-secret", "hello from b to a via fed", chrono::Utc::now()).await;
    let (corr_a, endpoint_a, body_a, _) = expect_send(&mut ra).await;
    assert_eq!(endpoint_a, "inchan");
    assert!(body_a.starts_with("[MOCK"), "body was: {body_a}");
    assert!(body_a.contains("hello from b to a via fed"), "body was: {body_a}");
    assert!(!body_a.contains("!b-secret"), "native ref leaked across federation: {body_a}");
    write_frame(&mut wa, &PluginToDaemon::DeliveryResult {
        corr: corr_a, delivered: true, detail: None,
    }).await.unwrap();

    poll_until_contains(&d_b.admin_sock(), "/v1/queue?state=delivered", "\"route\":\"b-out\"").await;

    // ---- 5. trust-denied: daemon C dials A but is never listed as A's ------
    // peer -- handshake succeeds (Noise identity binding is orthogonal to
    // policy trust), envelope TRUST_DENIED. Per Task 4's binding ruling this
    // is Persistence::NoPersist -- nothing written to storage -- so this is
    // asserted via FED_REJECTED on GET /metrics + a bounded negative, never
    // via /v1/queue?state=dead_letter.
    let config_c = format!(
        r#"
node:
  name: e2e-fed-c
  data_dir: DATA_DIR
plugins:
  mockc:
    enabled: true
routes:
  - name: c-out
    sources: ["mockc:outchan"]
    destinations: ["fed:a/a-in"]
federation:
  peers:
    - name: a
      node_id: "{node_id_a}"
      addr: "{a_addr}"
"#
    );
    let d_c = start_daemon_with_config(dir_c, &config_c);
    wait_for(&d_c.plugin_sock()).await;
    let (_rc, mut wc) = connect_plugin(&d_c.plugin_sock(), "mockc").await;

    inbound(&mut wc, "outchan", "!c-untrusted", "this must never reach a mock plugin",
        chrono::Utc::now()).await;

    poll_until_contains(&d_a.admin_sock(), "/metrics", "relayfabric_federation_rejected_total 1").await;
    assert!(
        timeout(Duration::from_secs(2), read_frame::<_, DaemonToPlugin>(&mut ra)).await.is_err(),
        "a trust-denied peer's envelope was bridged anyway"
    );

    // ---- 6. loop guard: A federates "loop" only to b, b's "loop" delivers --
    // locally (the terminal mock, exactly once) AND federates back to a; the
    // echo must die (dedup and/or hop cap -- both already unit-proven at the
    // fed_ingress level; this proves the WIRING doesn't storm over a real
    // two-daemon round trip) rather than bouncing forever.
    inbound(&mut wa, "loopchan", "!loop-secret", "unique-loop-body-xyz", chrono::Utc::now()).await;
    let (corr_loop, endpoint_loop, body_loop, _) = expect_send(&mut rb).await;
    assert_eq!(endpoint_loop, "loopchan");
    assert!(body_loop.contains("unique-loop-body-xyz"), "body was: {body_loop}");
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr: corr_loop, delivered: true, detail: None,
    }).await.unwrap();

    // bounded negative: no SECOND Send for the loop message reaches B's
    // mock plugin -- the echo must not re-deliver locally a second time.
    assert!(
        timeout(Duration::from_secs(2), read_frame::<_, DaemonToPlugin>(&mut rb)).await.is_err(),
        "the loop's echo was delivered to the terminal mock plugin a second time"
    );

    // bounded total: poll each daemon's total delivery row count until it
    // stabilizes (5 consecutive identical reads, 200ms apart, capped at
    // 15s) -- a genuine storm would never stop changing, so stabilizing at
    // all is itself part of the assertion, not just the value it settles
    // to.
    let a_total = poll_until_queue_count_stable(&d_a.admin_sock(), Duration::from_secs(15)).await;
    let b_total = poll_until_queue_count_stable(&d_b.admin_sock(), Duration::from_secs(15)).await;
    assert!(a_total <= 12, "daemon A's total delivery rows unexpectedly large: {a_total}");
    assert!(b_total <= 12, "daemon B's total delivery rows unexpectedly large: {b_total}");
}

/// Design §Testing's "peer-down retry-then-recover" leg -- a SIBLING to
/// `federation_two_daemons_bidirectional_with_trust_and_loop_guards` above
/// rather than a fourth phase bolted onto it: that test is already long,
/// and killing+respawning a daemon subprocess mid-test is a genuinely
/// different shape from its steady-state flow. Reuses
/// `precreate_node_identity`/`free_tcp_port` exactly as the main test does,
/// so A's node_id, B's node_id, and A's `federation.listen` port are all
/// known before either config is written.
///
/// TIMING (why there's no backoff to "beat" here): B is killed and
/// respawned as a BRAND NEW OS process on the SAME `data_dir` (same
/// identity file, same node_id, same config text/port). Unlike
/// `fed::conn::spawn_outbound`'s own redial loop -- which backs off
/// 1s..60s across REPEATED ATTEMPTS BY THE SAME LONG-LIVED TASK when a
/// live process keeps failing to connect -- a freshly-spawned process's
/// `spawn_outbound` starts a brand new `backoff` local variable and makes
/// its FIRST connection attempt immediately, with no sleep before it (see
/// `spawn_outbound`'s loop shape: connect first, `sleep(backoff)` only
/// AFTER each attempt). So it does not matter how long this test waits
/// between killing B and respawning it -- the respawned process always
/// dials A on its very first tick, at `backoff`'s initial 1s-but-unused
/// value. The one real timing constraint is A's OWN fixed 5s `mark_retry`
/// interval on the stuck delivery row (`engine::process_due_fed`'s "no
/// live connection" branch, design §5) -- `expect_send`'s existing 10s
/// bound already covers that with margin.
#[tokio::test]
async fn federation_peer_down_then_recovers() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let data_a = dir_a.path().join("data");
    let data_b = dir_b.path().join("data");
    let node_id_a = precreate_node_identity(&data_a);
    let node_id_b = precreate_node_identity(&data_b);

    let a_port = free_tcp_port();
    let a_addr = format!("127.0.0.1:{a_port}");

    // ---- daemon A: listener. This test only needs the A -> B egress -------
    // direction (the one that actually gets stuck while B is down), so A
    // has exactly one route with a `fed:` destination and no ingress route
    // of its own.
    let config_a = format!(
        r#"
node:
  name: e2e-fed-recover-a
  data_dir: DATA_DIR
plugins:
  mocka:
    enabled: true
routes:
  - name: a-out
    sources: ["mocka:outchan"]
    destinations: ["fed:b/b-in"]
federation:
  listen: "{a_addr}"
  peers:
    - name: b
      node_id: "{node_id_b}"
      addr: "127.0.0.1:1"
"#
    );
    let d_a = start_daemon_with_config(dir_a, &config_a);
    wait_for(&d_a.plugin_sock()).await;
    wait_for(&d_a.admin_sock()).await;
    let (_ra, mut wa) = connect_plugin(&d_a.plugin_sock(), "mocka").await;

    let config_b = format!(
        r#"
node:
  name: e2e-fed-recover-b
  data_dir: DATA_DIR
plugins:
  mockb:
    enabled: true
routes:
  - name: b-in
    sources: []
    destinations: ["mockb:inchan"]
federation:
  ingress_routes: [b-in]
  peers:
    - name: a
      node_id: "{node_id_a}"
      addr: "{a_addr}"
"#
    );
    let mut d_b = start_daemon_with_config(dir_b, &config_b);
    wait_for(&d_b.plugin_sock()).await;

    // ---- 1. healthy: confirm the connection is up before killing anything -
    poll_until_contains(&d_a.admin_sock(), "/v1/federation", "\"connected\":true").await;

    // ---- 2. kill B (the honest version of "peer down" -- an actual dead ---
    // process, not just a dropped connection). A must notice within its
    // own 90s dead-timer bound, but in practice a killed process's TCP
    // socket closes immediately, so A's read errors out right away.
    d_b.child.kill().unwrap();
    d_b.child.wait().unwrap();
    poll_until_contains(&d_a.admin_sock(), "/v1/federation", "\"connected\":false").await;

    // ---- 3. drive a message toward the now-dead peer: the delivery must ---
    // go (and stay) pending -- retried every 5s by process_due_fed's "no
    // live connection" branch -- never dead_lettered, never lost.
    inbound(&mut wa, "outchan", "!recover-secret", "message sent while b is down",
        chrono::Utc::now()).await;
    poll_until_contains(&d_a.admin_sock(), "/v1/queue?state=pending", "\"route\":\"a-out\"").await;

    // ---- 4. respawn B on the SAME data_dir (same identity/config/port) ----
    // -- see this test's doc comment for why there's no backoff to time
    // around here.
    let _ = std::fs::remove_file(d_b.plugin_sock());
    let cfg_path_b = d_b.dir.path().join("relayfabric.yaml");
    d_b.child = spawn_daemon(&cfg_path_b);
    wait_for(&d_b.plugin_sock()).await;
    let (mut rb, mut wb) = connect_plugin(&d_b.plugin_sock(), "mockb").await;

    // ---- 5. bounded settle: the parked message reaches B's mock plugin ----
    // (rendered, pseudonymous) and A's own delivery row is marked delivered
    // by B's Fed::Ack once the connection comes back and the pump retries.
    let (corr, endpoint, body, _) = expect_send(&mut rb).await;
    assert_eq!(endpoint, "inchan");
    assert!(body.contains("message sent while b is down"), "body was: {body}");
    assert!(!body.contains("!recover-secret"), "native ref leaked across federation: {body}");
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr, delivered: true, detail: None,
    }).await.unwrap();

    poll_until_contains(&d_a.admin_sock(), "/v1/queue?state=delivered", "\"route\":\"a-out\"").await;
}

/// Bounded negative for admin-JSON polling (design §Testing's discovery e2e
/// leg): unlike `poll_until_contains` (which polls until `needle` FIRST
/// appears), this polls `ATTEMPTS` times, `INTERVAL` apart, asserting
/// `needle` is absent from `path`'s body on EVERY read -- proving it never
/// shows up across the whole window, not just that it hadn't yet at one
/// point-in-time sample (which a late-arriving advert could slip past).
async fn assert_stays_absent(sock: &Path, path: &str, needle: &str) {
    const ATTEMPTS: usize = 8;
    const INTERVAL: Duration = Duration::from_millis(150);
    for _ in 0..ATTEMPTS {
        let body = admin_get(sock, path).await;
        assert!(!body.contains(needle), "{path} unexpectedly contains {needle:?}: {body}");
        tokio::time::sleep(INTERVAL).await;
    }
}

/// Design §Testing's discovery e2e leg (cycle G): extends the federation
/// pairing pattern above (`precreate_node_identity`/`free_tcp_port`) with
/// `discovery: {mode: federation}` on both A and B, each publishing one
/// `public_services` chat entry so the exchanged advert carries a real
/// service + protocol, not just the always-present `federation: true`
/// (`fed::advert::build_from_config`). A learns B's advert (and vice versa)
/// purely from the connection-up `AdvertReq`/`Advert` exchange (design
/// §2) -- no message traffic needed here, unlike the bidirectional test
/// above.
///
/// A third daemon C dials A (same "untrusted third party" shape as
/// `federation_two_daemons_bidirectional_with_trust_and_loop_guards`'s own
/// C -- connects, completes the Noise handshake, but is never listed in
/// A's `federation.peers`) with its OWN discovery enabled too, so this
/// proves the scope gate actually DENIES an attempted exchange rather than
/// merely observing "C never asked": `advert_scope_allows`'s "federation"
/// arm fails A's `accept_from` check against C's unknown trust level in
/// BOTH directions -- A never answers C's `AdvertReq`, and A never sends C
/// one via its own post-connect `AdvertReq` either -- so neither daemon's
/// `/v1/discovery` ever learns anything about the other
/// (`assert_stays_absent` above, not a single point-in-time read, since a
/// late-arriving advert would only show up after this test's own poll-
/// driven positive assertions have already spent real wall-clock time).
#[tokio::test]
async fn federation_discovery_two_daemons_exchange_adverts_and_deny_untrusted_third_party() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let dir_c = tempfile::tempdir().unwrap();
    let data_a = dir_a.path().join("data");
    let data_b = dir_b.path().join("data");
    let data_c = dir_c.path().join("data");
    let node_id_a = precreate_node_identity(&data_a);
    let node_id_b = precreate_node_identity(&data_b);
    let node_id_c = precreate_node_identity(&data_c);

    let a_port = free_tcp_port();
    let a_addr = format!("127.0.0.1:{a_port}");

    // ---- daemon A: listener, discovery on, publishes a chat service -------
    let config_a = format!(
        r#"
node:
  name: e2e-fed-disco-a
  data_dir: DATA_DIR
plugins:
  mocka:
    enabled: true
public_services:
  - name: a-chat
    type: chat
    ingress: [mocka]
    egress: [mocka]
discovery:
  mode: federation
federation:
  listen: "{a_addr}"
  peers:
    - name: b
      node_id: "{node_id_b}"
      addr: "127.0.0.1:1"
"#
    );
    let d_a = start_daemon_with_config(dir_a, &config_a);
    wait_for(&d_a.admin_sock()).await;

    // ---- daemon B: dials A, discovery on, publishes a chat service --------
    let config_b = format!(
        r#"
node:
  name: e2e-fed-disco-b
  data_dir: DATA_DIR
plugins:
  mockb:
    enabled: true
public_services:
  - name: b-chat
    type: chat
    ingress: [mockb]
    egress: [mockb]
discovery:
  mode: federation
federation:
  peers:
    - name: a
      node_id: "{node_id_a}"
      addr: "{a_addr}"
"#
    );
    let d_b = start_daemon_with_config(dir_b, &config_b);
    wait_for(&d_b.admin_sock()).await;

    poll_until_contains(&d_a.admin_sock(), "/v1/federation", "\"connected\":true").await;

    // ---- A learns B's advert: node_id, name, and the published service ----
    let a_view_of_b = poll_until_contains(
        &d_a.admin_sock(), "/v1/discovery", &format!("\"node_id\":\"{node_id_b}\"")).await;
    assert!(a_view_of_b.contains("\"name\":\"e2e-fed-disco-b\""), "body: {a_view_of_b}");
    assert!(a_view_of_b.contains("\"chat\":true"), "body: {a_view_of_b}");
    assert!(a_view_of_b.contains("\"mockb\":{"), "body: {a_view_of_b}");

    // ---- B learns A's advert: the reverse direction ------------------------
    let b_view_of_a = poll_until_contains(
        &d_b.admin_sock(), "/v1/discovery", &format!("\"node_id\":\"{node_id_a}\"")).await;
    assert!(b_view_of_a.contains("\"name\":\"e2e-fed-disco-a\""), "body: {b_view_of_a}");
    assert!(b_view_of_a.contains("\"chat\":true"), "body: {b_view_of_a}");
    assert!(b_view_of_a.contains("\"mocka\":{"), "body: {b_view_of_a}");

    // ---- daemon C: dials A too, discovery on, but never in A's peers[] -----
    let config_c = format!(
        r#"
node:
  name: e2e-fed-disco-c
  data_dir: DATA_DIR
discovery:
  mode: federation
federation:
  peers:
    - name: a
      node_id: "{node_id_a}"
      addr: "{a_addr}"
"#
    );
    let d_c = start_daemon_with_config(dir_c, &config_c);
    wait_for(&d_c.admin_sock()).await;
    poll_until_contains(&d_c.admin_sock(), "/v1/federation", "\"connected\":true").await;

    // ---- bounded negative: neither side ever learns the other's advert ----
    assert_stays_absent(
        &d_a.admin_sock(), "/v1/discovery", &format!("\"node_id\":\"{node_id_c}\"")).await;
    assert_stays_absent(
        &d_c.admin_sock(), "/v1/discovery", &format!("\"node_id\":\"{node_id_a}\"")).await;
}

/// Design §Testing's federation egress budget leg (design §5, carried from
/// cycle F): `federation.peers[].messages_per_minute: 1` on A's peer entry
/// for B caps A's `fed/b` link to one send per rolling minute
/// (`engine::process_due_fed`, keyed exactly that way). Two inbound
/// messages queued back-to-back on A are both due almost immediately
/// (`engine::pump`'s 500ms tick, `due_deliveries(now, 32)`), so the budget
/// check runs against both within a tick or two of each other: one send
/// succeeds and consumes the minute's only slot, the other observes an
/// exhausted limiter and defers (`mark_retry(+5s)` + `BUDGET_DEFERRED`, no
/// priority bypass -- cycle-F's no-emergency-lane ruling for fed egress).
/// This test only needs the cheap, bounded half of that story: the metric
/// ticking to 1 well within the couple of seconds this test waits, long
/// before the deferred message's own 5s retry could possibly produce a
/// SECOND deferral -- no window-rollover timing to race. A sibling to
/// `federation_discovery_two_daemons_exchange_adverts_and_deny_untrusted_third_party`
/// above rather than a leg bolted onto it: discovery and the fed egress
/// budget are independent knobs, and this needs live message traffic the
/// discovery test deliberately has none of.
#[tokio::test]
async fn federation_budget_defers_the_second_message_to_a_rate_limited_peer() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let data_a = dir_a.path().join("data");
    let data_b = dir_b.path().join("data");
    let node_id_a = precreate_node_identity(&data_a);
    let node_id_b = precreate_node_identity(&data_b);

    let a_port = free_tcp_port();
    let a_addr = format!("127.0.0.1:{a_port}");

    let config_a = format!(
        r#"
node:
  name: e2e-fed-budget-a
  data_dir: DATA_DIR
plugins:
  mocka:
    enabled: true
routes:
  - name: a-out
    sources: ["mocka:outchan"]
    destinations: ["fed:b/b-in"]
federation:
  listen: "{a_addr}"
  peers:
    - name: b
      node_id: "{node_id_b}"
      addr: "127.0.0.1:1"
      messages_per_minute: 1
"#
    );
    let d_a = start_daemon_with_config(dir_a, &config_a);
    wait_for(&d_a.plugin_sock()).await;
    wait_for(&d_a.admin_sock()).await;
    let (_ra, mut wa) = connect_plugin(&d_a.plugin_sock(), "mocka").await;

    let config_b = format!(
        r#"
node:
  name: e2e-fed-budget-b
  data_dir: DATA_DIR
plugins:
  mockb:
    enabled: true
routes:
  - name: b-in
    sources: []
    destinations: ["mockb:inchan"]
federation:
  ingress_routes: [b-in]
  peers:
    - name: a
      node_id: "{node_id_a}"
      addr: "{a_addr}"
"#
    );
    let d_b = start_daemon_with_config(dir_b, &config_b);
    wait_for(&d_b.plugin_sock()).await;
    let (mut rb, _wb) = connect_plugin(&d_b.plugin_sock(), "mockb").await;

    poll_until_contains(&d_a.admin_sock(), "/v1/federation", "\"connected\":true").await;

    // two quick messages, back-to-back -- due almost simultaneously.
    inbound(&mut wa, "outchan", "!budget-1", "budget message one", chrono::Utc::now()).await;
    inbound(&mut wa, "outchan", "!budget-2", "budget message two", chrono::Utc::now()).await;

    // exactly one gets through promptly...
    let (_corr, endpoint, body, _) = expect_send(&mut rb).await;
    assert_eq!(endpoint, "inchan");
    assert!(body.contains("budget message"), "body was: {body}");

    // ...and no second Send follows within a couple of seconds -- the
    // other message stayed deferred by the budget, not delivered too.
    assert!(
        timeout(Duration::from_secs(2), read_frame::<_, DaemonToPlugin>(&mut rb)).await.is_err(),
        "a second message was delivered despite the peer's 1/minute budget"
    );

    // ...and the deferral shows up on the metric, not just as an absence.
    poll_until_contains(&d_a.admin_sock(), "/metrics", "relayfabric_budget_deferred_total 1").await;
}

/// Design §Testing's two-gateway sealed-routing e2e (cycle H, Task 6, SPEC
/// §113): a THIRD real multi-daemon scenario in this file's federation
/// family, but for `security_mode: sealed` routes specifically. Reuses this
/// file's whole federation pattern -- `precreate_node_identity` (every
/// node_id known before any mutually-referencing config is written),
/// `free_tcp_port`/one listener (A) dialed by every other daemon (B, C) --
/// plus this task's own `precreate_sealed_key`/`wait_for_fed_peer_connected`
/// above.
///
/// A seals for B on a `security_mode: sealed` route, using B's PRE-
/// GENERATED, config-pinned `sealed_key`; B decrypts and delivers to its
/// mock plugin -- proving delivery+decrypt end to end over a REAL two-
/// process round trip. The sealed `Fed::Sealed` frame itself rides inside
/// the Noise transport layer, so it can't be sniffed in the clear at the
/// TCP level from this test (there is no plaintext TCP hop to observe); the
/// "ciphertext, not plaintext, crosses the fed layer" half of this claim is
/// instead proven at the unit level by `engine::tests::
/// process_due_fed_sealed_mode_produces_fed_sealed_frame_that_unseals_and_verifies`
/// (already landed, Task 4), which asserts the exact serialized `Fed::
/// Sealed` CBOR frame bytes never contain the sentinel body/native-ref --
/// this test is the delivery-side pair that unit test's own doc comment
/// anticipates.
///
/// A third daemon C -- otherwise an identical sealed destination, with its
/// OWN pre-generated, config-pinned `sealed_key` -- sets
/// `allow_gateway_decryption: false` on its ingress route. A's sealed send
/// to C completes the FULL decrypt+verify+trust pipeline at C (proving the
/// refusal is the last, deliberate policy gate, not an earlier one firing
/// first) and then refuses. Per Task 5's `sealed_reject` (`engine.rs`),
/// EVERY `fed_sealed_ingress` rejection reason -- including
/// `SECURITY_DOWNGRADE_REFUSED` -- is `Persistence::NoPersist`: nothing is
/// ever written to C's own `dead_letter` table, precisely so a refused
/// decryption never itself becomes a plaintext-bearing DLQ row. So this is
/// asserted via the `SEALED_REJECTED` counter on C's `GET /metrics`
/// (`relayfabric_sealed_rejected_total`) plus a bounded negative (C's mock
/// plugin never receives anything) -- never via
/// `/v1/queue?state=dead_letter`, which Task 5's own posture rules out here.
///
/// SEALED_OVERSIZE (design §4/§113.4: "rejected at origin, never shrunk")
/// is deliberately NOT reproduced here via a real subprocess payload: the
/// ceiling it dead-letters against (`engine::SEALED_MAX_BYTES` -- `fed::
/// noise::MAX_FRAME` minus a 512-byte margin) and the plugin IPC protocol's
/// OWN frame ceiling (`relay_ipc::MAX_FRAME`) are the SAME 16 MiB constant,
/// leaving under a kilobyte of daylight between "big enough to dead-letter
/// SEALED_OVERSIZE at A" and "too big for the Inbound frame to even reach A
/// over the mock plugin socket" -- reproducing that here would be exactly
/// the fragile, unbounded test this cycle's own "keep it bounded"
/// instruction rules out. It's already proven, byte-boundary-exact, at the
/// engine integration level (design §Testing's own "Integration: duplex
/// sealed egress→ingress through the real handlers" tier) by
/// `engine::tests::
/// process_due_fed_sealed_mode_oversized_envelope_dead_letters_sealed_oversize_not_shrunk`
/// (already landed, Task 4): constructs the oversized envelope directly,
/// in-process, driven through the real `process_due` handler against a
/// live registered fed connection -- no IPC frame ceiling in the way there.
#[tokio::test]
async fn sealed_routing_two_gateways_end_to_end() {
    const DELIVER_SENTINEL: &str = "SENTINEL-SEALED-DELIVERY-BODY-xyz789";
    const DOWNGRADE_SENTINEL: &str = "SENTINEL-SEALED-DOWNGRADE-REFUSED-BODY-abc123";

    // ---- 0. identities, sealed keys, and the one real TCP port needed -----
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let dir_c = tempfile::tempdir().unwrap();
    let data_a = dir_a.path().join("data");
    let data_b = dir_b.path().join("data");
    let data_c = dir_c.path().join("data");
    let node_id_a = precreate_node_identity(&data_a);
    let node_id_b = precreate_node_identity(&data_b);
    let node_id_c = precreate_node_identity(&data_c);
    let sealed_key_b = precreate_sealed_key(&data_b);
    let sealed_key_c = precreate_sealed_key(&data_c);

    let a_port = free_tcp_port();
    let a_addr = format!("127.0.0.1:{a_port}");

    // ---- 1. daemon A: listener, sealed routes to both b and c -------------
    let config_a = format!(
        r#"
node:
  name: e2e-sealed-a
  data_dir: DATA_DIR
plugins:
  mocka:
    enabled: true
routes:
  - name: a-out-b
    sources: ["mocka:outchan-b"]
    destinations: ["fed:b/b-in"]
    security_mode: sealed
  - name: a-out-c
    sources: ["mocka:outchan-c"]
    destinations: ["fed:c/c-in"]
    security_mode: sealed
federation:
  listen: "{a_addr}"
  peers:
    - name: b
      node_id: "{node_id_b}"
      addr: "127.0.0.1:1"
      sealed_key: "{sealed_key_b}"
    - name: c
      node_id: "{node_id_c}"
      addr: "127.0.0.1:1"
      sealed_key: "{sealed_key_c}"
"#
    );
    let d_a = start_daemon_with_config(dir_a, &config_a);
    wait_for(&d_a.plugin_sock()).await;
    wait_for(&d_a.admin_sock()).await;
    let (_ra, mut wa) = connect_plugin(&d_a.plugin_sock(), "mocka").await;

    // ---- 2. daemon B: dials A, ingress route with the DEFAULT (true) ------
    // allow_gateway_decryption -- the normal sealed-termination case.
    let config_b = format!(
        r#"
node:
  name: e2e-sealed-b
  data_dir: DATA_DIR
plugins:
  mockb:
    enabled: true
routes:
  - name: b-in
    sources: []
    destinations: ["mockb:inchan"]
federation:
  ingress_routes: [b-in]
  peers:
    - name: a
      node_id: "{node_id_a}"
      addr: "{a_addr}"
"#
    );
    let d_b = start_daemon_with_config(dir_b, &config_b);
    wait_for(&d_b.plugin_sock()).await;
    wait_for(&d_b.admin_sock()).await;
    let (mut rb, mut wb) = connect_plugin(&d_b.plugin_sock(), "mockb").await;

    // ---- 3. daemon C: dials A, ingress route REFUSES gateway decryption ---
    let config_c = format!(
        r#"
node:
  name: e2e-sealed-c
  data_dir: DATA_DIR
plugins:
  mockc:
    enabled: true
routes:
  - name: c-in
    sources: []
    destinations: ["mockc:inchan"]
    allow_gateway_decryption: false
federation:
  ingress_routes: [c-in]
  peers:
    - name: a
      node_id: "{node_id_a}"
      addr: "{a_addr}"
"#
    );
    let d_c = start_daemon_with_config(dir_c, &config_c);
    wait_for(&d_c.plugin_sock()).await;
    wait_for(&d_c.admin_sock()).await;
    let (mut rc, _wc) = connect_plugin(&d_c.plugin_sock(), "mockc").await;

    // both B and C dial out to A; wait for both live connections (named
    // specifically -- see `wait_for_fed_peer_connected`'s doc comment) so
    // neither send below races a still-handshaking peer.
    wait_for_fed_peer_connected(&d_a.admin_sock(), "b").await;
    wait_for_fed_peer_connected(&d_a.admin_sock(), "c").await;

    // ---- 4. A -> B, sealed: delivered and DECRYPTED at B ------------------
    inbound(&mut wa, "outchan-b", "!a-secret-b", DELIVER_SENTINEL, chrono::Utc::now()).await;
    let (corr_b, endpoint_b, body_b, _) = expect_send(&mut rb).await;
    assert_eq!(endpoint_b, "inchan");
    assert!(body_b.contains(DELIVER_SENTINEL), "body was: {body_b}");
    assert!(!body_b.contains("!a-secret-b"), "native ref leaked across sealed federation: {body_b}");
    write_frame(&mut wb, &PluginToDaemon::DeliveryResult {
        corr: corr_b, delivered: true, detail: None,
    }).await.unwrap();

    poll_until_contains(&d_a.admin_sock(), "/metrics", "relayfabric_sealed_egress_total 1").await;
    poll_until_contains(&d_b.admin_sock(), "/metrics", "relayfabric_sealed_ingress_total 1").await;

    // ---- 5. A -> C, sealed: decrypts fine, then DOWNGRADE REFUSAL ---------
    // at C's policy gate -- never delivered, never persisted (NoPersist).
    inbound(&mut wa, "outchan-c", "!a-secret-c", DOWNGRADE_SENTINEL, chrono::Utc::now()).await;

    poll_until_contains(&d_c.admin_sock(), "/metrics", "relayfabric_sealed_rejected_total 1").await;
    assert!(
        timeout(Duration::from_secs(2), read_frame::<_, DaemonToPlugin>(&mut rc)).await.is_err(),
        "a security-downgrade-refused sealed message was delivered to C's mock plugin anyway"
    );

    // bounded negative, over the SAME window: the refused content never
    // shows up in C's dead-letter queue either (Task 5's NoPersist posture
    // for every fed_sealed_ingress rejection -- a persisted row here would
    // make the refusal cosmetic, not real).
    assert_stays_absent(&d_c.admin_sock(), "/v1/queue?state=dead_letter", "SECURITY_DOWNGRADE_REFUSED").await;
}

/// Task 3 (design §3): the human-facing/machine-facing docs surfaces
/// (Tasks 1-2), exercised end to end over a real subprocess + admin
/// socket rather than the in-process `tower::oneshot` calls `admin.rs`'s
/// own unit tests use. Covers:
/// - `GET /v1/openapi.json` parses as JSON, is OpenAPI 3.1.x, and its
///   `paths` map contains a sampling of the real routes.
/// - `GET /docs` is a direct 200 `text/html` containing a UI marker, with
///   no external host anywhere in ITS OWN bytes (the literal index.html,
///   not the vendored JS bundles it loads — see `admin.rs`'s
///   `docs_html_has_no_external_href_or_src` for why those are excluded).
/// - `/docs/swagger-initializer.js` — the file that actually wires the UI
///   to this daemon — references `/v1/openapi.json` (the "GET /docs ...
///   references /v1/openapi.json" requirement; the literal index.html
///   only pulls in swagger-initializer.js by `<script src>`, it doesn't
///   inline the URL itself) and carries `"validatorUrl": "none"`, the
///   config that neutralizes Swagger UI's default phone-home to
///   validator.swagger.io. This is the CARRIED-OVER regression guard from
///   the Task 2 review: that proof previously lived only in the review
///   transcript, not in a test.
/// - `/docs/swagger-ui-bundle.js` contains the vendored Swagger UI dist's
///   own embedded version string, PINNED to the exact version currently
///   vendored (`utoipa-swagger-ui-vendored` 0.1.2 bakes in Swagger UI
///   5.17.14 — confirmed directly against that crate's `res/*.zip`). If a
///   future `utoipa-swagger-ui`/`-vendored` bump changes this, this
///   assertion fails LOUDLY rather than silently shipping a different
///   dist (with possibly different default phone-home behavior) unnoticed.
/// - "ctl `openapi` over the socket dumps parseable JSON with the same
///   path count": switchyardctl is a separate binary crate this
///   `switchyardd`-crate integration test cannot spawn (`CARGO_BIN_EXE_`
///   is only injected for binaries of the package under test, confirmed
///   empirically — `switchyardctl` isn't one), the same constraint
///   `admin_request`/`open_events_stream` already document above. Per
///   `switchyardctl/src/main.rs`, `openapi` does nothing beyond `fetch()`
///   (identical wire request to `admin_get`) followed by an UNMODIFIED
///   `print!("{body}")` — no reformatting, unlike every other subcommand —
///   so a second `admin_get` of the same path is byte-for-byte what ctl
///   would print, and comparing its parsed path count against the first
///   fetch's is exactly "ctl's output has the same path count as the
///   direct GET". `switchyardctl`'s own `request_for`/raw-print logic is
///   unit-tested in that crate.
#[tokio::test]
async fn openapi_doc_and_swagger_ui_are_served() {
    let d = start_daemon(tempfile::tempdir().unwrap());
    wait_for(&d.admin_sock()).await;

    // GET /v1/openapi.json -- parses, OpenAPI 3.1.x, has the real paths.
    let spec_body = admin_get(&d.admin_sock(), "/v1/openapi.json").await;
    let spec: serde_json::Value =
        serde_json::from_str(&spec_body).expect("/v1/openapi.json must parse as JSON");
    let version = spec["openapi"].as_str().expect("openapi field must be a string");
    assert!(version.starts_with("3.1"), "expected OpenAPI 3.1.x, got {version:?}");
    let paths = spec["paths"].as_object().expect("paths must be an object");
    for want in [
        "/v1/status", "/v1/config", "/v1/identities/link", "/v1/federation", "/v1/discovery",
    ] {
        assert!(paths.contains_key(want), "openapi.json paths missing {want}: {:?}", paths.keys().collect::<Vec<_>>());
    }
    let direct_path_count = paths.len();

    // GET /docs -- direct 200 text/html, a UI marker, no external host in
    // the literal index.html bytes.
    let (status, head, docs_body) = admin_get_with_head(&d.admin_sock(), "/docs").await;
    assert_eq!(status, 200, "GET /docs must be a direct 200, not a redirect");
    assert!(head.contains("text/html"), "GET /docs content-type head was: {head}");
    assert!(
        docs_body.contains("swagger-ui") || docs_body.contains("Swagger UI"),
        "GET /docs body has no Swagger UI marker: {docs_body}"
    );
    assert!(
        !docs_body.contains("http://") && !docs_body.contains("https://"),
        "GET /docs body references an external host: {docs_body}"
    );

    // swagger-initializer.js -- the piece that actually points the UI at
    // this daemon's /v1/openapi.json, with the phone-home guard.
    let init_js = admin_get(&d.admin_sock(), "/docs/swagger-initializer.js").await;
    assert!(init_js.contains("/v1/openapi.json"), "swagger-initializer.js: {init_js}");
    assert!(
        init_js.contains("\"validatorUrl\": \"none\""),
        "swagger-initializer.js is missing validatorUrl:\"none\" -- Swagger UI's default \
         validator.swagger.io phone-home may be live again: {init_js}"
    );

    // swagger-ui-bundle.js -- pinned vendored dist version regression guard.
    let bundle_js = admin_get(&d.admin_sock(), "/docs/swagger-ui-bundle.js").await;
    assert!(
        bundle_js.contains("PACKAGE_VERSION:\"5.17.14\""),
        "vendored Swagger UI dist version drifted from the pinned 5.17.14 -- re-verify \
         validatorUrl:none (and no new phone-home) still holds in the new version before \
         updating this assertion"
    );

    // ctl `openapi` over the socket -- see the doc comment above for why
    // this reproduces the fetch rather than spawning the ctl binary.
    let ctl_body = admin_get(&d.admin_sock(), "/v1/openapi.json").await;
    let ctl_spec: serde_json::Value =
        serde_json::from_str(&ctl_body).expect("ctl openapi output must parse as JSON");
    let ctl_paths = ctl_spec["paths"].as_object().expect("paths must be an object");
    assert_eq!(
        ctl_paths.len(), direct_path_count,
        "ctl openapi's path count must match the direct GET /v1/openapi.json"
    );
}
