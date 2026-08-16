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
    let data = dir.path().join("data");
    let cfg_path = dir.path().join("relayfabric.yaml");
    std::fs::write(&cfg_path, CONFIG.replace("DATA_DIR", data.to_str().unwrap())).unwrap();
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
    write_frame(w, &PluginToDaemon::Inbound {
        endpoint: endpoint.into(),
        sender: sender.into(),
        kind: "text".into(),
        body: body.into(),
        created_at: Some(created_at),
        attachments,
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

async fn admin_get(sock: &Path, path: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = UnixStream::connect(sock).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.0\r\nhost: x\r\n\r\n").as_bytes()).await.unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).await.unwrap();
    raw.split_once("\r\n\r\n").map(|x| x.1.to_string()).unwrap_or_default()
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
