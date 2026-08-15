//! RelayFabric MQTT plugin: topics ↔ fabric endpoints over MQTT v5.

use relay_core::Capabilities;
use relay_ipc::{read_frame, write_frame, DaemonToPlugin, PluginToDaemon, PROTOCOL_VERSION};
use rumqttc::v5::mqttbytes::v5::Filter;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::{AsyncClient, Event, Incoming, MqttOptions};
use rumqttc::Outgoing;
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
struct PluginCfg {
    broker: String,
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default = "default_client_id")]
    client_id: String,
}

fn default_client_id() -> String {
    "relayfabric".into()
}

fn parse_broker(url: &str) -> Result<(String, u16), String> {
    let rest = url.strip_prefix("mqtt://").ok_or("broker must be mqtt://host[:port]")?;
    match rest.split_once(':') {
        Some((host, port)) => Ok((host.into(), port.parse().map_err(|_| "bad port".to_string())?)),
        None => Ok((rest.into(), 1883)),
    }
}

/// Correlates locally-enqueued `Send` requests with broker QoS1 PUBACKs, so
/// `DeliveryResult` reflects broker acknowledgment rather than merely local
/// eventloop-channel enqueue (spec §70 forbids fabricating delivery
/// guarantees).
///
/// This plugin is the only publisher on its `AsyncClient`, and rumqttc
/// assigns pkids to enqueued publishes in FIFO order, so a plain queue
/// correctly pairs each `Outgoing::Publish` pkid assignment with the corr of
/// the oldest still-unassigned enqueued publish.
struct DeliveryTracker {
    pending_pkid: VecDeque<i64>,
    awaiting_ack: HashMap<u16, i64>,
}

impl DeliveryTracker {
    fn new() -> Self {
        Self { pending_pkid: VecDeque::new(), awaiting_ack: HashMap::new() }
    }

    /// `client.publish(..)` returned `Ok`: the corr is now waiting for
    /// rumqttc's eventloop to assign it a pkid.
    fn on_enqueued(&mut self, corr: i64) {
        self.pending_pkid.push_back(corr);
    }

    /// rumqttc assigned `pkid` to the oldest unassigned enqueued publish. An
    /// `Outgoing::Publish` with nothing pending (e.g. a pkid collision retry
    /// rumqttc reissues internally) is simply ignored.
    ///
    /// ponytail: caps `awaiting_ack` at 1024 and evicts an arbitrary entry
    /// (a `HashMap` has no order, so "oldest" isn't cheaply tracked) if
    /// PubAcks never arrive for some entries — e.g. the broker goes down
    /// indefinitely. Capping bounds memory instead of leaking forever; it
    /// isn't lost work, because the daemon's `reclaim_stale` (60s) requeues
    /// the delivery with a fresh corr regardless, so a late ack for an
    /// evicted pkid is just ignored rather than misattributed to a
    /// different corr. Pruning on reconnect (`Incoming::ConnAck`) was the
    /// other option, but it requires reasoning about rumqttc's own
    /// reconnect/retransmission bookkeeping to avoid dropping entries that
    /// are still live; the size cap is simpler and doesn't depend on that.
    fn on_outgoing_publish(&mut self, pkid: u16) {
        let Some(corr) = self.pending_pkid.pop_front() else { return };
        self.awaiting_ack.insert(pkid, corr);
        if self.awaiting_ack.len() > 1024 {
            if let Some(stale) = self.awaiting_ack.keys().next().copied() {
                self.awaiting_ack.remove(&stale);
            }
        }
    }

    /// Broker acknowledged `pkid`; returns the corr to report as delivered.
    fn on_puback(&mut self, pkid: u16) -> Option<i64> {
        self.awaiting_ack.remove(&pkid)
    }

    #[cfg(test)]
    fn awaiting_count(&self) -> usize {
        self.awaiting_ack.len()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    let socket = std::env::var("RELAYFABRIC_SOCKET").expect("RELAYFABRIC_SOCKET");
    let name = std::env::var("RELAYFABRIC_PLUGIN_NAME").unwrap_or_else(|_| "mqtt".into());
    let cfg: PluginCfg = serde_json::from_str(
        &std::env::var("RELAYFABRIC_PLUGIN_CONFIG").expect("RELAYFABRIC_PLUGIN_CONFIG"),
    )
    .expect("valid plugin config JSON");

    let (host, port) = parse_broker(&cfg.broker).expect("broker url");
    let mut opts = MqttOptions::new(&cfg.client_id, host, port);
    opts.set_keep_alive(Duration::from_secs(30));
    let (client, mut eventloop) = AsyncClient::new(opts, 64);

    let stream = tokio::net::UnixStream::connect(&socket).await.expect("daemon socket");
    let (mut r, mut w) = stream.into_split();
    write_frame(
        &mut w,
        &PluginToDaemon::Hello {
            plugin: name.clone(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: Capabilities { groups: true, max_payload: Some(64_000), ..Default::default() },
        },
    )
    .await
    .expect("hello");
    match read_frame::<_, DaemonToPlugin>(&mut r).await.expect("hello ack") {
        DaemonToPlugin::HelloAck { error: None, .. } => info!("registered with switchyardd"),
        DaemonToPlugin::HelloAck { error: Some(e), .. } => panic!("daemon refused us: {e}"),
        other => panic!("unexpected ack: {other:?}"),
    }

    // No Local: broker must not echo our own publishes (MQTT v5) — the
    // transport-level half of loop prevention.
    let filters: Vec<Filter> = cfg
        .topics
        .iter()
        .map(|t| {
            let mut f = Filter::new(t.clone(), QoS::AtLeastOnce);
            f.nolocal = true;
            f
        })
        .collect();
    if !filters.is_empty() {
        client.subscribe_many(filters).await.expect("subscribe");
    }

    // read_frame is NOT cancel-safe: it does two sequential read_exact
    // awaits (length header, then body), and tokio::select! drops the
    // losing branch mid-await. Racing it directly against eventloop.poll()
    // would let a poll() win mid-read, discarding already-consumed bytes
    // and permanently desyncing the length-prefixed IPC stream. Instead, a
    // dedicated reader task owns the read half and always drives read_frame
    // to completion, forwarding whole frames over an mpsc channel; the main
    // loop then selects on `frames_rx.recv()`, which IS cancel-safe.
    let (frames_tx, mut frames_rx) = mpsc::channel::<DaemonToPlugin>(64);
    tokio::spawn(async move {
        loop {
            match read_frame::<_, DaemonToPlugin>(&mut r).await {
                Ok(frame) => {
                    if frames_tx.send(frame).await.is_err() {
                        return;
                    }
                }
                Err(_) => return, // dropping frames_tx closes the channel
            }
        }
    });

    let mut tracker = DeliveryTracker::new();

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
                Ok(Event::Outgoing(Outgoing::Publish(pkid))) => tracker.on_outgoing_publish(pkid),
                Ok(Event::Incoming(Incoming::PubAck(ack))) => {
                    if let Some(corr) = tracker.on_puback(ack.pkid) {
                        let result = PluginToDaemon::DeliveryResult { corr, delivered: true, detail: None };
                        if write_frame(&mut w, &result).await.is_err() {
                            warn!("daemon connection lost");
                            return;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(error = %e, "mqtt error, reconnecting in 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            },
            frame = frames_rx.recv() => match frame {
                Some(DaemonToPlugin::Send { corr, endpoint, body, .. }) => {
                    match client.publish(endpoint, QoS::AtLeastOnce, false, body.into_bytes()).await {
                        // Not yet delivered: publish() only enqueues onto rumqttc's
                        // eventloop channel. The real DeliveryResult is emitted once
                        // the broker's PUBACK arrives (see Incoming::PubAck above).
                        Ok(()) => tracker.on_enqueued(corr),
                        Err(e) => {
                            let result = PluginToDaemon::DeliveryResult {
                                corr, delivered: false, detail: Some(e.to_string()),
                            };
                            if write_frame(&mut w, &result).await.is_err() {
                                warn!("daemon connection lost");
                                return;
                            }
                        }
                    }
                }
                Some(DaemonToPlugin::Shutdown) | None => return,
                Some(_) => {}
            },
        }
    }
}

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

    #[test]
    fn tracker_correlates_enqueue_outgoing_and_puback() {
        let mut t = DeliveryTracker::new();
        t.on_enqueued(42);
        t.on_outgoing_publish(7);
        assert_eq!(t.on_puback(7), Some(42));
        // a stray second PUBACK for the same pkid must not resurrect the corr
        assert_eq!(t.on_puback(7), None);
    }

    #[test]
    fn tracker_pairs_fifo_across_multiple_pending() {
        let mut t = DeliveryTracker::new();
        t.on_enqueued(1);
        t.on_enqueued(2);
        t.on_outgoing_publish(100); // oldest enqueued (1) gets the first pkid
        t.on_outgoing_publish(200);
        assert_eq!(t.on_puback(200), Some(2));
        assert_eq!(t.on_puback(100), Some(1));
    }

    #[test]
    fn tracker_ignores_outgoing_publish_with_nothing_pending() {
        let mut t = DeliveryTracker::new();
        t.on_outgoing_publish(9); // no prior on_enqueued call
        assert_eq!(t.on_puback(9), None);
    }

    #[test]
    fn tracker_caps_awaiting_ack_to_bound_memory() {
        let mut t = DeliveryTracker::new();
        for pkid in 0u16..1100 {
            t.on_enqueued(i64::from(pkid));
            t.on_outgoing_publish(pkid);
        }
        assert!(t.awaiting_count() <= 1024, "awaiting_ack grew unbounded: {}", t.awaiting_count());
    }

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
}
