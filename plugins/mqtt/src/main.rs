//! RelayFabric MQTT plugin: topics ↔ fabric endpoints over MQTT v5.

use relay_core::Capabilities;
use relay_ipc::{read_frame, write_frame, DaemonToPlugin, PluginToDaemon, PROTOCOL_VERSION};
use rumqttc::v5::mqttbytes::v5::{Filter, Publish};
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::{AsyncClient, ClientError, ConnectionError, Event, Incoming, MqttOptions};
use rumqttc::Outgoing;
use rumqttc::{TlsConfiguration, Transport};
use serde::Deserialize;
use std::collections::{HashMap, VecDeque};
use std::process::ExitCode;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Largest message body advertised to the daemon (`Capabilities.max_payload`).
const MAX_PAYLOAD: u32 = 64_000;
/// Largest MQTT packet this plugin accepts, sent to the broker in CONNECT
/// (Maximum Packet Size) so a v5 broker never delivers a bigger one:
/// MAX_PAYLOAD plus headroom for topic and properties. rumqttc's own
/// default is 10 KiB and NOT advertised, and an oversize incoming packet is
/// a connection error (reconnect), not a dropped message.
const MAX_PACKET_SIZE: u32 = MAX_PAYLOAD + 16 * 1024;

#[derive(Debug, Deserialize)]
struct PluginCfg {
    broker: String,
    #[serde(default)]
    topics: Vec<String>,
    #[serde(default = "default_client_id")]
    client_id: String,
    /// Optional broker login. Over plain `mqtt://` it crosses the wire in
    /// the clear (local/trusted brokers only); use `mqtts://` elsewhere.
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    /// PEM certificate of the private CA that signed the broker's
    /// certificate (`mqtts://`). Unset: the system trust store.
    #[serde(default)]
    ca_file: Option<String>,
}

fn default_client_id() -> String {
    "relayfabric".into()
}

/// `(host, port, tls)` from `mqtt://host[:port]` or `mqtts://host[:port]`.
fn parse_broker(url: &str) -> Result<(String, u16, bool), String> {
    let (rest, tls, default_port) = if let Some(rest) = url.strip_prefix("mqtts://") {
        (rest, true, 8883)
    } else if let Some(rest) = url.strip_prefix("mqtt://") {
        (rest, false, 1883)
    } else {
        return Err("broker must be mqtt://host[:port] or mqtts://host[:port]".into());
    };
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, port.parse().map_err(|_| "bad port".to_string())?),
        None => (rest, default_port),
    };
    Ok((host.into(), port, tls))
}

/// Transport for `mqtts://`: the platform TLS stack verifying against the
/// system trust store, or additionally against the CA certificate at
/// `ca_file`. Broker certificates are always verified; there is no opt-out.
/// A bad `ca_file` is a startup error, never a silent fallback.
fn tls_transport(ca_file: Option<&str>) -> Result<TlsConfiguration, String> {
    let Some(path) = ca_file else {
        return Ok(TlsConfiguration::Native);
    };
    let pem = std::fs::read(path).map_err(|e| format!("ca_file {path}: {e}"))?;
    native_tls::Certificate::from_pem(&pem).map_err(|e| format!("ca_file {path}: {e}"))?;
    Ok(TlsConfiguration::SimpleNative {
        ca: pem,
        client_auth: None,
    })
}

/// Subscriptions for the configured topics. No Local: the broker must not
/// echo our own publishes (MQTT v5) — the transport-level half of loop
/// prevention.
fn subscription_filters(topics: &[String]) -> Vec<Filter> {
    topics
        .iter()
        .map(|t| {
            let mut f = Filter::new(t.clone(), QoS::AtLeastOnce);
            f.nolocal = true;
            f
        })
        .collect()
}

/// Events forwarded from the dedicated eventloop-polling task (spawned in
/// `main`) to the main select loop. Only what the main loop actually needs
/// to act on is forwarded — not the raw rumqttc `Event`.
#[derive(Debug)]
enum MqttEvent {
    /// CONNACK: every (re)connect, with the broker's advertised limit.
    Connected {
        session_present: bool,
        broker_max_packet: Option<u32>,
    },
    Inbound {
        topic: String,
        body: String,
    },
    OutgoingPublish(u16),
    PubAck(u16),
    Error(String),
}

/// Maps one `eventloop.poll()` result to the event the main loop acts on
/// (None for everything it ignores). Pure so the mapping — in particular
/// that a CONNACK surfaces at all, which is what re-subscribing hangs on —
/// is unit-tested without a broker.
fn classify(polled: Result<Event, ConnectionError>) -> Option<MqttEvent> {
    match polled {
        Ok(Event::Incoming(Incoming::ConnAck(ack))) => Some(MqttEvent::Connected {
            session_present: ack.session_present,
            broker_max_packet: ack.properties.and_then(|p| p.max_packet_size),
        }),
        Ok(Event::Incoming(Incoming::Publish(p))) => Some(MqttEvent::Inbound {
            topic: String::from_utf8_lossy(&p.topic).into_owned(),
            body: String::from_utf8_lossy(&p.payload).into_owned(),
        }),
        Ok(Event::Outgoing(Outgoing::Publish(pkid))) => Some(MqttEvent::OutgoingPublish(pkid)),
        Ok(Event::Incoming(Incoming::PubAck(ack))) => Some(MqttEvent::PubAck(ack.pkid)),
        Ok(_) => None,
        Err(e) => Some(MqttEvent::Error(e.to_string())),
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
/// the oldest still-unassigned enqueued publish — within one connection.
/// Across a reconnect the pairing would desync (see `on_disconnect`), so
/// the tracker follows the connection state and resets with it.
struct DeliveryTracker {
    pending_pkid: VecDeque<i64>,
    awaiting_ack: HashMap<u16, i64>,
    /// Connection state as seen through the eventloop's events.
    connected: bool,
    /// `Outgoing::Publish` events a session-present reconnect would replay
    /// (rumqttc re-sends every in-flight and drained request, emitting one
    /// each), computed at disconnect; their corrs were failed then.
    replay_on_resume: usize,
    /// Replayed `Outgoing::Publish` events still to ignore on this
    /// connection before FIFO pairing resumes.
    skip: usize,
}

impl DeliveryTracker {
    fn new() -> Self {
        Self {
            pending_pkid: VecDeque::new(),
            awaiting_ack: HashMap::new(),
            connected: false,
            replay_on_resume: 0,
            skip: 0,
        }
    }

    /// `client.publish(..)` returned `Ok`: the corr is now waiting for
    /// rumqttc's eventloop to assign it a pkid.
    fn on_enqueued(&mut self, corr: i64) {
        self.pending_pkid.push_back(corr);
    }

    /// rumqttc assigned `pkid` to the oldest unassigned enqueued publish. An
    /// `Outgoing::Publish` with nothing pending (e.g. a pkid collision retry
    /// rumqttc reissues internally) is simply ignored, as is one buffered
    /// from before a disconnect (it surfaces before the next CONNACK) or
    /// replayed by a session resume — those publishes were failed already.
    ///
    /// Caps `awaiting_ack` at 1024 and evicts an arbitrary entry if PubAcks
    /// never arrive — bounded memory rather than a leak, and not lost work:
    /// `corr` is the delivery's stable row id, reused verbatim on every
    /// daemon retry, so a requeued Send still earns its own ack via a fresh
    /// pkid; a stray late ack for an evicted entry is at worst a duplicate
    /// `delivered` the daemon's delivery state machine ignores.
    fn on_outgoing_publish(&mut self, pkid: u16) {
        if !self.connected {
            return;
        }
        if self.skip > 0 {
            self.skip -= 1;
            return;
        }
        let Some(corr) = self.pending_pkid.pop_front() else {
            return;
        };
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

    /// The connection dropped. rumqttc drains both the in-flight publishes
    /// and the not-yet-sent requests into a "pending" list that a
    /// clean_start reconnect (this plugin's mode) throws away, so nothing
    /// tracked here will ever be acked: fail every corr so the daemon
    /// retries, and reset so the FIFO pairing starts clean on the next
    /// connection. Errors while already disconnected (each failed reconnect
    /// attempt) change nothing — Sends enqueued during the outage stay in
    /// rumqttc's channel and go out, correctly paired, after reconnect.
    fn on_disconnect(&mut self) -> Vec<i64> {
        if !self.connected {
            return Vec::new();
        }
        self.connected = false;
        self.replay_on_resume = self.pending_pkid.len() + self.awaiting_ack.len();
        let mut failed: Vec<i64> = self.pending_pkid.drain(..).collect();
        failed.extend(self.awaiting_ack.drain().map(|(_, corr)| corr));
        failed
    }

    /// CONNACK. With a resumed session the broker-side state survived and
    /// rumqttc replays the pending list (one `Outgoing::Publish` each) ahead
    /// of anything newer; those were failed at disconnect, so skip them.
    fn on_connect(&mut self, session_present: bool) {
        self.connected = true;
        self.skip = if session_present {
            self.replay_on_resume
        } else {
            0
        };
        self.replay_on_resume = 0;
    }

    #[cfg(test)]
    fn awaiting_count(&self) -> usize {
        self.awaiting_ack.len()
    }
}

/// What the main loop does in response to a broker event, computed by
/// `Bridge::on_mqtt` without touching the network so the reconnect paths
/// (which a broker-less unit test can't drive through rumqttc) are
/// testable. The main loop only performs the I/O.
#[derive(Debug, PartialEq)]
enum Action {
    /// (Re)issue the configured subscriptions. The session is clean_start,
    /// so the broker forgets them on every reconnect; without this a
    /// reconnect leaves the plugin alive, answering Ping, and deaf.
    Subscribe(Vec<Filter>),
    /// Forward a received publish to the daemon.
    Inbound { topic: String, body: String },
    /// Report a delivery outcome to the daemon.
    Result {
        corr: i64,
        delivered: bool,
        detail: Option<String>,
    },
}

struct Bridge {
    filters: Vec<Filter>,
    tracker: DeliveryTracker,
    /// The broker's Maximum Packet Size from CONNACK, when it sent one.
    broker_max_packet: Option<u32>,
}

impl Bridge {
    fn new(topics: &[String]) -> Self {
        Self {
            filters: subscription_filters(topics),
            tracker: DeliveryTracker::new(),
            broker_max_packet: None,
        }
    }

    fn on_mqtt(&mut self, ev: MqttEvent) -> Vec<Action> {
        match ev {
            MqttEvent::Connected {
                session_present,
                broker_max_packet,
            } => {
                self.tracker.on_connect(session_present);
                self.broker_max_packet = broker_max_packet;
                if self.filters.is_empty() {
                    // an empty SUBSCRIBE is a protocol error rumqttc turns
                    // into a reconnect loop
                    Vec::new()
                } else {
                    vec![Action::Subscribe(self.filters.clone())]
                }
            }
            MqttEvent::Inbound { topic, body } => vec![Action::Inbound { topic, body }],
            MqttEvent::OutgoingPublish(pkid) => {
                self.tracker.on_outgoing_publish(pkid);
                Vec::new()
            }
            MqttEvent::PubAck(pkid) => self
                .tracker
                .on_puback(pkid)
                .map(|corr| Action::Result {
                    corr,
                    delivered: true,
                    detail: None,
                })
                .into_iter()
                .collect(),
            MqttEvent::Error(e) => {
                warn!(error = %e, "mqtt error, reconnecting in 5s");
                self.tracker
                    .on_disconnect()
                    .into_iter()
                    .map(|corr| Action::Result {
                        corr,
                        delivered: false,
                        detail: Some(format!("mqtt connection lost before broker ack: {e}")),
                    })
                    .collect()
            }
        }
    }

    /// Outbound size gate against the broker's advertised limit. Done here,
    /// per message, because rumqttc enforces it at write time as a
    /// connection error — which reconnects, replays the same publish, and
    /// fails again, forever.
    fn fits_broker(&self, publish: &Publish) -> Result<(), String> {
        match self.broker_max_packet {
            Some(max) if publish.size() > max as usize => Err(format!(
                "publish of {} bytes exceeds broker max packet size {max}",
                publish.size()
            )),
            _ => Ok(()),
        }
    }
}

/// The QoS1 packet for an outbound Send, sized as it will go on the wire
/// (`size()` counts the packet id only once one is set).
fn outbound_publish(topic: &str, body: String) -> Publish {
    let mut p = Publish::new(topic, QoS::AtLeastOnce, body.into_bytes(), None);
    p.pkid = 1;
    p
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().init();
    let socket = std::env::var("RELAYFABRIC_SOCKET").expect("RELAYFABRIC_SOCKET");
    let name = std::env::var("RELAYFABRIC_PLUGIN_NAME").unwrap_or_else(|_| "mqtt".into());
    let cfg: PluginCfg = serde_json::from_str(
        &std::env::var("RELAYFABRIC_PLUGIN_CONFIG").expect("RELAYFABRIC_PLUGIN_CONFIG"),
    )
    .expect("valid plugin config JSON");
    // The config may carry secrets the daemon resolved from ${env:}/${file:}
    // references; scrub it so nothing this process spawns inherits it (and
    // it is no longer readable via /proc/self/environ).
    std::env::remove_var("RELAYFABRIC_PLUGIN_CONFIG");

    let (host, port, tls) = parse_broker(&cfg.broker).expect("broker url");
    let mut opts = MqttOptions::new(&cfg.client_id, host, port);
    opts.set_keep_alive(Duration::from_secs(30));
    opts.set_max_packet_size(Some(MAX_PACKET_SIZE));
    if tls {
        let tls = tls_transport(cfg.ca_file.as_deref()).expect("broker tls");
        opts.set_transport(Transport::tls_with_config(tls));
    }
    if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        opts.set_credentials(user, pass);
    }
    let (client, mut eventloop) = AsyncClient::new(opts, 64);

    let stream = tokio::net::UnixStream::connect(&socket)
        .await
        .expect("daemon socket");
    let (mut r, mut w) = stream.into_split();
    write_frame(
        &mut w,
        &PluginToDaemon::Hello {
            plugin: name.clone(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: PROTOCOL_VERSION,
            capabilities: Capabilities {
                groups: true,
                max_payload: Some(u64::from(MAX_PAYLOAD)),
                ..Default::default()
            },
        },
    )
    .await
    .expect("hello");
    match read_frame::<_, DaemonToPlugin>(&mut r)
        .await
        .expect("hello ack")
    {
        DaemonToPlugin::HelloAck { error: None, .. } => info!("registered with switchyardd"),
        DaemonToPlugin::HelloAck { error: Some(e), .. } => panic!("daemon refused us: {e}"),
        other => panic!("unexpected ack: {other:?}"),
    }

    // Subscriptions are issued on every CONNACK (Bridge::on_mqtt), the first
    // connection included -- not once here -- because clean_start sessions
    // lose them on every reconnect.

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
                Err(e) => {
                    // EOF (daemon gone) or a malformed frame: dropping
                    // frames_tx closes the channel and the main loop exits
                    // non-zero so a `Restart=on-failure` unit restarts us.
                    warn!(error = %e, "daemon connection lost");
                    return;
                }
            }
        }
    });

    // The eventloop's request channel (cap 64, see AsyncClient::new above)
    // only drains via eventloop.poll(). If poll() lived in THIS same select
    // loop, a broker outage with >64 pending publishes would wedge this
    // loop forever — and since poll() never runs again, the eventloop
    // can't even reconnect once the broker comes back. The standard rumqttc
    // pattern avoids this: a dedicated task owns the eventloop and polls it
    // continuously, forwarding just the events the main loop needs over an
    // mpsc channel. That keeps reconnects retrying independently of
    // whatever the main loop happens to be awaiting. Publishes below use
    // try_publish for the same reason: while the broker is down nothing
    // drains the channel, and a blocking publish would stall the loop past
    // the daemon's liveness window (no Pong) -- a full queue is reported as
    // a failed delivery for the daemon to retry instead.
    let (mqtt_tx, mut mqtt_rx) = mpsc::channel::<MqttEvent>(256);
    tokio::spawn(async move {
        loop {
            let polled = eventloop.poll().await;
            let failed = polled.is_err();
            if let Some(ev) = classify(polled) {
                if mqtt_tx.send(ev).await.is_err() {
                    return;
                }
            }
            if failed {
                // throttle so a persistent failure (e.g. broker down)
                // doesn't hot-loop this task calling poll() repeatedly.
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    });

    let mut bridge = Bridge::new(&cfg.topics);

    loop {
        tokio::select! {
            event = mqtt_rx.recv() => {
                let Some(event) = event else {
                    warn!("mqtt eventloop task ended");
                    return ExitCode::FAILURE;
                };
                for action in bridge.on_mqtt(event) {
                    let frame = match action {
                        Action::Subscribe(filters) => {
                            if let Err(e) = client.subscribe_many(filters).await {
                                warn!(error = %e, "subscribe failed");
                            }
                            continue;
                        }
                        Action::Inbound { topic, body } => PluginToDaemon::Inbound {
                            endpoint: topic.clone(),
                            sender: topic, // MQTT has no per-message sender identity
                            kind: "text".into(),
                            body,
                            created_at: Some(chrono::Utc::now()),
                            attachments: vec![],
                            priority: None,
                        },
                        Action::Result { corr, delivered, detail } => {
                            PluginToDaemon::DeliveryResult { corr, delivered, detail }
                        }
                    };
                    if write_frame(&mut w, &frame).await.is_err() {
                        warn!("daemon connection lost");
                        return ExitCode::FAILURE;
                    }
                }
            },
            frame = frames_rx.recv() => match frame {
                Some(DaemonToPlugin::Send { corr, endpoint, body, .. }) => {
                    let publish = outbound_publish(&endpoint, body);
                    let enqueued = match bridge.fits_broker(&publish) {
                        Ok(()) => client
                            .try_publish(endpoint, QoS::AtLeastOnce, false, publish.payload)
                            .map_err(|e| match e {
                                ClientError::TryRequest(_) => "mqtt request queue full".to_string(),
                                other => other.to_string(),
                            }),
                        Err(e) => Err(e),
                    };
                    match enqueued {
                        // Not yet delivered: try_publish only enqueues onto rumqttc's
                        // eventloop channel. The real DeliveryResult is emitted once
                        // the broker's PUBACK arrives (see MqttEvent::PubAck above).
                        Ok(()) => bridge.tracker.on_enqueued(corr),
                        Err(detail) => {
                            let result = PluginToDaemon::DeliveryResult {
                                corr, delivered: false, detail: Some(detail),
                            };
                            if write_frame(&mut w, &result).await.is_err() {
                                warn!("daemon connection lost");
                                return ExitCode::FAILURE;
                            }
                        }
                    }
                }
                // the one clean exit: the daemon asked us to stop
                Some(DaemonToPlugin::Shutdown) => return ExitCode::SUCCESS,
                None => return ExitCode::FAILURE, // reader task logged why
                Some(DaemonToPlugin::Ping) => {
                    // Liveness probe: answer or the daemon restarts us.
                    if write_frame(&mut w, &PluginToDaemon::Pong).await.is_err() {
                        warn!("daemon connection lost");
                        return ExitCode::FAILURE;
                    }
                }
                // a newer daemon's frame this build doesn't know: ignored by
                // contract (docs/plugin-authors.md §3), never fatal
                Some(DaemonToPlugin::Unknown) => debug!("ignoring frame with unknown tag"),
                Some(_) => {}
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rumqttc::v5::mqttbytes::v5::{ConnAck, ConnectReturnCode};

    #[test]
    fn parses_broker_url() {
        assert_eq!(
            parse_broker("mqtt://10.0.0.5:1883").unwrap(),
            ("10.0.0.5".into(), 1883, false)
        );
        assert_eq!(
            parse_broker("mqtt://broker.local").unwrap(),
            ("broker.local".into(), 1883, false)
        );
        assert_eq!(
            parse_broker("mqtts://broker.example").unwrap(),
            ("broker.example".into(), 8883, true)
        );
        assert_eq!(
            parse_broker("mqtts://broker.example:8884").unwrap(),
            ("broker.example".into(), 8884, true)
        );
        assert!(parse_broker("http://x").is_err());
    }

    /// A `ca_file` that cannot be read or holds no certificate is a startup
    /// error, never a silent fallback to the system roots.
    #[test]
    fn tls_transport_refuses_an_unusable_ca_file() {
        let err = tls_transport(Some("/nonexistent/ca.pem")).unwrap_err();
        assert!(err.contains("ca_file"), "err was: {err}");
        let dir = std::env::temp_dir().join(format!("rf-mqtt-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("ca.pem");
        std::fs::write(&bad, "not a certificate").unwrap();
        let err = tls_transport(Some(bad.to_str().unwrap())).unwrap_err();
        assert!(err.contains("ca_file"), "err was: {err}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn config_defaults() {
        let cfg: PluginCfg =
            serde_json::from_str(r#"{"broker":"mqtt://127.0.0.1:1883","topics":["a/b"]}"#).unwrap();
        assert_eq!(cfg.client_id, "relayfabric");
        assert_eq!(cfg.topics, vec!["a/b"]);
        assert_eq!(cfg.username, None);
        assert_eq!(cfg.password, None);
        assert_eq!(cfg.ca_file, None);
    }

    #[test]
    fn config_accepts_broker_credentials() {
        let cfg: PluginCfg = serde_json::from_str(
            r#"{"broker":"mqtt://127.0.0.1","username":"relay","password":"s3cret"}"#,
        )
        .unwrap();
        assert_eq!(cfg.username.as_deref(), Some("relay"));
        assert_eq!(cfg.password.as_deref(), Some("s3cret"));
    }

    /// Every configured topic becomes a QoS1, No-Local subscription.
    #[test]
    fn subscription_filters_are_qos1_nolocal() {
        let f = subscription_filters(&["a/b".to_string(), "c/#".to_string()]);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|f| f.nolocal && f.qos == QoS::AtLeastOnce));
        assert_eq!(f[1].path, "c/#");
    }

    fn connack(session_present: bool) -> Result<Event, ConnectionError> {
        Ok(Event::Incoming(Incoming::ConnAck(ConnAck {
            session_present,
            code: ConnectReturnCode::Success,
            properties: None,
        })))
    }

    /// The eventloop task must surface CONNACK to the main loop (that is
    /// what re-subscribing hangs on) and a poll error as `Error`.
    #[test]
    fn classify_surfaces_connack_and_errors() {
        assert!(matches!(
            classify(connack(true)),
            Some(MqttEvent::Connected {
                session_present: true,
                broker_max_packet: None
            })
        ));
        assert!(classify(Ok(Event::Outgoing(Outgoing::PingReq))).is_none());
        assert!(matches!(
            classify(Err(ConnectionError::RequestsDone)),
            Some(MqttEvent::Error(_))
        ));
    }

    fn connected(session_present: bool) -> MqttEvent {
        MqttEvent::Connected {
            session_present,
            broker_max_packet: None,
        }
    }

    /// The reconnect bug: subscriptions must be issued on EVERY connect, not
    /// once at startup, or a reconnect leaves the plugin deaf.
    #[test]
    fn every_connack_resubscribes_the_configured_topics() {
        let mut b = Bridge::new(&["chat/a".to_string()]);
        let expected = Action::Subscribe(subscription_filters(&["chat/a".to_string()]));
        assert_eq!(b.on_mqtt(connected(false)), vec![expected]);
        // broker bounces
        b.on_mqtt(MqttEvent::Error("broker went away".into()));
        let again = b.on_mqtt(connected(false));
        assert_eq!(
            again,
            vec![Action::Subscribe(subscription_filters(&[
                "chat/a".to_string()
            ]))],
            "the reconnect must re-issue the subscriptions"
        );
    }

    /// No topics configured: no SUBSCRIBE at all (an empty one is a
    /// protocol error that would reconnect-loop).
    #[test]
    fn no_topics_means_no_subscribe_on_connect() {
        let mut b = Bridge::new(&[]);
        assert!(b.on_mqtt(connected(false)).is_empty());
    }

    #[test]
    fn tracker_correlates_enqueue_outgoing_and_puback() {
        let mut t = DeliveryTracker::new();
        t.on_connect(false);
        t.on_enqueued(42);
        t.on_outgoing_publish(7);
        assert_eq!(t.on_puback(7), Some(42));
        // a stray second PUBACK for the same pkid must not resurrect the corr
        assert_eq!(t.on_puback(7), None);
    }

    #[test]
    fn tracker_pairs_fifo_across_multiple_pending() {
        let mut t = DeliveryTracker::new();
        t.on_connect(false);
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
        t.on_connect(false);
        t.on_outgoing_publish(9); // no prior on_enqueued call
        assert_eq!(t.on_puback(9), None);
    }

    #[test]
    fn tracker_caps_awaiting_ack_to_bound_memory() {
        let mut t = DeliveryTracker::new();
        t.on_connect(false);
        for pkid in 0u16..1100 {
            t.on_enqueued(i64::from(pkid));
            t.on_outgoing_publish(pkid);
        }
        assert!(
            t.awaiting_count() <= 1024,
            "awaiting_ack grew unbounded: {}",
            t.awaiting_count()
        );
    }

    /// A disconnect fails everything tracked (nothing in flight or drained
    /// will ever be acked on a clean_start session) and resets the FIFO, so
    /// an ack on the next connection can't be attributed to a message that
    /// was never published there.
    #[test]
    fn tracker_fails_inflight_and_pending_on_disconnect_and_resets() {
        let mut t = DeliveryTracker::new();
        t.on_connect(false);
        t.on_enqueued(1);
        t.on_outgoing_publish(10); // 1 is in flight
        t.on_enqueued(2); // 2 enqueued, no pkid yet
        let mut failed = t.on_disconnect();
        failed.sort();
        assert_eq!(failed, vec![1, 2]);
        assert_eq!(t.awaiting_count(), 0);
        // a late/buffered event from the dead connection: ignored
        t.on_outgoing_publish(11);
        assert_eq!(t.on_puback(10), None, "old pkids are dead");
        // a repeat error while still down fails nothing twice
        t.on_enqueued(3); // retry enqueued during the outage
        assert_eq!(t.on_disconnect(), Vec::<i64>::new());
        // reconnect: the outage-time Send pairs with the first new pkid
        t.on_connect(false);
        t.on_outgoing_publish(1);
        assert_eq!(t.on_puback(1), Some(3));
    }

    /// Before the first CONNACK nothing is paired: a pkid event can't be
    /// real yet, and Sends enqueued early wait for the first connection.
    #[test]
    fn tracker_pairs_nothing_before_first_connect() {
        let mut t = DeliveryTracker::new();
        t.on_enqueued(5);
        t.on_outgoing_publish(1);
        assert_eq!(t.on_puback(1), None);
        t.on_connect(false);
        t.on_outgoing_publish(1);
        assert_eq!(t.on_puback(1), Some(5));
    }

    /// A resumed session replays the publishes rumqttc held across the
    /// outage (one `Outgoing::Publish` each, already failed at disconnect);
    /// those must not consume the corrs of newer Sends.
    #[test]
    fn tracker_skips_session_resume_replays() {
        let mut t = DeliveryTracker::new();
        t.on_connect(false);
        t.on_enqueued(1);
        t.on_outgoing_publish(10); // in flight
        t.on_enqueued(2); // drained at disconnect
        assert_eq!(t.on_disconnect().len(), 2);
        t.on_enqueued(3); // new Send during the outage
        t.on_connect(true); // session resumed: 1 and 2 are replayed first
        t.on_outgoing_publish(10);
        t.on_outgoing_publish(11);
        t.on_outgoing_publish(12); // this one is 3
        assert_eq!(t.on_puback(10), None);
        assert_eq!(t.on_puback(11), None);
        assert_eq!(t.on_puback(12), Some(3));
    }

    /// End-to-end through the bridge: a disconnect turns every unacked
    /// Send into a failed DeliveryResult for the daemon to retry.
    #[test]
    fn bridge_reports_unacked_sends_failed_on_disconnect() {
        let mut b = Bridge::new(&[]);
        b.on_mqtt(connected(false));
        b.tracker.on_enqueued(7);
        b.on_mqtt(MqttEvent::OutgoingPublish(1));
        let actions = b.on_mqtt(MqttEvent::Error("eof".into()));
        assert!(
            matches!(
                &actions[..],
                [Action::Result {
                    corr: 7,
                    delivered: false,
                    detail: Some(_)
                }]
            ),
            "{actions:?}"
        );
        // and a PubAck for the dead connection's pkid reports nothing
        assert!(b.on_mqtt(MqttEvent::PubAck(1)).is_empty());
    }

    /// An outbound publish bigger than the broker's advertised Maximum
    /// Packet Size is refused per message, not handed to rumqttc (where it
    /// becomes a reconnect loop).
    #[test]
    fn oversize_publish_is_refused_against_broker_limit() {
        let mut b = Bridge::new(&[]);
        b.on_mqtt(MqttEvent::Connected {
            session_present: false,
            broker_max_packet: Some(100),
        });
        let small = outbound_publish("t", "x".repeat(50));
        assert!(b.fits_broker(&small).is_ok());
        let big = outbound_publish("t", "x".repeat(100));
        assert!(b.fits_broker(&big).is_err());
        // no limit advertised: nothing to refuse against
        let mut unlimited = Bridge::new(&[]);
        unlimited.on_mqtt(connected(false));
        assert!(unlimited.fits_broker(&big).is_ok());
    }

    /// The wire size counts the QoS1 packet id, which `Publish::size`
    /// only does once one is set.
    #[test]
    fn outbound_publish_size_counts_the_packet_id() {
        let p = outbound_publish("t", String::new());
        // fixed header 1 + remaining-length 1 + topic (2 + 1) + pkid 2 + props 1
        assert_eq!(p.size(), 8);
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
