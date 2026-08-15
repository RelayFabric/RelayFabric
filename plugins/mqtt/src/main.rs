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
                        corr,
                        delivered: ok,
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
