//! Operator self-alerting (self-hoster feature): the daemon watches its own
//! event stream and, when configured (`alerts:`), sends a short text alert
//! through one of its own plugins on notable operational events — a plugin
//! going down or recovering, a federation peer lost or restored. "The bridge
//! tells you it broke, over your own fabric," with no extra monitoring stack.
//!
//! Reads config LIVE per event (no restart to change `alerts:`), throttles
//! per subject so a flapping plugin can't spam the operator, and is
//! fire-and-forget: an alert that can't be sent (e.g. the alert plugin itself
//! is the one that's down) is simply dropped — a plugin can't report its own
//! outage, so route alerts through a DIFFERENT plugin than the ones you most
//! want to hear about.

use crate::engine::Daemon;
use crate::events::Event;
use relay_ipc::DaemonToPlugin;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast::error::RecvError;
use tracing::{info, warn};

/// At most one alert per subject (`category:name`) per this window, so a
/// plugin that flap-restarts can't flood the operator.
const ALERT_THROTTLE: Duration = Duration::from_secs(60);

static ALERT_THROTTLE_MAP: std::sync::LazyLock<Mutex<HashMap<String, Instant>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Subscribe to the event stream and dispatch alerts forever. Cheap (one
/// broadcast receiver); always spawned, does nothing unless `alerts:` is set.
pub fn spawn_alerter(d: Arc<Daemon>) {
    let mut rx = d.events.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(ev) => handle_event(&d, &ev),
                Err(RecvError::Lagged(_)) => continue, // dropped some events; keep going
                Err(RecvError::Closed) => return,
            }
        }
    });
}

/// The alert (category, subject, text) for an event given the config, or None
/// if this event isn't alertable. Pure, so it's unit-tested without a daemon.
fn alert_for(cfg: &crate::config::AlertConfig, ev: &Event) -> Option<(String, String)> {
    match ev {
        Event::Plugin { name, up, .. } if cfg.wants("plugin") => Some((
            format!("plugin:{name}"),
            format!(
                "plugin '{name}' {}",
                if *up { "recovered" } else { "went DOWN" }
            ),
        )),
        Event::Federation { peer, up, .. } if cfg.wants("federation") => Some((
            format!("federation:{peer}"),
            format!(
                "federation peer '{peer}' {}",
                if *up { "reconnected" } else { "went DOWN" }
            ),
        )),
        _ => None,
    }
}

fn handle_event(d: &Arc<Daemon>, ev: &Event) {
    let Some(cfg) = d.cfg_snapshot(|c| c.alerts.clone()) else {
        return;
    };
    let Some((subject, text)) = alert_for(&cfg, ev) else {
        return;
    };
    // Throttle per subject so a flapping plugin can't spam.
    if !crate::fed::warn_throttle_due(&ALERT_THROTTLE_MAP, &subject, ALERT_THROTTLE) {
        return;
    }
    send_alert(d, &cfg.endpoint, &text);
}

/// Fire-and-forget send of `text` to a `"plugin:endpoint"` target through the
/// plugin's own outbound channel. Uses a sentinel corr (-1): the plugin's
/// delivery_result for it maps to no delivery row and is harmlessly ignored.
fn send_alert(d: &Arc<Daemon>, endpoint: &str, text: &str) {
    let Some((plugin, ep)) = endpoint.split_once(':') else {
        return;
    };
    let tx = {
        let plugins = d.plugins.lock().unwrap();
        plugins
            .get(plugin)
            .filter(|h| h.connected)
            .map(|h| h.tx.clone())
    };
    let Some(tx) = tx else {
        // Alert plugin not connected (possibly it's the thing that's down).
        warn!(plugin, "alert not delivered: alert plugin not connected");
        return;
    };
    let frame = DaemonToPlugin::Send {
        corr: -1,
        endpoint: ep.to_string(),
        kind: "text".to_string(),
        body: format!("[relayfabric alert] {text}"),
        attachments: Vec::new(),
    };
    match tx.try_send(frame) {
        Ok(()) => info!(target = endpoint, "sent operator alert"),
        Err(_) => warn!(target = endpoint, "alert not delivered: plugin channel full/closed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AlertConfig;
    use chrono::Utc;

    fn cfg(events: &[&str]) -> AlertConfig {
        AlertConfig {
            endpoint: "lxmf:bridge".into(),
            events: events.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn plugin_down_and_up_map_to_alerts_when_selected() {
        let c = cfg(&["plugin"]);
        let down = Event::Plugin { name: "meshcore".into(), up: false, ts: Utc::now() };
        let (subj, text) = alert_for(&c, &down).unwrap();
        assert_eq!(subj, "plugin:meshcore");
        assert!(text.contains("meshcore") && text.contains("DOWN"), "{text}");

        let up = Event::Plugin { name: "meshcore".into(), up: true, ts: Utc::now() };
        assert!(alert_for(&c, &up).unwrap().1.contains("recovered"));
    }

    #[test]
    fn federation_event_ignored_when_only_plugin_selected() {
        let c = cfg(&["plugin"]);
        let fed = Event::Federation { peer: "hub".into(), up: false, ts: Utc::now() };
        assert!(alert_for(&c, &fed).is_none());
    }

    #[test]
    fn empty_events_means_all_supported_categories() {
        let c = cfg(&[]);
        let fed = Event::Federation { peer: "hub".into(), up: false, ts: Utc::now() };
        assert!(alert_for(&c, &fed).is_some());
        let pl = Event::Plugin { name: "x".into(), up: false, ts: Utc::now() };
        assert!(alert_for(&c, &pl).is_some());
    }

    #[test]
    fn non_alertable_events_are_ignored() {
        let c = cfg(&[]);
        let cfg_applied = Event::ConfigApplied { restart_required: vec![], ts: Utc::now() };
        assert!(alert_for(&c, &cfg_applied).is_none());
    }
}
