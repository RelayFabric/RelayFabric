//! Transport-class model (design doc §1, 2026-08-17): a first-class notion of
//! the *link* a plugin rides, separate from the plugin's protocol
//! `Capabilities`. The same protocol can ride a very different link (Signal
//! over fiber vs. Signal-shaped traffic bridged over a LoRa mesh), and
//! routing/policy decisions such as payload caps and media demotion should
//! be driven by the link's characteristics, not just the protocol.
//!
//! These types are ADDITIVE and are never embedded in `Envelope` or any
//! other struct that crosses the relay-ipc wire — the golden frame tests in
//! `relay-ipc` assert their byte shape stays untouched by this module.

use serde::Deserialize;
use std::fmt;
use std::str::FromStr;

/// The class of link a plugin's traffic actually rides. Distinct from the
/// plugin's protocol: e.g. an MQTT-based plugin bridged over a LoRa radio is
/// still "MQTT" at the protocol layer but `Meshtastic` at the transport
/// layer, and the policy engine should degrade based on the latter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportClass {
    /// MQTT/Signal/Nostr/Bitchat/etc. over broadband or cellular IP.
    TerrestrialInternet,
    /// T-Satellite / Starlink Direct-to-Cell / Iridium — constrained IP.
    SatelliteInternet,
    /// LXMF/RNS.
    Reticulum,
    /// LoRa (Meshtastic firmware).
    Meshtastic,
    /// LoRa (MeshCore firmware).
    MeshCore,
    /// BLE nearby.
    Bluetooth,
    /// Wi-Fi Direct / Aware / LAN.
    LocalNetwork,
}

impl FromStr for TransportClass {
    type Err = String;

    /// Parses the same snake_case names `Deserialize` accepts from config
    /// (e.g. `"satellite_internet"`), for callers that have a bare `&str`
    /// rather than a config value to deserialize.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "terrestrial_internet" => Ok(TransportClass::TerrestrialInternet),
            "satellite_internet" => Ok(TransportClass::SatelliteInternet),
            "reticulum" => Ok(TransportClass::Reticulum),
            "meshtastic" => Ok(TransportClass::Meshtastic),
            "mesh_core" => Ok(TransportClass::MeshCore),
            "bluetooth" => Ok(TransportClass::Bluetooth),
            "local_network" => Ok(TransportClass::LocalNetwork),
            other => Err(format!("unknown transport class '{other}'")),
        }
    }
}

impl fmt::Display for TransportClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TransportClass::TerrestrialInternet => "terrestrial_internet",
            TransportClass::SatelliteInternet => "satellite_internet",
            TransportClass::Reticulum => "reticulum",
            TransportClass::Meshtastic => "meshtastic",
            TransportClass::MeshCore => "mesh_core",
            TransportClass::Bluetooth => "bluetooth",
            TransportClass::LocalNetwork => "local_network",
        };
        f.write_str(s)
    }
}

/// Link throughput, coarse-grained for policy purposes (not a measured
/// figure).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bandwidth {
    High,
    Medium,
    Low,
    VeryLow,
}

/// Link round-trip latency, coarse-grained for policy purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Latency {
    Low,
    Medium,
    High,
}

/// The link characteristics of a `TransportClass` — inputs to policy
/// derivation (`TransportPolicy::for_class`), not policy itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportCharacteristics {
    pub bandwidth: Bandwidth,
    pub latency: Latency,
    /// Gaps/timeouts are expected in normal operation (satellite passes,
    /// LoRa duty cycling, BLE range) — not just failure conditions.
    pub intermittent: bool,
    /// The link has a meaningful per-byte or per-connection cost.
    pub metered: bool,
    /// Undeliverable traffic should be queued for opportunistic delivery
    /// rather than dropped.
    pub store_and_forward: bool,
}

impl TransportClass {
    /// The built-in default characteristics table (design §1). Exact values
    /// per class — see the task-1 report for the rationale behind each.
    pub fn characteristics(self) -> TransportCharacteristics {
        match self {
            TransportClass::SatelliteInternet => TransportCharacteristics {
                bandwidth: Bandwidth::VeryLow,
                latency: Latency::High,
                intermittent: true,
                metered: true,
                store_and_forward: true,
            },
            TransportClass::Meshtastic => TransportCharacteristics {
                bandwidth: Bandwidth::VeryLow,
                latency: Latency::High,
                intermittent: true,
                metered: false,
                store_and_forward: true,
            },
            TransportClass::MeshCore => TransportCharacteristics {
                bandwidth: Bandwidth::VeryLow,
                latency: Latency::High,
                intermittent: true,
                metered: false,
                store_and_forward: true,
            },
            TransportClass::Reticulum => TransportCharacteristics {
                bandwidth: Bandwidth::Low,
                latency: Latency::High,
                intermittent: true,
                metered: false,
                store_and_forward: true,
            },
            TransportClass::TerrestrialInternet => TransportCharacteristics {
                bandwidth: Bandwidth::High,
                latency: Latency::Low,
                intermittent: false,
                metered: false,
                store_and_forward: true,
            },
            TransportClass::Bluetooth => TransportCharacteristics {
                bandwidth: Bandwidth::Medium,
                latency: Latency::Low,
                intermittent: true,
                metered: false,
                store_and_forward: true,
            },
            TransportClass::LocalNetwork => TransportCharacteristics {
                bandwidth: Bandwidth::Medium,
                latency: Latency::Low,
                intermittent: false,
                metered: false,
                store_and_forward: true,
            },
        }
    }
}

/// Effective egress rules for a transport class, derived from its
/// `TransportCharacteristics`. Config (Phase 1 §2, a later task) can
/// override individual fields on top of these defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportPolicy {
    /// Hard payload cap the link imposes, in bytes. This is the TRANSPORT
    /// cap and composes with (does not replace) a plugin's own
    /// `Capabilities::max_payload` — callers take the minimum of the two.
    pub max_payload_bytes: u64,
    pub allow_images: bool,
    pub allow_video: bool,
    /// Hint: compress the body on egress (Phase 1: flag only).
    pub compress: bool,
    /// Hint for future telemetry aggregation (Phase 1: flag only).
    pub batch_telemetry: bool,
}

/// 16 MiB — mirrors the daemon's existing `MAX_FRAME` cap. Used as the
/// `TerrestrialInternet` transport cap specifically so that classifying a
/// plugin's link as terrestrial internet (the default for every protocol
/// this cycle doesn't special-case) can never newly constrain a route that
/// today has no transport-level cap at all: the transport policy composes
/// via `min()` with the plugin's own cap, so this value must be at least as
/// large as anything the daemon already enforces.
const TERRESTRIAL_MAX_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024;

impl TransportPolicy {
    /// Derives the default policy for a class from its characteristics.
    /// Per-class `max_payload_bytes` are example values chosen to be
    /// representative of the class, not protocol mandates — a real
    /// deployment can override them via config (Phase 1 §2):
    ///
    /// | class                | max_payload_bytes | rationale                              |
    /// |-----------------------|-------------------|-----------------------------------------|
    /// | `SatelliteInternet`   | 32 * 1024 (32 KiB)| constrained IP, small messages         |
    /// | `Meshtastic`          | 237                | Meshtastic's own advertised max payload |
    /// | `MeshCore`            | 237                | matches Meshtastic-class LoRa framing   |
    /// | `Reticulum`           | 32 * 1024 (32 KiB)| LXMF/RNS packet-size ballpark           |
    /// | `TerrestrialInternet` | 16 MiB (`MAX_FRAME`) | backward-compat anchor, see below    |
    /// | `Bluetooth`           | 65536 (64 KiB)     | BLE GATT-ish practical ceiling          |
    /// | `LocalNetwork`        | 16 MiB (`MAX_FRAME`) | effectively unconstrained on a LAN   |
    ///
    /// `TerrestrialInternet` MUST derive a non-constraining policy
    /// (`max_payload_bytes >= MAX_FRAME`, images and video allowed): every
    /// plugin defaults to this class absent config (a later task), so this
    /// is the guarantee that today's internet routes are unaffected by
    /// introducing transport classes at all.
    pub fn for_class(class: TransportClass) -> TransportPolicy {
        let c = class.characteristics();
        let very_low = matches!(c.bandwidth, Bandwidth::VeryLow);

        let max_payload_bytes = match class {
            TransportClass::SatelliteInternet => 32 * 1024,
            TransportClass::Meshtastic => 237,
            TransportClass::MeshCore => 237,
            TransportClass::Reticulum => 32 * 1024,
            TransportClass::TerrestrialInternet => TERRESTRIAL_MAX_PAYLOAD_BYTES,
            TransportClass::Bluetooth => 65536,
            TransportClass::LocalNetwork => TERRESTRIAL_MAX_PAYLOAD_BYTES,
        };

        TransportPolicy {
            max_payload_bytes,
            allow_images: !very_low,
            allow_video: !very_low,
            compress: c.metered || very_low,
            batch_telemetry: c.intermittent || very_low,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn characteristics_table_matches_spec_per_class() {
        let cases = [
            (
                TransportClass::SatelliteInternet,
                TransportCharacteristics {
                    bandwidth: Bandwidth::VeryLow,
                    latency: Latency::High,
                    intermittent: true,
                    metered: true,
                    store_and_forward: true,
                },
            ),
            (
                TransportClass::Meshtastic,
                TransportCharacteristics {
                    bandwidth: Bandwidth::VeryLow,
                    latency: Latency::High,
                    intermittent: true,
                    metered: false,
                    store_and_forward: true,
                },
            ),
            (
                TransportClass::MeshCore,
                TransportCharacteristics {
                    bandwidth: Bandwidth::VeryLow,
                    latency: Latency::High,
                    intermittent: true,
                    metered: false,
                    store_and_forward: true,
                },
            ),
            (
                TransportClass::Reticulum,
                TransportCharacteristics {
                    bandwidth: Bandwidth::Low,
                    latency: Latency::High,
                    intermittent: true,
                    metered: false,
                    store_and_forward: true,
                },
            ),
            (
                TransportClass::TerrestrialInternet,
                TransportCharacteristics {
                    bandwidth: Bandwidth::High,
                    latency: Latency::Low,
                    intermittent: false,
                    metered: false,
                    store_and_forward: true,
                },
            ),
            (
                TransportClass::Bluetooth,
                TransportCharacteristics {
                    bandwidth: Bandwidth::Medium,
                    latency: Latency::Low,
                    intermittent: true,
                    metered: false,
                    store_and_forward: true,
                },
            ),
            (
                TransportClass::LocalNetwork,
                TransportCharacteristics {
                    bandwidth: Bandwidth::Medium,
                    latency: Latency::Low,
                    intermittent: false,
                    metered: false,
                    store_and_forward: true,
                },
            ),
        ];

        for (class, expected) in cases {
            assert_eq!(class.characteristics(), expected, "characteristics mismatch for {class:?}");
        }
    }

    #[test]
    fn for_class_derives_expected_policy_per_class() {
        let cases = [
            (
                TransportClass::SatelliteInternet,
                TransportPolicy {
                    max_payload_bytes: 32 * 1024,
                    allow_images: false,
                    allow_video: false,
                    compress: true,
                    batch_telemetry: true,
                },
            ),
            (
                TransportClass::Meshtastic,
                TransportPolicy {
                    max_payload_bytes: 237,
                    allow_images: false,
                    allow_video: false,
                    compress: true,
                    batch_telemetry: true,
                },
            ),
            (
                TransportClass::MeshCore,
                TransportPolicy {
                    max_payload_bytes: 237,
                    allow_images: false,
                    allow_video: false,
                    compress: true,
                    batch_telemetry: true,
                },
            ),
            (
                TransportClass::Reticulum,
                TransportPolicy {
                    max_payload_bytes: 32 * 1024,
                    allow_images: true,
                    allow_video: true,
                    compress: false,
                    batch_telemetry: true,
                },
            ),
            (
                TransportClass::TerrestrialInternet,
                TransportPolicy {
                    max_payload_bytes: 16 * 1024 * 1024,
                    allow_images: true,
                    allow_video: true,
                    compress: false,
                    batch_telemetry: false,
                },
            ),
            (
                TransportClass::Bluetooth,
                TransportPolicy {
                    max_payload_bytes: 65536,
                    allow_images: true,
                    allow_video: true,
                    compress: false,
                    batch_telemetry: true,
                },
            ),
            (
                TransportClass::LocalNetwork,
                TransportPolicy {
                    max_payload_bytes: 16 * 1024 * 1024,
                    allow_images: true,
                    allow_video: true,
                    compress: false,
                    batch_telemetry: false,
                },
            ),
        ];

        for (class, expected) in cases {
            let got = TransportPolicy::for_class(class);
            assert_eq!(got, expected, "policy mismatch for {class:?}");
        }
    }

    #[test]
    fn terrestrial_internet_policy_is_the_non_constraining_backward_compat_anchor() {
        // Every plugin defaults to TerrestrialInternet absent config (a
        // later task), so this class's derived policy must not constrain
        // anything today's daemon doesn't already constrain: the cap must
        // be at least MAX_FRAME (16 MiB) and both media kinds allowed.
        let policy = TransportPolicy::for_class(TransportClass::TerrestrialInternet);
        assert!(policy.max_payload_bytes >= 16 * 1024 * 1024);
        assert!(policy.allow_images);
        assert!(policy.allow_video);
    }

    #[test]
    fn very_low_bandwidth_classes_disallow_media() {
        for class in [
            TransportClass::SatelliteInternet,
            TransportClass::Meshtastic,
            TransportClass::MeshCore,
        ] {
            let policy = TransportPolicy::for_class(class);
            assert!(!policy.allow_images, "{class:?} should disallow images");
            assert!(!policy.allow_video, "{class:?} should disallow video");
        }
    }

    #[test]
    fn non_very_low_bandwidth_classes_allow_media() {
        for class in [
            TransportClass::Reticulum,
            TransportClass::TerrestrialInternet,
            TransportClass::Bluetooth,
            TransportClass::LocalNetwork,
        ] {
            let policy = TransportPolicy::for_class(class);
            assert!(policy.allow_images, "{class:?} should allow images");
            assert!(policy.allow_video, "{class:?} should allow video");
        }
    }

    #[test]
    fn transport_class_deserializes_snake_case_names() {
        let cases = [
            ("\"terrestrial_internet\"", TransportClass::TerrestrialInternet),
            ("\"satellite_internet\"", TransportClass::SatelliteInternet),
            ("\"reticulum\"", TransportClass::Reticulum),
            ("\"meshtastic\"", TransportClass::Meshtastic),
            ("\"mesh_core\"", TransportClass::MeshCore),
            ("\"bluetooth\"", TransportClass::Bluetooth),
            ("\"local_network\"", TransportClass::LocalNetwork),
        ];
        for (json, expected) in cases {
            let got: TransportClass = serde_json::from_str(json).unwrap();
            assert_eq!(got, expected, "deserialize mismatch for {json}");
        }
    }

    #[test]
    fn transport_class_deserialize_rejects_unknown_class() {
        let err = serde_json::from_str::<TransportClass>("\"warp_drive\"").unwrap_err();
        assert!(
            err.to_string().contains("unknown variant"),
            "expected a clear unknown-variant error, got: {err}"
        );
    }

    #[test]
    fn transport_class_from_str_parses_and_rejects_unknown() {
        for (s, expected) in [
            ("terrestrial_internet", TransportClass::TerrestrialInternet),
            ("satellite_internet", TransportClass::SatelliteInternet),
            ("reticulum", TransportClass::Reticulum),
            ("meshtastic", TransportClass::Meshtastic),
            ("mesh_core", TransportClass::MeshCore),
            ("bluetooth", TransportClass::Bluetooth),
            ("local_network", TransportClass::LocalNetwork),
        ] {
            assert_eq!(s.parse::<TransportClass>().unwrap(), expected);
        }

        let err = "warp_drive".parse::<TransportClass>().unwrap_err();
        assert!(err.contains("warp_drive"), "error should name the bad input, got: {err}");
    }

    #[test]
    fn transport_class_display_round_trips_through_from_str() {
        for class in [
            TransportClass::TerrestrialInternet,
            TransportClass::SatelliteInternet,
            TransportClass::Reticulum,
            TransportClass::Meshtastic,
            TransportClass::MeshCore,
            TransportClass::Bluetooth,
            TransportClass::LocalNetwork,
        ] {
            let s = class.to_string();
            assert_eq!(s.parse::<TransportClass>().unwrap(), class);
        }
    }
}
