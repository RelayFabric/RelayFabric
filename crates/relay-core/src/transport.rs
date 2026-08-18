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

/// Effective egress rules for a transport class. Config (`transports:`)
/// can override individual fields on top of these defaults.
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
    /// The built-in default policy per class. Per-class `max_payload_bytes` are example values chosen to be
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
        // Values per class are locked by for_class_derives_expected_policy_
        // per_class below; the very-low-bandwidth LoRa/satellite classes
        // disallow media and want compression/batching.
        let policy = |max_payload_bytes, media, compress, batch_telemetry| TransportPolicy {
            max_payload_bytes,
            allow_images: media,
            allow_video: media,
            compress,
            batch_telemetry,
        };
        match class {
            TransportClass::SatelliteInternet => policy(32 * 1024, false, true, true),
            TransportClass::Meshtastic => policy(237, false, true, true),
            TransportClass::MeshCore => policy(237, false, true, true),
            TransportClass::Reticulum => policy(32 * 1024, true, false, true),
            TransportClass::TerrestrialInternet => {
                policy(TERRESTRIAL_MAX_PAYLOAD_BYTES, true, false, false)
            }
            TransportClass::Bluetooth => policy(65536, true, false, true),
            TransportClass::LocalNetwork => {
                policy(TERRESTRIAL_MAX_PAYLOAD_BYTES, true, false, false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

}
