//! Federation core (design doc §1-5, cycle F): switchyardd-to-switchyardd
//! links secured with Noise and bound to Ed25519 node identities, signed
//! canonical envelopes with an attestation chain, and the CBOR wire frames
//! exchanged over a link once its handshake completes. This module provides
//! the link layer (`noise`), the signing layer (`sign`), the frame layer
//! (`wire`), and the connection manager (`conn` — handshake lifecycle,
//! listener/outbound tasks, ping/dead-timer, ack resolution); the trust
//! store lives in `storage.rs` and federation policy config in `config.rs`
//! (both cross-cutting, so they aren't under `fed/`). Verified-ingress
//! dispatch (`fed_ingress`) lives in `engine.rs`, alongside the plugin
//! ingress path it shares a fan-out helper with.
//!
//! RFDP discovery (design doc, cycle G, SPEC §111): `advert` defines the
//! signed Node Advertisement document and builds one from `Config` at
//! load time (SPEC §111.4 privacy sourcing rule). Exchange over live fed
//! connections (`Advert`/`AdvertReq` wire frames, refresh timer, receive-
//! path verification) and storage are later cycle-G tasks.
//!
//! Sealed routing (design doc, cycle H, SPEC §113): `sealkey` defines the
//! per-node stable X25519 keypair a sealed-routing origin encrypts to
//! (SPEC §113.3 "keys anchor to §112.6 node identities"), published via
//! `advert::SecurityCaps::sealed_key`. The AEAD envelope format itself
//! (`seal`/`unseal`) is a later cycle-H task.

pub mod advert;
pub mod conn;
pub mod domains;
pub mod noise;
pub mod sealkey;
pub mod sign;
pub mod wire;

/// A federation node_id's first 8 hex chars (after its `"rf:"` prefix),
/// e.g. `"rf:ab12cd34..."` -> `"ab12cd34"`. Shared by `engine::fed_ingress`
/// (the `("fed", "<node_id first 8 hex>:<native_ref>")` per-sender limiter
/// key, and the synthetic `fed:<short>` dead_letter destination) and
/// `fed::conn` (`Event::Federation`/the `relayfabric_federation_peer_up`
/// metric label for an unconfigured/inbound-only connection — events.rs
/// privacy convention: no full node_id in a broadcast/metric surface, see
/// `fed::conn::display_peer_key`).
pub(crate) fn short_node_id(node_id: &str) -> String {
    node_id.trim_start_matches("rf:").chars().take(8).collect()
}
