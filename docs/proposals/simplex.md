# Proposal: SimpleX Chat Plugin

**Status:** proposed, v0.6+ (protocols frozen for v0.4; v0.5 is committed
to the client arc + ham radio) · **Date:** 2026-08-20 · Facts verified
against simplex-chat/simplex-chat on the date above.

## Why SimpleX fits RelayFabric

[SimpleX](https://simplex.chat/) is the strongest *philosophical* match of
any bridged protocol yet: no user identifiers of any kind (pairwise
per-queue identifiers), double-ratchet E2EE with post-quantum key
exchange on every ratchet step, and a metadata-resistance posture that
targets exactly the audience the RelayFabric Manifesto addresses. A node
that bridges Reticulum/LoRa communities to SimpleX contacts and groups
serves users no other bridge reaches.

## Integration shape: the signal-cli precedent, exactly

The `simplex-chat` terminal client (Haskell, single binary) exposes a
WebSocket JSON API for bots, with an official TypeScript SDK documenting
the surface. The plugin is therefore the established sidecar pattern:

- operator runs an unmodified upstream `simplex-chat` CLI (its own systemd
  unit in the cycle-B hardening pattern);
- a Python plugin in the fleet convention speaks the WebSocket API —
  connect, map contacts/groups to channels, `capped_text_send` egress,
  XFTP files onto the existing attachment/CAS model;
- the gateway is simply a SimpleX *contact/group member* on the native
  side, consistent with every other plugin.

**Licensing:** simplex-chat is AGPL-3.0. Policy treats this exactly like
signal-cli (GPL-3.0): run unmodified, out-of-process, spoken to over its
own API — no linking, no code reuse, nothing derived. The AGPL network
clause binds the SimpleX software itself, which the operator runs
unmodified (source = upstream). Nothing AGPL enters the RelayFabric tree
or dependency graph; `cargo-deny`/`pip-audit` surfaces stay clean.

## The honesty requirement (non-negotiable)

SimpleX users are the most privacy-sensitive population any plugin
touches, and a bridge is necessarily an encryption endpoint: the gateway
terminates the double ratchet before re-encrypting toward Signal/LXMF/
anything else. Same truth as Signal (§113.3 — delivering to a plaintext
plugin IS gateway decryption), but the cultural stakes are higher here:

- every bridged SimpleX conversation is labeled **E2EE-BRIDGED**, never
  represented as end-to-end;
- the gateway's SimpleX profile must identify itself as a bridge;
- route-scoped pseudonyms apply on egress as with every protocol — no
  cross-network identity graph is constructed.

## Cautions

- The bot/WebSocket API evolves with SimpleX's fast release cadence —
  pin a tested CLI version per RelayFabric release, like signal-cli.
- Haskell runtime footprint is fine on 1 GB nodes; verify on 512 MB
  before recommending for `t4g.nano`-class deployments.
- Group semantics are client-side (pairwise fan-out) — group bridging
  works via bot membership, but large groups multiply queue traffic.
