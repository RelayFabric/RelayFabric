# Proposal: HAVEN as the Personal Nostr Relay Sidecar

**Status:** proposed, v0.5+ (protocols are frozen for v0.4) · **Scope:**
deliberately scoped down from a larger external plan — a sidecar plus
modest plugin changes, no new abstraction layers · **Date:** 2026-08-19

## What HAVEN is (facts verified 2026-08-19)

[HAVEN](https://github.com/bitvora/haven) — Go, MIT, built on khatru —
serves four logically separate relay surfaces as paths on one port
(default 3355), plus an integrated Blossom media server:

| Surface | Semantics |
|---|---|
| `/private` | owner + allowlisted npubs only, NIP-42 protected — personal storage |
| `/chat` | DMs, NIP-42 + Web-of-Trust filtered |
| `/inbox` | pulls mentions/replies/zaps of the owner from other relays — pre-filtered |
| `/` (outbox) | owner writes, public reads, auto-blasts to configured external relays |

Upstream declares it **feature-complete, maintenance-only**. That is
acceptable for infrastructure (stability is a feature) and MIT permits a
fork if it ever matters; the bus-factor risk is noted, not blocking.

## Why this is mostly configuration, not architecture

RelayFabric's nostr plugin already speaks the relay protocol with
**per-channel relay URLs** — pointing channels at
`ws://127.0.0.1:3355/inbox` and `ws://127.0.0.1:3355` is the bulk of the
integration. The larger plan this proposal descends from called for a
`PersonalNostrRelay` provider trait, an `engine: haven` config concept, and
a six-module adapter tree; all three are declined:

- the swap-HAVEN-later escape hatch a provider trait would exist for is a
  different URL — the abstraction already exists as configuration;
- the daemon stays protocol-neutral — no Nostr concept enters
  `switchyardd`;
- the fleet convention is one plugin module + tests, which has served
  eight protocols.

Likewise "private events must never auto-bridge" is already structural:
RelayFabric is deny-by-default (SPEC §38) — nothing bridges without an
explicit route. The plan's "explicit export rule" *is* a route.

## What actually gets built

1. **NIP-42 client auth in the nostr plugin.** Answer a relay `AUTH`
   challenge with a signed kind-22242 event; the signing primitives
   already live in `relayfabric_sdk.nip01`. Per-relay `auth: required`
   config. This is the one real protocol gap between the plugin and
   HAVEN's protected surfaces (and useful against any NIP-42 relay, not
   just HAVEN).
2. **A loud-accident guard for private surfaces.** New optional channel
   flag `private: true`; a route referencing a private-backed channel
   fails `--check-config` unless the route sets an explicit
   `allow_private_export: true`. Deny-by-default already makes the
   accident impossible; this makes the deliberate act legible.
3. **Sidecar deployment, signal-cli style.** HAVEN is operator-run (it
   has its own config/state lifecycle), with a hardened
   `deploy/systemd/haven.service` in the cycle-B pattern — dedicated
   user, outbound-only network for the inbox/blast function, no path to
   RelayFabric's keys. Not spawned by `switchyardd`.
4. **Docs: the personal-node story.** HAVEN is *single-owner* (one
   npub's private/chat/inbox); the existing plugin bridges shared public
   channels. These compose — a node can do both — but they are different
   modes and the docs must not conflate them.

**Immediate synergy, even before any of the above:** a local HAVEN is a
real relay for closing the interop matrix's "Nostr live-relay validation
pending" cell in livetest — worth wiring into the livetest ladder first.

## Deferred decisions (explicitly not in this proposal)

- **NIP-17/59 DM bridging.** The external plan's two strongest
  recommendations contradict each other: "never hold the user's nsec" and
  "bridge gift-wrapped DMs" are mutually exclusive — unwrapping requires
  NIP-44 *decryption* capability at the gateway, which signature-only
  NIP-46 delegation does not provide. If DM bridging ever ships, the
  honest design is a gateway-held key, labeled **E2EE-BRIDGED** (never
  claimed as end-to-end), gated by the same downgrade-refusal machinery
  as sealed routing (§113.3: delivering to a plaintext plugin IS gateway
  decryption). That is its own proposal with the key-custody question
  answered first, not a rider on this one. (Note the current plugin
  already holds an `identity_file` nsec — the no-custody aspiration is a
  posture change, to be decided, not an existing property.)
- **Blossom media.** Maps naturally onto the attachment/CAS model;
  worthwhile, separate work.
- **Reimplementing HAVEN semantics natively** ("RelayFabric 2.x personal
  relay"): revisit only if HAVEN upstream dies AND the personal-node mode
  has real adoption. Until then the sidecar is the implementation.

## Non-goals

- No Nostr concepts in `switchyardd`; no provider/engine abstraction; no
  plugin module tree restructure.
- No claim, anywhere, that a bridged conversation is end-to-end encrypted
  across protocols.
