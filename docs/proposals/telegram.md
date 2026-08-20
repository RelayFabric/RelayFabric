# Proposal: Telegram Plugin

**Status:** proposed, backlog (v0.6+ at the earliest, behind
[SimpleX](simplex.md) in the messenger tier) · **Date:** 2026-08-20

## Posture first: this is a PLAINTEXT-PLATFORM bridge

Telegram cloud chats are server-side plaintext by design, identity is
phone-number-anchored, and the platform is centralized. The Bot API — the
only sane integration surface — cannot reach Telegram's E2E "secret
chats" at all. So unlike Signal/SimpleX there is no E2EE-BRIDGED nuance:
**every bridged message is readable by Telegram**, and the docs/UI must
label the capability exactly that bluntly. This plugin never appears in
the default or getting-started configuration.

## Why bridge it anyway

Reach, and the fact that the mismatch is where RelayFabric's identity
machinery earns its keep: mesh/LoRa users reach the Telegram communities
where real-world coordination happens through **route-scoped pseudonyms**,
behind deny-by-default routing, with no cross-network identity graph —
strictly better for them than installing Telegram. Policy-controlled
interop with a hostile platform is still policy-controlled interop.

## Integration shape: the cheapest plugin in the fleet

Bot API over plain HTTPS (long-polling `getUpdates` / `sendMessage`), no
sidecar process, no restrictive-license exposure (it is an API; the plugin
uses stdlib HTTP like potatomesh). Fleet-convention Python module:
`channels` map to chat ids, `capped_text_send` egress, attachments via
`sendDocument`/`getFile` onto the CAS model, bot token via `${env:}`.
Effort class: potatomesh, not signal.

## Constraints

- Bot-visible messages only (bots see group messages per Telegram's
  privacy-mode settings; the README documents the required bot setup).
- Rate limits (~30 msg/s per bot, 20 msg/min per group) — the existing
  transport_budgets machinery is the natural fit.
- Positioning guard: this exists for reach, not identity. If it ever
  crowds the off-grid/privacy story in docs or defaults, it is mis-shelved.
