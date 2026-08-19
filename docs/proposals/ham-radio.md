# Proposal: Licensed Amateur Radio Support

**Status:** roadmapped 2026-08-19 — items 1–3 slotted for v0.5, 4–6 beyond ·
**Scope:** compliance-gated capability for licensed operators

Licensed operators unlock what unlicensed mesh cannot: HF that crosses
continents, VHF/UHF at real power, real antennas. The constraint is a
regulatory inversion of RelayFabric's defaults — on amateur bands (US
Part 97 and equivalents) **encryption that obscures meaning is prohibited,
station identification is mandatory, and pseudonymity is effectively
illegal**. Ham support therefore means the fabric actively flips its own
posture at the RF edge, structurally, while the internet/federation legs
stay Noise-encrypted.

RelayFabric cannot verify a license: "licensed features" are
compliance-gated features behind an operator-declared callsign, with the
daemon enforcing the rules that make that declaration true on the air.

## v0.5

1. **`licensed_ham` transport class with compliance-enforcing policy.**
   The Phase-1 transport-class machinery is the seam: a class whose policy
   *refuses sealed/encrypted egress* (the mirror image of
   `SECURITY_DOWNGRADE_REFUSED` — the daemon refuses to put ciphertext on
   the air), caps payloads for narrowband links, and injects automatic
   station ID (callsign per transmission and on a 10-minute timer,
   §97.119). The plaintext/identified boundary is structural, not operator
   discipline.
2. **Callsign identity mode.** Route-level `identity_mode: callsign`
   rendering the operator's callsign instead of HMAC pseudonyms — required
   for legality, per-route so a ham egress never strips pseudonymity from
   non-ham routes. Optional callsign-format/ULS validation at config load.
3. **APRS plugin.** Callsign-addressed messaging + position beacons via a
   KISS TNC over TCP (Direwolf as an external process, like signal-cli —
   GPL stays outside the process boundary) or APRS-IS for the internet
   side. APRS positions can also feed the PotatoMesh plugin. Named as a
   gateway target by SPEC §112.1.

## Beyond v0.5

4. **Winlink bridge** via Pat (MIT, HTTP API — license-clean): email over
   HF, continent-scale delay-tolerant delivery.
5. **JS8Call plugin** (TCP API): HF keyboard chat with native
   store-and-forward.
6. **Meshtastic licensed-mode support**: `ham: true` plugin config pairing
   with the firmware's ham mode (plaintext channel asserted, callsign node
   ID), composed with the callsign identity mode.

Plus, costing little once 1–3 exist: an **EmComm deployment profile**
(the existing emergency-first airtime ladder + store-and-forward,
documented for ARES/RACES-style use).

## Non-starters

- **Reticulum/LXMF on amateur bands (US):** RNS is encrypted by
  construction with no plaintext mode — not Part 97-legal. The ham story
  runs on APRS/Winlink/JS8/M17-class protocols.
- Anything that would put sealed routing on RF: the whole point of the
  `licensed_ham` class is that the daemon makes this impossible, not
  discouraged.
