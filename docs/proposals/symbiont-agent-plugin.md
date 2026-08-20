# Proposal: Symbiont Agent Plugin — a Governed AI Agent on the Mesh

**Status:** proposed, v0.6+ (behind the committed v0.4 hardening and v0.5
client/ham arcs) · **Scope:** one plugin, out-of-process · **Date:**
2026-08-20

## The idea

[Symbiont](https://github.com/ThirdKeyAI/Symbiont) is a policy-governed AI
agent runtime (Rust, Apache-2.0; OATS reference implementation): Cedar
policy gates, AgentPin ES256 identity, SchemaPin/ToolClad tool
verification, per-agent sandboxing, and hash-chained Ed25519-signed audit
journals. A `symbiont` plugin makes a governed agent an **endpoint on the
fabric**: a message arrives on any bridged network (LoRa, Reticulum,
Signal, …) → routes to the plugin → Symbiont runs an agent under Cedar
policy → the reply routes back out over whatever transport the sender
used.

**Why this is worth doing** — it is the one integration that creates
capability neither project has alone: *a policy-governed AI agent reachable
over off-grid mesh*. When the internet is down, an EmComm operator can
query a governed assistant over LoRa/Reticulum, every tool call recorded in
Symbiont's audit journal and anything out of policy denied by Cedar. Both
projects are Rust + Apache-2.0 by the same author, so there is no license
boundary to manage (unlike the signal-cli / simplex-chat GPL/AGPL
sidecars).

## Shape: Symbiont behind the plugin, over IPC — never linked in

Symbiont runs as its own supervised process; the plugin speaks Plugin
Protocol v1 to `switchyardd` on one side and Symbiont's `ChannelAdapter`
trait (`crates/channel-adapter`, already used for Teams/Mattermost) on the
other. This is deliberate and matches every other heavy/untrusted bridge:

- RelayFabric keeps its crash-isolation and per-plugin sandboxing — a
  runaway agent process can't take the fabric down or reach the daemon's
  keys;
- Symbiont keeps its own runtime, its own Docker/gVisor/Firecracker
  sandboxing, and its own Cedar/audit stack on its side of the boundary;
- to RelayFabric it is just another endpoint: deny-by-default routing
  applies, and **transport-class egress caps apply automatically** — an
  agent reply is capped/media-demoted for a 237-byte LoRa hop exactly like
  any other message.

Two directions achieve the same outcome; pick the cleaner one:

1. **Symbiont-as-adapter (recommended):** RelayFabric ships a thin Python
   plugin (fleet convention) that bridges the fabric to a Symbiont
   `ChannelAdapter` endpoint over its channel API. RelayFabric owns
   nothing of Symbiont's internals.
2. **RelayFabric-as-Symbiont-channel:** a Symbiont-side `ChannelAdapter`
   impl that speaks to `switchyardd`'s admin API / a plugin socket. Lives
   in the Symbiont repo, not here.

Prefer (1): it keeps the integration inside RelayFabric's established
plugin pattern and out of `switchyardd`.

## Honest caveats

- **Inference needs compute.** A cloud-LLM agent can't answer over a
  no-backhaul LoRa link; Symbiont's local-model support is the off-grid
  path. The *governance* value (policy + audit) holds wherever inference
  runs.
- **Two identity layers, composed not merged.** RelayFabric's Ed25519
  node identity attests the transport hop; Symbiont's AgentPin ES256
  attests the agent. Layering them is a feature — do not try to unify
  them.
- **Payload realities.** Long agent replies over constrained transports
  are demoted like any egress; a mesh-facing agent should be prompted for
  terse output (a Symbiont-side policy/config concern, not RelayFabric's).

## Explicitly out of scope

- **No Cedar in RelayFabric.** RelayFabric's deny-by-default routing +
  capabilities is deliberately simple; Cedar governs agent tool calls, a
  different domain. Message routing does not adopt it.
- **No merged identity model, no shared crate (yet).** Neither project has
  extracted a reusable journal/identity crate; forcing one couples two
  independent projects prematurely.
- Symbiont does not absorb RelayFabric or vice versa. They compose over the
  plugin seam and stay independent.

## Separate spin-off (its own proposal): a tamper-evident audit journal

The one Symbiont *pattern* worth borrowing independently — its hash-chained,
Ed25519-signed audit journal — is now its own proposal:
[Tamper-Evident Operational Audit Journal](audit-journal.md). It is a native
RelayFabric public-node feature informed by Symbiont's design, NOT a
dependency on Symbiont, and ships independently of this plugin.
