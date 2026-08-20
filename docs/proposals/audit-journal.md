# Proposal: Tamper-Evident Operational Audit Journal

**Status:** proposed, public-node hardening (v0.5+) · **Scope:** a native
RelayFabric feature, informed by Symbiont's design, not a dependency on it ·
**Date:** 2026-08-20

## Problem

RelayFabric has strong **content** privacy — default logs carry
operational metadata (message id, route, source protocol) and never
message bodies, asserted by privacy tests even with linked identities.
What it lacks is a tamper-evident record of **operational decisions**: a
public federation node cannot prove, after the fact, that it routed within
policy — accepted the peers it should have, applied the quotas it
advertised, refused the sealed downgrades it claims to refuse — without an
audit trail that a compromised or dishonest operator cannot silently
rewrite.

Ordinary logs don't answer this: a node operator with disk access can edit
them. For a node other communities are asked to *federate with*, "trust me,
the logs are accurate" is exactly the assurance an audit journal exists to
replace.

## Design: a hash-chained, signed decision journal

The pattern is proven in [Symbiont](https://github.com/ThirdKeyAI/Symbiont)'s
`BufferedJournal` (hash-chained, Ed25519-signed) — adopt the *design*, not
the code:

- **Append-only, hash-chained.** Each entry carries `prev_hash =
  H(previous entry)`, so removing or altering any entry breaks the chain
  from that point forward — detectable by anyone who has seen a later
  hash.
- **Signed with the node identity.** Entries (or periodic checkpoints) are
  signed with the existing Ed25519 node identity (`identity/node.key`), so
  the chain is bound to the `rf:` node that produced it and cannot be
  forged by a third party.
- **Decisions, never content.** The journal records *what the daemon
  decided and why*, never message bodies — it must not become a privacy
  regression. Entry kinds: federation accept/reject (with reason:
  TRUST_DENIED, ROUTE_NOT_FEDERATED, sealed downgrade refused, …), quota
  enforcement (rate-limited / budget-dropped), config apply (which
  revision, restart-required set), trust-level changes, plugin
  connect/disconnect. These are the same `metrics::*` decision points that
  already exist — the journal is a durable, ordered, signed record of
  them.
- **Verifiable offline.** A `switchyardctl audit verify` walks the chain,
  checks every `prev_hash` link and the signatures, and reports the first
  break. A peer can be handed a checkpoint hash out-of-band and later
  confirm the node's journal still descends from it.

## Why native, not via the Symbiont plugin

The audit need is RelayFabric's own — it exists whether or not any agent
plugin is present, and it must cover the daemon's routing/federation
decisions, which live in `switchyardd`, not in a plugin. Symbiont's
journal governs *agent tool calls*; this one governs *routing decisions*.
Same cryptographic shape, different subject. Borrowing the pattern keeps
RelayFabric's permissive-only, few-dependencies posture intact (the
primitives — Ed25519, SHA-256 — are already in the tree).

## Scope discipline

- **Content stays out.** The journal is decisions and reasons; a body or a
  sender's native_ref never enters it. Pseudonymized route/short-node-id
  identifiers only, consistent with today's logging invariant.
- **Bounded on disk.** Rotating segments with a retained checkpoint chain
  (the checkpoint hashes preserve verifiability across rotation); size
  capped like the CAS budget, not unbounded.
- **Off by default, on for public nodes.** A private single-operator node
  doesn't need it; `node.public: true` is where it earns its cost, and a
  future public-node preset can default it on (pairs with the
  already-hardened "public node must configure quotas" rule).

## Relationship to other proposals

- Pairs with the **public federation** work ([v0.4 roadmap](v0.4-roadmap.md)
  cycle G): the journal is what lets a public node *prove* it behaved,
  turning "trust the operator" into "verify the chain."
- Shares the Symbiont-journal *design* referenced by the
  [Symbiont agent plugin](symbiont-agent-plugin.md) proposal, but is
  independent of it — either can ship without the other.
