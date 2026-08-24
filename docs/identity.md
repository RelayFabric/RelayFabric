# Identity & Privacy

RelayFabric routes messages between networks that each have their own,
incompatible notion of "who someone is": a Signal UUID, an LXMF hash, a
Meshtastic node ID, a Nostr `npub`. RelayFabric never assumes these refer to
the same person. Cross-network identity is optional, opt-in functionality
layered on top of routing, not a prerequisite for it: the guiding rule is
*route messages, not identities* (see [The privacy rule](#the-privacy-rule)
below). This page covers the native identity model, the three sender
presentation modes, route-scoped pseudonyms, and the identity linking /
unlinking flow.

## Native identities

Every native protocol identity is treated independently. RelayFabric never
auto-resolves two native identifiers to a common human identity. That only
happens through explicit [identity linking](#linking-identities).

```text
signal:uuid:...
lxmf:82ad...
meshtastic:!ab12cd34
meshcore:key:...
bitchat:key:...
nostr:npub...
```

A user with accounts on Signal, Reticulum/LXMF, and Nostr is, by default,
three unrelated identities to RelayFabric, even if all three routes
terminate at the same gateway.

## Three privacy modes

RelayFabric supports three sender presentation modes, configured per route
(see [Routing & Policy](routing.md) for where `identity_mode` lives in a
route definition). They differ in what a **destination-side recipient**
sees, not in what the gateway operator sees, which is a separate question
addressed under [route-scoped pseudonyms](#route-scoped-pseudonyms) below.

| Mode | Destination sees | Stable across | Linkable across routes | Requires |
|---|---|---|---|---|
| **Anonymous** | No identifier at all | Nothing, not even within one route | No | Nothing |
| **Pseudonymous** (default) | A route-local HMAC tag | The configured privacy scope (typically one route) | No, by construction | Nothing (automatic) |
| **Linked** | A human-readable display name | Until explicitly unlinked | Yes, that's the point | Opt-in verification and/or admin policy |

### Anonymous

```text
[Meshtastic User]
Hello
```

No stable identifier crosses the route at all. Two messages from the same
sender are not distinguishable to the recipient as coming from the same
person.

### Pseudonymous

The default, recommended mode. The destination sees a stable-looking tag
instead of a real identifier:

```text
[MESH-7F21]
Hello
```

The pseudonym is stable **only within its configured privacy scope**. See
[Route-Scoped Pseudonyms](#route-scoped-pseudonyms). It is not a persistent,
portable handle; it's a per-scope alias.

### Linked

After an explicit identity link has been established and verified:

```text
[Jascha]
Hello
```

Linked mode MUST require explicit administrator policy and/or end-user
verification. It is never a default, and it is never inferred from traffic
patterns. See [Linking identities](#linking-identities).

!!! warning "Mode choice is a routing decision, not a security boundary"
    These three modes govern what a *destination recipient* sees in the
    rendered message. They say nothing about what the *gateway operator*
    can see. The gateway processes the native identity on every mode,
    including Anonymous. For confidentiality against the gateway itself,
    see [Security & Sealed Routing](security.md).

## Route-scoped pseudonyms

Pseudonymous mode generates a per-scope alias with an HMAC rather than
assigning a persistent user ID:

```text
alias =
HMAC(
    gateway_secret,
    native_identity || privacy_scope
)
```

Because the `privacy_scope` is part of the HMAC input, the same underlying
native identity produces a *different* alias in each scope:

```text
Meshtastic !abcd1234

Signal route A:
MESH-7F21

Matrix route B:
MESH-C82A

Nostr route C:
MESH-19EE
```

An observer on Signal route A and an observer on Nostr route C cannot
trivially correlate `MESH-7F21` and `MESH-19EE` as the same person. The
aliases share no visible structure. Within a single scope, the alias stays
stable, so a recipient can still recognize "the same sender" across repeated
messages without learning who that sender is.

!!! danger "What this does (and does not) hide"
    Route-scoped pseudonymity is **unlinkability across routes for
    destination-side observers who only see the alias.** It is *not*:

    - **Anonymity from the gateway operator.** The gateway computes every
      alias from the real native identity and the shared `gateway_secret`.
      It necessarily knows the mapping for every message it routes. A
      malicious or compromised gateway operator can correlate identities
      across routes trivially, because it holds the one input (the native
      identity) that's constant across all of them. This is explicitly
      called out in the spec's threat model as something route-scoped
      pseudonyms mitigate the *exposure* of, not eliminate: the mitigation
      is that recipients and other networks don't get the correlation, not
      that no one does.
    - **Traffic-analysis resistance.** Timing, message size, and the fact
      that a gateway is involved at all remain observable regardless of
      alias scheme.
    - **A cryptographic identity binding.** The alias is a keyed derivation
      for unlinkability, not a signature. See
      [Security & Sealed Routing](security.md) for provenance guarantees
      (SIGNED mode) and payload confidentiality (SEALED mode), which are
      orthogonal to, and can be combined with, any of the three privacy
      modes here.

    If a route's `gateway_secret` is rotated, every alias derived from it
    changes too. Recipients will see a "new" pseudonym for a sender they
    previously recognized. That's an operational consequence to plan
    around, not a bug.

## Linking identities

Identity linking is how a user opts into having two native identities
recognized as the same person: for example, so a Reticulum contact and a
Signal contact both render as `[Jascha]` instead of two unrelated
pseudonyms.

Linking MUST be opt-in. It starts with an explicit request naming the
target network and account:

```text
/link signal alice.42
```

RelayFabric then sends a verification challenge **directly** to the target
account: a one-shot, out-of-band message delivered straight to that native
identity, independent of any configured route or channel mapping. This
requires the target plugin to advertise the `direct_messages` capability
(see the capability model); a plugin that can't address an arbitrary native
ref outside a route simply can't be a linking target.

```text
Verification code: 391847
```

The user confirms possession of the target account by returning that code
through the expected channel. Only after that confirmation does RelayFabric
store the association:

```text
mesh:!abcd
       ↕
signal:uuid...
```

From that point on, messages from either identity render under the linked
display name rather than a pseudonym, wherever linked rendering is enabled
for the route.

**Challenge lifecycle.** A challenge is issued in a pending state tied to
one specific link request; it carries an expiry, after which it can no
longer be confirmed and the request must be restarted. The verification
code itself is treated as a secret in transit and at rest. It is delivered
only over the direct, one-shot channel to the target account, never
re-displayed or logged in the clear afterward.

!!! warning "Linking is the one mode that requires trust and consent"
    Anonymous and pseudonymous modes never require anything from the user.
    Linked mode is the exception: it MUST require explicit administrator
    policy and/or end-user verification before it takes effect, precisely
    because it is the mode that intentionally *reduces* privacy in exchange
    for a recognizable identity.

## Unlinking

Users or administrators SHOULD be able to remove a previously established
link:

```text
/unlink signal
```

Unlinking reverts the affected identity back to whatever mode the route
would otherwise use (typically pseudonymous). Future messages stop
rendering under the linked display name. Where administratively permitted,
unlinking SHOULD also support deletion of the underlying correlation data,
not just its display.

Unlinking also **voids any outstanding challenge** tied to that
relationship: a verification code issued for a link that has since been
removed cannot be replayed to reinstate it. A stale code found later (in a
log, a screen, a message history) is not a live credential.

## The privacy rule

A central RelayFabric principle:

> Route messages, not identities.

Every message can be routed correctly (matched, transformed, delivered)
without any identity resolution beyond the native identifier it arrived
with. Cross-network identity federation (linking) is optional functionality
layered on top of that baseline, never a requirement for routing to work.
This is also why anonymous and pseudonymous modes need zero configuration
or user action: they fall directly out of *not* linking anything, which is
the default state of the system.

## Where this fits

- [Routing & Policy](routing.md): where `identity_mode` is set per route,
  and how policy can gate which routes are even eligible for linking.
- [Security & Sealed Routing](security.md): TRANSLATE / SIGNED / SEALED
  content-security modes, which control what the *gateway* can see and are
  independent of which privacy mode governs what the *recipient* sees.
