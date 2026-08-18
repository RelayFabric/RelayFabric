# RelayFabric Manifesto

*by Jascha Wanger · 2026-08-17*

RelayFabric exists because communications networks should be able to interoperate without demanding that users surrender privacy, autonomy, or control.

The world does not need one winning mesh, one messaging platform, or one communications protocol. Reticulum, MeshCore, Meshtastic, Signal, Bitchat, Nostr, radio networks, and systems that have not yet been invented should be able to coexist.

RelayFabric is infrastructure for connecting them.

## Networks should remain independent

Interoperability should not require consolidation.

RelayFabric does not seek to replace the networks it connects. Each protocol should retain its own routing, identities, security model, community, and operational independence.

The fabric connects networks without requiring them to become the same network.

## Route messages, not identities

Interoperability must not quietly become surveillance.

A person using a pseudonymous radio identity should not automatically become correlated with their Signal account, phone number, email address, or identities on other networks.

RelayFabric therefore treats identities as protocol-local by default.

Cross-network identity association must be explicit, voluntary, and removable.

Where possible, RelayFabric should use anonymous or route-scoped pseudonymous identities rather than expose native identifiers.

## Privacy is architecture

Privacy cannot be added after the routing layer has already collected everything.

RelayFabric should minimize:

* identity correlation
* metadata collection
* message retention
* location disclosure
* logging of content
* unnecessary native identifiers

A gateway should know only what it needs to perform its function.

Operators and users should be able to understand exactly where encryption terminates and when a gateway can access plaintext.

When protocol translation requires a trusted gateway, RelayFabric should say so plainly.

Where stronger guarantees are possible, RelayFabric should support signatures, encrypted envelopes, and end-to-end modes that reduce the trust placed in intermediaries.

## Decentralization means anyone can participate

RelayFabric must not depend on RelayFabric, Inc., a mandatory cloud service, a central broker, a global account database, or a privileged directory.

Anyone should be able to run `switchyardd`.

A Raspberry Pi connected to a few radios should be as legitimate a RelayFabric node as a regional communications backbone.

Nodes should be able to discover, federate, route, disconnect, reconnect, and continue operating locally without permission from a central authority.

## Failure is normal

Networks disappear.

Internet connections fail. Towers lose power. Radio links fade. Devices move. Communities become partitioned.

RelayFabric should be designed for those conditions rather than treating them as exceptions.

Store-and-forward, delayed delivery, multiple transports, graceful degradation, and local operation are fundamental features.

## Protocols are tools, not tribes

No transport is universally best.

LoRa trades bandwidth for range and resilience. Internet messaging offers convenience and reach. Reticulum provides flexible heterogeneous networking. BLE enables proximity communication. Nostr provides decentralized Internet transport.

RelayFabric should choose paths according to capabilities and policy rather than ideology.

The purpose of the fabric is to let these systems complement one another.

## Open means usable

RelayFabric should be genuinely open source and easy to build upon.

We favor permissive licenses such as **Apache-2.0, MIT, and BSD-style licenses** because interoperability infrastructure becomes more valuable when it can be embedded, extended, forked, studied, deployed, and incorporated broadly.

We are skeptical of restrictive copyleft licenses, including the **AGPL**, for foundational interoperability infrastructure.

A license should encourage participation rather than dictate how unrelated systems surrounding the software must be distributed.

RelayFabric should earn adoption through usefulness, security, and openness rather than through licensing leverage.

Open protocols matter as much as open code.

The wire formats, plugin interfaces, discovery protocol, federation mechanisms, and message envelopes should be documented so that independent implementations can exist.

No implementation should own the fabric.

## Security should survive the gateway

Gateways are powerful.

A protocol-translating gateway may be able to read, modify, suppress, replay, or correlate communications.

RelayFabric should design around that reality.

Messages should preserve provenance where possible. Signatures should make undetected modification harder. Sensitive identity mappings should be minimized. Plugins should be isolated. Administrative interfaces should be strongly protected.

Trust should be explicit, scoped, and reducible.

## The fabric should remain extensible

Today's important networks will not be tomorrow's complete list.

RelayFabric should have a small, stable core and a pluggable edge.

```text
Signal
Reticulum
MeshCore
Meshtastic
Bitchat
Nostr
MQTT
APRS
Matrix
future protocols
        │
        ▼
   RelayFabric
        │
        ▼
   switchyardd
```

Adding a protocol should not require redesigning the system.

## Our objective

RelayFabric is not an attempt to create another communications silo.

It is an attempt to make silos less important.

We want independent networks to communicate while preserving their autonomy. We want people to move information across radio, local mesh, decentralized infrastructure, and the Internet without requiring one company, one protocol, or one identity system to control the path.

**Connect networks. Preserve boundaries. Minimize trust. Protect identity. Keep the fabric open.**
