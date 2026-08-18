# Proposal: Federation over Tor and I2P

**Status:** proposed, v0.2 · **Scope:** bounded — a transport option on the
existing RFDP link, no new wire protocol · **Date:** 2026-08-17

## Problem

Federation peers dial each other over plain TCP at a known `IP:port`
(`fed/conn.rs` `spawn_outbound` → `TcpStream::connect(&peer.addr)`; inbound via
`run_listener` → `TcpListener::bind`). Even with sealed routing — which hides
routing *content* from intermediate nodes — the transport still exposes
metadata to a passive network observer: which nodes peer, when, and how much
traffic flows. Operators behind NAT also can't accept inbound federation
without a public IP and port-forwarding.

Routing an RFDP link through a Tor onion service (or an I2P hidden service)
closes both gaps: peer IPs stay hidden from network observers, and the hidden
service gives inbound reachability with no public IP or forwarded port.

## Scope: the two transport planes

RelayFabric has two independent transport planes, and this proposal touches
only the second:

| Plane | Transport | Where anonymity lives |
|---|---|---|
| **Edge / plugin** (lxmf ↔ NomadNet, Sideband, other RNS apps) | Reticulum, per the plugin's `rns_configdir` `[interfaces]` | **RNS itself** |
| **Federation** (switchyardd ↔ switchyardd, RFDP) | raw TCP + Noise | this proposal |

**LXMF/NomadNet anonymity is not a RelayFabric concern.** Reticulum already
ships a native `I2PInterface` (i2pd/SAM), and its `TCPClientInterface` can be
SOCKS/torsocks-tunnelled. An operator who wants edge traffic over I2P adds an
`I2PInterface` to the lxmf plugin's RNS config — zero RelayFabric change.
NomadNet is an edge *application* on Reticulum, reached through the lxmf plugin
as an LXMF destination; it is never an RFDP federation peer. This proposal is
solely about the federation plane, which does **not** ride Reticulum.

## Non-goals

- No new framing or handshake — RFDP/Noise runs unchanged over the tunnelled
  TCP stream.
- Not a replacement for sealed routing (content) or end-to-end privacy: the
  tunnel hides transport metadata from the *network*, not from the peer you
  federate with.
- Does not anonymize plugin transports that hit third-party servers (Nostr
  relays, MQTT, Signal), nor the RNS edge plane (that's an RNS-config concern,
  above). This proposal covers the RFDP inter-node links only.

## Design (Approach A — SOCKS5 proxy, operator-run tor/i2pd)

Tor and I2P are the *same* code path: both expose a local SOCKS proxy, and
`.onion` and `.b32.i2p` hostnames dial identically through it. Two independent
halves; either can ship alone.

### Outbound — dial peers through a SOCKS5 proxy

1. **Config.** One optional field on `FederationConfig` (`config.rs:368`):

   ```yaml
   federation:
     listen: "127.0.0.1:47000"
     socks5: "127.0.0.1:9050"          # local Tor (9050) or i2pd (4447) SOCKS port
     peers:
       - { name: peer-b, node_id: "rf:<64 hex>", addr: "abcd…xyz.onion:47000" }
       - { name: peer-c, node_id: "rf:<64 hex>", addr: "xyz…def.b32.i2p:47000" }
       - { name: peer-d, node_id: "rf:<64 hex>", addr: "10.0.0.5:47000" }  # clearnet
   ```

   `socks5: Option<String>` — a single field, not a per-peer flag. Default
   `None` = today's direct-connect behaviour, fully back-compatible.

2. **Dial path — proxy chosen by address type, not a flag.** In
   `spawn_outbound` (`fed/conn.rs:307`): if the peer `addr`'s host is a
   hidden-service name (`.onion` / `.i2p` suffix) **and** `socks5` is set, dial
   via SOCKS5 CONNECT to `peer.addr` through the proxy (the proxy resolves the
   name — the daemon never does a clearnet DNS lookup for it); otherwise a
   direct `TcpStream::connect` exactly as today. **Clearnet peers stay direct
   even when `socks5` is set** — the daemon does not silently route clearnet
   federation through Tor; an operator who wants that uses onion addresses.
   *(Open option: a `federation.proxy_all: true` toggle to force every dial
   through the proxy, for operators who want to hide clearnet peering too. Left
   out of the first slice unless wanted.)*

3. **Address validation (the one real gotcha).** `config.rs:1206` currently
   rejects any `addr` that doesn't parse as a `std::net::SocketAddr`, which a
   `.onion`/`.i2p` hostname never will. Relax it: a hidden-service host
   validates as `host:port` (non-empty host, `u16` port); clearnet addrs keep
   the strict `SocketAddr` check so a typo is still caught. A hidden-service
   `addr` with no `socks5` set is a config error naming the peer.

### Inbound — run as a hidden service (no code change)

The hidden service is configured in the anonymity daemon, not in RelayFabric:
it maps the public address to the daemon's existing loopback `listen`. Inbound
needs **zero daemon changes**.

```
# Tor — /etc/tor/torrc
HiddenServiceDir /var/lib/tor/relayfabric/
HiddenServicePort 47000 127.0.0.1:47000
# hostname file → the .onion address to share with peers

# I2P — i2pd tunnels.conf
[relayfabric]
type = server
host = 127.0.0.1
port = 47000
keys = relayfabric.dat
# the tunnel's .b32.i2p address is what peers put in addr
```

### Dependency

A SOCKS5 client. Prefer `tokio-socks` (MIT) if it fits the permissive-only
policy at integration time; otherwise the SOCKS5 CONNECT handshake is ~40
lines over the existing `TcpStream` and can be inlined (no new dep). Decide at
implementation time.

## Operational notes

- **Latency.** Onion/I2P circuits add latency and occasional reconnects. The
  outbound redial/backoff loop already tolerates this; the transport-class
  layer should treat proxied peers as higher-latency/constrained so egress
  degrades gracefully rather than timing out aggressively.
- **Bootstrap.** The daemon depends on a running local `tor` or `i2pd`.
  Document it as an external service (like `mosquitto` for the MQTT demo); the
  daemon should log a clear error if the SOCKS port is unreachable and keep
  retrying.

## Considered alternative — Approach D: federate over Reticulum

Instead of tunnelling the raw TCP federation link, RelayFabric gateways could
announce RNS destinations and carry RFDP **over a Reticulum link**, inheriting
I2P transport (`I2PInterface`), Tor-ability, NAT traversal, store-and-forward,
and end-to-end encryption from RNS for free — and collapsing the edge and
federation planes into one. This is the "Reticulum-native" design NomadNet
makes obvious.

Rejected for the bounded v0.2 add because it is a far larger change:

- RNS becomes a hard dependency for the federation plane (today only the lxmf
  plugin needs it).
- RNS's own transport encryption partly duplicates Noise (§86) + gateway
  attestation (§33), so the trust model would need reconciling, not just
  reusing.
- RFDP framing assumes a reliable TCP byte stream; RNS packet/MTU/link
  semantics differ, so the wire framing would need rework — violating this
  proposal's "no new wire protocol" scope.

Worth revisiting as a v0.4+ architectural direction (alongside the companion
client and user-to-user SEALED), where unifying the planes may pay for itself.
Recorded here so the question "why not just federate over Reticulum?" has an
answer.

## Test plan

- Unit: a `.onion`/`.i2p` `addr` validates only when `socks5` is set, and is a
  config error without it; a malformed clearnet `addr` still fails.
- Unit: `spawn_outbound` issues a SOCKS5 CONNECT for a hidden-service `addr`
  when `socks5` is set (against a stub SOCKS server), and a direct connect for
  a clearnet `addr` regardless.
- Manual: two daemons federating over local Tor onion services, and over local
  i2pd tunnels, end to end.
