# Proposal: Federation over Tor (and, later, I2P)

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

Routing an RFDP link through a Tor onion service closes both gaps: peer IPs
stay hidden from network observers, and an onion service gives inbound
reachability with no public IP or forwarded port.

## Non-goals

- No new framing or handshake — RFDP/Noise runs unchanged over the tunnelled
  TCP stream.
- Not a replacement for sealed routing (content) or end-to-end privacy: Tor
  hides transport metadata from the *network*, not from the peer you federate
  with.
- Does not anonymize plugin transports that hit third-party servers (Nostr
  relays, MQTT, Signal); those only benefit if the endpoint itself offers an
  onion address. This proposal covers the RFDP inter-node links only.

## Design (Tor)

Two independent halves; either can ship alone.

### Outbound — dial peers through a SOCKS5 proxy

1. **Config.** Add an optional proxy to `FederationConfig` (`config.rs:368`):

   ```yaml
   federation:
     listen: "127.0.0.1:47000"
     socks5: "127.0.0.1:9050"        # optional; Tor's default SOCKS port
     peers:
       - name: peer-b
         node_id: "rf:<64 hex>"
         addr: "abcd…xyz.onion:47000"  # onion host:port
   ```

   `socks5: Option<String>` (default `None` = today's direct-connect
   behaviour, fully back-compatible).

2. **Dial path.** In `spawn_outbound` (`fed/conn.rs:307`), when `socks5` is
   set, replace the direct `TcpStream::connect(&peer.addr)` with a SOCKS5
   CONNECT to `peer.addr` through the proxy. The proxy resolves the `.onion`
   name (Tor does the resolution — the daemon never does a clearnet DNS
   lookup for it). Everything after the connected stream is unchanged.

3. **Address validation (the one real gotcha).** `config.rs:1206` currently
   rejects any `addr` that doesn't parse as a `std::net::SocketAddr`, which an
   `.onion` hostname never will. Relax it: when `socks5` is set, validate
   `addr` as `host:port` (non-empty host, `u16` port) instead of a numeric
   `SocketAddr`. Keep the strict `SocketAddr` check for direct (no-proxy)
   peers so a typo in a clearnet address is still caught.

### Inbound — run as an onion service (no code change)

An onion service is configured in `torrc`, not in RelayFabric: Tor maps
`<onion>:47000` to the daemon's existing local `listen` address. So inbound
needs **zero daemon changes** — bind `listen` to loopback and point an onion
service at it:

```
# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/relayfabric/
HiddenServicePort 47000 127.0.0.1:47000
```

The generated `hostname` file is the `.onion` address to share with peers.

### Dependency

A SOCKS5 client. Prefer `tokio-socks` (MIT) if it fits the permissive-only
policy at integration time; otherwise the SOCKS5 CONNECT handshake is ~40
lines over the existing `TcpStream` and can be inlined (no new dep). Decide at
implementation time.

## Operational notes

- **Latency.** Onion circuits add latency and occasional reconnects. The
  outbound redial/backoff loop already tolerates this; the transport-class
  layer should treat onion peers as higher-latency/constrained so egress
  degrades gracefully rather than timing out aggressively.
- **Bootstrap.** The daemon depends on a running local `tor`. Document it as
  an external service (like `mosquitto` for the MQTT demo); the daemon should
  log a clear error if the SOCKS port is unreachable and keep retrying.

## I2P — deferred

I2P offers a similar hidden-service model with stronger sustained-anonymity
properties, reachable through its SOCKS proxy (or SAM). If `socks5` lands as
above, pointing it at I2P's SOCKS port is most of the work — but I2P is
heavier to operate and has a smaller ecosystem, so defer it until there's
demand rather than carrying the extra dependency and docs up front.

## Test plan

- Unit: `socks5`-set config accepts an `.onion` `addr`; unset config still
  rejects a non-`SocketAddr` addr (guards the relaxed validation).
- Unit: `spawn_outbound` issues a SOCKS5 CONNECT when `socks5` is set (against
  a stub SOCKS server), a direct connect when it isn't.
- Manual: two daemons federating over local onion services end to end.
