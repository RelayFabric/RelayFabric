# relayfabric-nostr

Bridges Nostr relays into RelayFabric as a Plugin Protocol v1 plugin. Speaks
native NIP-01 directly over WebSocket relays (spec §8's preferred native
style) — no intermediary broker, and never the GPL `strfry` relay (reference-
only per project policy). Each channel is a `(relay-set, filter)` for
inbound plus a publish target.

**Scope: kind-1 public text notes only.** Encrypted DMs (NIP-04/NIP-17
gift-wrap), attachments, and profile/contact-list management are out of
scope this cycle.

## Install

```
pip install -r plugins/nostr/requirements.txt
```

## Identity

One Nostr keypair (secp256k1/BIP-340 schnorr, hex form — not bech32
`nsec1.../npub1...`) is the plugin's outbound author identity: reused from
`identity_file` if it already holds a key, else generated and (if
`identity_file` is set) persisted there mode 0600. Public key (npub, hex)
logged once at startup, private key never; a `null` `identity_file` means a
fresh identity every restart.

## Daemon config

```yaml
plugins:
  nostr:
    enabled: true
    command: /path/to/RelayFabric/.venv/bin/python /path/to/RelayFabric/plugins/nostr/relayfabric-nostr
    config:
      identity_file: /var/lib/relayfabric/nostr.nsec  # optional; generated if absent
      relays: ["wss://relay.example.com"]              # default relay set
      channels:
        regional:
          relays: ["wss://relay.example.com"]           # optional; falls back to default
          filter: {kinds: [1], "#t": ["pasadena"]}       # NIP-01 REQ filter
          publish_tags: [["t", "pasadena"]]              # tags on outbound events
      max_text_bytes: 280
```

## Sig-verify + deny-by-default

Every inbound event's id is recomputed (NIP-01 canonical sha256) and its
schnorr sig verified against the claimed pubkey before bridging — a relay is
untrusted (spec §80); bad id/sig events are dropped, never bridged. Only
configured channels' filters are subscribed, and only configured channels
accept outbound sends.

## Loop guard

Consume-on-match cache keyed on `(channel, text)`: a successful publish
records the pair for 1 hour, dropping the next matching inbound event on
that channel (a genuine identical-text note within that hour can also be
swallowed).

## Known field-test risks

- Relay reliability/dedup: relays reconnect independently; an event from
  two subscribed relays isn't deduped. Exercised only against fakes.
- Filter breadth: an unscoped filter (bare `{"kinds":[1]}`) bridges
  relay-wide traffic as spam — operator scopes it.
- Clock skew: `created_at` is relay/author-supplied, not wall-clock checked.
- `nostr:<pubkey hex>` sender identity is stable per author but not
  human-friendly; a rotated keypair reads as an entirely new sender.
