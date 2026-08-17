# relayfabric-bitchat

Bridges Bitchat's **public geohash channels** into RelayFabric as a Plugin
Protocol v1 plugin, over the **Internet/Nostr transport** (ephemeral
kind-20000 events, channel = `["g", <geohash>]` tag) — reusing the shipped
Nostr NIP-01 crypto (`relayfabric_sdk.nip01`: coincurve/websockets,
MIT/BSD-3), never the GPL `strfry` relay or the AGPL `NYM` Bitchat-Nostr
bridge (reference-only per project policy). **BLE mesh is OUT of scope,
deferred** — Bitchat's direct Bluetooth-LE mesh is a separate mechanism
not built here; only the Internet/Nostr side. DMs/attachments out too.

## Install

```
pip install -r plugins/bitchat/requirements.txt
```

## Identity: ONE stable key

A single secp256k1/BIP-340 keypair (from `identity_file` if it already
holds one, else generated and, if set, persisted mode 0600; npub logged
once, nsec never) authors every outbound event on every configured
geohash. **Trade-off, stated plainly:** one key means the same pubkey
shows up on every geohash this bridge posts to — cross-geohash-linkable
to anyone watching a relay. Real Bitchat clients avoid this with
per-geohash ephemeral keys, whose derivation isn't cleanly documented
anywhere we could confirm, so it's deferred here.

## Daemon config

```yaml
plugins:
  bitchat:
    enabled: true
    command: /path/to/RelayFabric/.venv/bin/python /path/to/RelayFabric/plugins/bitchat/relayfabric-bitchat
    config:
      identity_file: /var/lib/relayfabric/bitchat.nsec  # optional; generated if absent
      relays: ["wss://relay.example.com"]                # default relay set
      channels:
        pasadena:
          geohash: "9q5c"                                 # base32, Bitchat's alphabet
          relays: ["wss://relay.example.com"]              # optional; falls back to default
          nickname: "relayfabric"                          # optional; passthrough n-tag only
      max_text_bytes: 280
```

## Sig-verify + deny-by-default

Every inbound event's id is recomputed (NIP-01 canonical sha256) and its
schnorr sig verified before bridging — a relay is untrusted (spec §80);
bad id/sig, wrong-kind, or wrong-geohash events are dropped. Only
configured geohashes are subscribed; only configured channels send.

## Loop guard

Consume-on-match cache keyed on `(channel, text)`: a successful publish
records the pair for 1 hour, dropping the next matching inbound event.

## Known field-test risks

- Pre-1.0 protocol: kind 20000 + `g`-tag geohash are stable; nickname/
  teleport semantics are not — expect churn.
- Ephemeral events: nothing is stored — bridges only with a live relay
  connection at publish time.
- Single-key cross-geohash linkability (see Identity above).
- Interop with real Bitchat clients is UNVERIFIED — fakes only, no live cross-check.
- Geohash breadth: a coarser (shorter) geohash is a wider channel, more
  traffic bridged.
- No BLE mesh, no DMs, no attachments.
