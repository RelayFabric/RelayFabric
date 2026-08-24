# relayfabric-xmpp

Bridges **XMPP** multi-user chat (MUC) rooms and 1:1 direct messages into
RelayFabric, using the permissive [`slixmpp`](https://slixmpp.readthedocs.io/)
(MIT) client. Unlike the `signal` and `meshtastic-direct` plugins, there is
**no GPL** here — this plugin stays Apache-2.0 in-tree.

## Scope (v1)

- **Text only.** MUC rooms map to RelayFabric channel endpoints; inbound 1:1
  chats arrive on a synthetic `direct:<jid>` endpoint (the `direct_messages`
  capability), which also enables identity-linking. A non-challenge DM
  matches no route and is dropped by deny-by-default — it never leaks onto a
  channel.
- **Not** in v1: attachments (XEP-0363 HTTP Upload), presence bridging, OMEMO.

> **Trust posture:** plain XMPP is TLS **to the server** but **server-readable**
> — a gateway (not end-to-end) bridge. OMEMO E2EE is out of scope this cycle.

## Install

```
pip install -r plugins/xmpp/requirements.txt
```

## Node setup

Create a normal XMPP account for the bridge on your server (Prosody,
ejabberd, …) and, for each MUC you bridge, make sure the account is allowed to
join the room.

## Daemon config

```yaml
plugins:
  xmpp:
    enabled: true
    command: /path/to/RelayFabric/.venv/bin/python /path/to/RelayFabric/plugins/xmpp/relayfabric-xmpp
    config:
      jid: "relay@example.com"
      password: ${env:XMPP_PASSWORD}      # use a secret reference
      nick: "relayfabric"                 # MUC nickname (default: relayfabric)
      max_text_bytes: 4000
      channels:
        townsquare: { muc: "townsquare@conference.example.com" }
```

Each channel maps a MUC room JID to a RelayFabric endpoint. A loop guard
drops the room's reflection of our own sends (1h window on `(channel, text)`),
in addition to dropping messages from our own MUC nick.

## Direct messages

Via the `direct_messages` capability the daemon can deliver a DM to a bare
JID (`switchyardd`'s identity-link challenge, and any route targeting
`direct:<jid>`), and an inbound DM is surfaced on `direct:<sender-jid>`.

## Limitations

- **Text only** this cycle (see scope above).
- `slixmpp` auto-reconnects a dropped link; a hard **auth failure** exits the
  process for the supervisor to restart (bad credentials never self-heal).
- Exercised against a fake backend in unit tests; verify against a real
  server before production (one inbound MUC message, one max-length send).
