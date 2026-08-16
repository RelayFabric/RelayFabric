# relayfabric-signal

Bridges Signal groups into RelayFabric as a Plugin Protocol v1 plugin. Each
configured group maps to a channel: messages from group members land on the
channel, and messages sent to the channel fan out as Signal group messages to
all configured groups. Text only. Uses a signal-cli JSON-RPC/SSE daemon.

## Install

```
pip install -r plugins/signal/requirements.txt
```

## signal-cli daemon setup

Register or link an account and start the daemon on the gateway host:

```
signal-cli -a +1234567890 register           # or: link --legacy
signal-cli -a +1234567890 daemon --http 127.0.0.1:7583
```

Then find your group IDs:

```
signal-cli -a +1234567890 listGroups
```

## Daemon config

Point `command` at the venv's Python and script absolute path after
`pip install -r plugins/signal/requirements.txt` into the venv:

```yaml
plugins:
  signal:
    enabled: true
    command: /path/to/RelayFabric/.venv/bin/python /path/to/RelayFabric/plugins/signal/relayfabric-signal
    config:
      account: "+1234567890"       # gateway's phone number
      rpc_url: http://127.0.0.1:7583  # signal-cli daemon URL
      groups:
        pasadena: "GRP=="          # channel: group_id (from listGroups)
      allowed_users: null          # null = all members; list UUIDs to restrict
```

## Linked-account note

If the account is a linked device, sync messages from the primary are handled:
echoes of the gateway's own posts are filtered, and DMs (no group) are dropped.

## Manual e2e smoke test

1. Start the signal-cli daemon: `signal-cli -a +1234567890 daemon --http 127.0.0.1:7583`
2. Start RelayFabric daemon with plugin configured.
3. Send a message to the configured Signal group from a member.
4. Expect the message on the channel.
5. Route a message back through the daemon to the channel.
6. Expect the message delivered to the Signal group.
