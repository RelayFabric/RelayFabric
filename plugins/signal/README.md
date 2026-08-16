# relayfabric-signal

Bridges Signal groups into RelayFabric as a Plugin Protocol v1 plugin. Each
configured group maps to a channel: messages from group members land on the channel, and messages sent to the channel are delivered to the mapped group (one endpoint, one group; fan-out is the daemon's routing concern).
Text and attachments (see [Attachments](#attachments)). Uses a signal-cli
JSON-RPC/SSE daemon.

## Install

```
pip install -r plugins/signal/requirements.txt
```

## signal-cli daemon setup

Register or link an account and start the daemon on the gateway host:

```
signal-cli -a +1234567890 register           # or: signal-cli link -n "relayfabric"
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
      attachment_dir: ~/.local/share/signal-cli/attachments  # signal-cli's download dir
      max_attachment_bytes: 8000000  # per-attachment cap, applied both ways
```

## Linked-account note

If the account is a linked device, sync messages from the primary are handled: echoes of the gateway's own posts are filtered, and DMs (no group) are dropped.
If `allowed_users` is set, include the account's own UUID in the list, or the operator's own phone posts will be dropped by the ACL.

## Attachments

Signal attachments bridge as generic files — signal-cli already downloads
them to `attachment_dir` before the SSE event fires; this plugin does not
decode, downscale, or transcode anything itself.

- `attachment_dir` (default `~/.local/share/signal-cli/attachments`, `~`
  expanded when read, not at config load): where signal-cli stores received
  attachment files. Each descriptor's `id` is basename-sanitized before
  joining, so a hostile or malformed id can never read outside this
  directory (an unreadable/missing file becomes a `[attachment <name>
  unavailable]` note instead).
- A fixed 32,000,000 B (32 MB) sanity cap bounds how much of a single
  attachment file is read into memory before any size policy is applied; a
  file over this cap is dropped with a note rather than failing the message.
- `max_attachment_bytes` (default 8,000,000): the actual pass-through cap,
  applied in both directions — inbound (Signal -> daemon) and outbound
  (daemon -> Signal) attachments over this size are dropped with a
  `[dropped <name>: N B over M B limit]` note appended to the message body.
- Outbound attachments are written to a fresh `tempfile.mkdtemp()`
  directory (basename-sanitized filenames), referenced by signal-cli's
  JSON-RPC `send`, and the directory is removed once the send returns.

No optional dependencies (Pillow/pycodec2/ffmpeg) are needed by this
plugin — it forwards attachment bytes as-is. Those matter on the LXMF side:
when a Signal attachment is routed onward to an `lxmf` endpoint,
[relayfabric-lxmf](../lxmf/README.md#attachments) applies image
downscaling/voice transcoding there, and degrades the same way if those
extras aren't installed.

## Manual e2e smoke test

1. Start the signal-cli daemon: `signal-cli -a +1234567890 daemon --http 127.0.0.1:7583`
2. Start RelayFabric daemon with plugin configured.
3. Send a message to the configured Signal group from a member.
4. Expect the message on the channel.
5. Route a message back through the daemon to the channel.
6. Expect the message delivered to the Signal group.
