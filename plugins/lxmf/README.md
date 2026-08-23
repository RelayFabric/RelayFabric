# relayfabric-lxmf

Bridges [LXMF](https://github.com/markqvist/LXMF) (over Reticulum) into
RelayFabric as a Plugin Protocol v1 plugin. Each configured channel maps
to a set of LXMF destination hashes ("members"): messages from a member
land on the channel, and messages sent to the channel fan out as direct
LXMF messages to every member, falling back to a propagation node
(store-and-forward) if direct delivery fails. Text and attachments (see
[Attachments](#attachments)).

## Install

```
pip install -r plugins/lxmf/requirements.txt
```

## Daemon config

The daemon spawns `command` via `sh -c`, so a bare `relayfabric-lxmf` only
works if it's on `PATH` — and the script's `#!/usr/bin/env python3` shebang
won't see packages installed in a venv. Point `command` at the venv's
Python and the script's absolute path instead, after
`pip install -r plugins/lxmf/requirements.txt` into that venv:

```yaml
plugins:
  lxmf:
    enabled: true
    command: /path/to/RelayFabric/.venv/bin/python /path/to/RelayFabric/plugins/lxmf/relayfabric-lxmf
    config:
      display_name: "RelayFabric Gateway"
      storage: /var/lib/relayfabric/lxmf
      rns_configdir: null          # null = default ~/.reticulum
      announce_interval: 3600
      stamp_cost: null             # PoW bits (1-254) we REQUIRE of inbound senders
      outbound_stamp_cost: null    # PoW bits (1-254) we PAY on outbound (e.g. 16 for Sideband)
      propagation_node: "auto"     # "auto" | explicit dest hash hex | null
      max_attachment_bytes: 1000000  # per-attachment cap, applied both ways
      image_max_bytes: null        # null = falls back to max_attachment_bytes
      voice_to_codec2: null        # e.g. 1200 = transcode outbound voice to codec2
      channels:
        - name: pasadena
          members: ["a91d00aa..."] # lowercase LXMF destination hashes
          open: false              # closed: operator-managed membership only
```

## Finding the gateway address

On startup the plugin logs its LXMF address once: `Gateway LXMF address:
<a91d00aa...>`. Give that to members to add as a Sideband contact.

## Commands

Sent as LXMF message text to the gateway address:

- `/join <channel>` — join an `open` channel
- `/leave <channel>` — leave a channel you dynamically joined
- `/channels` — list channels and your membership status

`open: false` channel membership is operator-managed via
`config.channels[].members`; dynamic joins persist to `<storage>/members.json`.

## Identity linking

This plugin advertises `direct_messages`, so LXMF members can be the target
of an opt-in, challenge-verified identity link (daemon-side; see the root
README and `switchyardctl link/unlink/identities`). The verification code
is delivered as a direct LXMF message via the same `send_lxmf` path used for
channel fan-out.

## Attachments

Files, an inline image, and voice messages bridge as LXMF fields
(`FIELD_FILE_ATTACHMENTS`/`FIELD_IMAGE`/`FIELD_AUDIO`); everything else
crosses as plain text.

- `max_attachment_bytes` (default 1,000,000): applied in both directions —
  any attachment over this size is dropped, appending a `[dropped <name>:
  N B over M B limit]` note to the message body instead of failing the send.
- `image_max_bytes` (default `null`, falling back to `max_attachment_bytes`):
  the size budget for the first image attachment, which becomes the inline
  `FIELD_IMAGE`.
- `voice_to_codec2` (default `null`): a codec2 bitrate (e.g. `1200`) to
  transcode the first outbound audio attachment into LXMF's tiny,
  LoRa-friendly `FIELD_AUDIO`.

Optional dependencies and what degrades without them:

- **Pillow** — recompresses/downscales an oversize image to fit
  `image_max_bytes`. Without it, an oversize image is dropped with a note
  instead of being shrunk.
- **ffmpeg** and **pycodec2** (which needs the `libcodec2` C library) —
  encode outbound voice to codec2 and decode inbound codec2 voice back to
  WAV. Without either, `voice_to_codec2` is a no-op and voice crosses as a
  plain file attachment instead of `FIELD_AUDIO`; without `pycodec2` alone,
  inbound codec2 voice is forwarded raw as `voice.c2` instead of being
  decoded to `voice.wav`.

None of these are required to install — `pip install -r
plugins/lxmf/requirements.txt` covers text and generic file attachments.

## Manual e2e smoke test

1. Start the daemon with the plugin configured as above.
2. Note the `Gateway LXMF address` from the plugin's log output.
3. In Sideband, add that address as a contact and send it a text message;
   expect it to land as an inbound message on the configured channel.
4. Route a message back through the daemon to that channel; expect it at
   Sideband, e.g. bridged onward as `[LXMF-a91d00aa] <text>`.
