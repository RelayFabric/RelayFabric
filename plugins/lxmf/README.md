# relayfabric-lxmf

Bridges [LXMF](https://github.com/markqvist/LXMF) (over Reticulum) into
RelayFabric as a Plugin Protocol v1 plugin. Each configured channel maps
to a set of LXMF destination hashes ("members"): messages from a member
land on the channel, and messages sent to the channel fan out as direct
LXMF messages to every member, falling back to a propagation node
(store-and-forward) if direct delivery fails. Text only.

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
      stamp_cost: null             # set to require inbound proof-of-work
      propagation_node: "auto"     # "auto" | explicit dest hash hex | null
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

## Manual e2e smoke test

1. Start the daemon with the plugin configured as above.
2. Note the `Gateway LXMF address` from the plugin's log output.
3. In Sideband, add that address as a contact and send it a text message;
   expect it to land as an inbound message on the configured channel.
4. Route a message back through the daemon to that channel; expect it at
   Sideband, e.g. bridged onward as `[LXMF-a91d00aa] <text>`.
