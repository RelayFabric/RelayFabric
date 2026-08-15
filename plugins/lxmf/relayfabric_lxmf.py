"""RelayFabric LXMF plugin: bridges Reticulum/LXMF channels over Plugin Protocol v1."""

import json
import os


def load_config(raw):
    cfg = dict(raw)
    if not cfg.get("storage"):
        raise ValueError("config requires 'storage'")
    cfg.setdefault("display_name", "RelayFabric Gateway")
    cfg.setdefault("rns_configdir", None)
    cfg.setdefault("announce_interval", 3600)
    cfg.setdefault("stamp_cost", None)
    cfg.setdefault("propagation_node", None)
    cfg["channels"] = [dict(ch) for ch in cfg.get("channels", [])]
    for ch in cfg["channels"]:
        if not ch.get("name"):
            raise ValueError("every channel requires a 'name'")
        ch["members"] = [m.lower() for m in ch.get("members", [])]
        ch.setdefault("open", False)
    return cfg


def channel_by_name(cfg, name):
    return next((c for c in cfg["channels"] if c["name"] == name), None)


def channel_for_member(cfg, sender_hex, dynamic):
    for ch in cfg["channels"]:
        if sender_hex in ch["members"] or sender_hex in dynamic.get(ch["name"], []):
            return ch
    return None


def channel_members(channel, dynamic):
    joined = dynamic.get(channel["name"], [])
    return channel["members"] + [m for m in joined if m not in channel["members"]]


def command_reply(cfg, dynamic, sender, text):
    parts = text.split()
    cmd = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else None

    if cmd == "/join" and arg:
        ch = channel_by_name(cfg, arg)
        if ch is None:
            return f"No such channel: {arg}", False
        if sender in ch["members"] or sender in dynamic.get(arg, []):
            return f"Already a member of {arg}", False
        if not ch["open"]:
            return f"Channel {arg} is closed; ask the operator", False
        dynamic.setdefault(arg, []).append(sender)
        return f"Joined {arg}", True

    if cmd == "/leave" and arg:
        joined = dynamic.get(arg, [])
        if sender in joined:
            joined.remove(sender)
            return f"Left {arg}", True
        ch = channel_by_name(cfg, arg)
        if ch is not None and sender in ch["members"]:
            return (f"You are in {arg} via the gateway config; "
                    f"ask the operator to remove you"), False
        return f"Not a member of {arg}", False

    if cmd == "/channels":
        lines = []
        for ch in cfg["channels"]:
            if sender in ch["members"] or sender in dynamic.get(ch["name"], []):
                status = "member"
            else:
                status = "open" if ch["open"] else "closed"
            lines.append(f"{ch['name']} ({status})")
        return "\n".join(lines) or "No channels configured", False

    return "Commands: /join <channel>, /leave <channel>, /channels", False


def save_members_atomic(path, dynamic):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(dynamic, f, indent=2)
    os.replace(tmp, path)
