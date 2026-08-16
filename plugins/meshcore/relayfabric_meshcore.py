"""RelayFabric MeshCore plugin: bridges MeshCore text events over Plugin Protocol v1.

Module top level is stdlib-only (urllib.parse) so config/parser/event
helpers stay importable without meshcore package. Text bytes are never logged,
only names/types.
"""

import urllib.parse

PLUGIN_VERSION = "0.1.0"

# Hard ceiling on advertised Hello capabilities.max_payload, independent of
# cfg["max_text_bytes"]: a practical cap for MeshCore text payloads regardless
# of how an operator configures max_text_bytes.
MESHCORE_MAX_PAYLOAD = 160


def load_config(raw):
    """Load and validate MeshCore plugin configuration.

    Required fields: connection (string), channels (non-empty dict).
    Each channel value must be a dict with required int 'index'.

    Defaults: max_text_bytes 160.

    Returns a copy of the config dict with channels deep-copied.
    Raises ValueError if validation fails.
    Raises TypeError if type checks fail.
    """
    cfg = dict(raw)

    if not cfg.get("connection"):
        raise ValueError("config requires 'connection'")
    if not isinstance(cfg.get("connection"), str):
        raise TypeError("connection must be str")
    if not cfg.get("channels"):
        raise ValueError("config requires a non-empty 'channels' mapping")
    if not isinstance(cfg.get("channels"), dict):
        raise TypeError("channels must be a dict")

    # Validate and copy channels
    channels_copy = {}
    for name, channel_spec in cfg["channels"].items():
        if not isinstance(channel_spec, dict):
            raise TypeError(f"channel '{name}' must be a dict")
        if "index" not in channel_spec:
            raise ValueError(f"channel '{name}' requires 'index'")
        idx = channel_spec["index"]
        if not isinstance(idx, int):
            raise TypeError(
                f"channel '{name}' index must be int, got {type(idx).__name__}"
            )

        # Deep copy each channel spec
        channels_copy[name] = dict(channel_spec)

    cfg["channels"] = channels_copy
    cfg.setdefault("max_text_bytes", 160)
    if not isinstance(cfg["max_text_bytes"], int):
        raise TypeError(
            f"max_text_bytes must be int, got {type(cfg['max_text_bytes']).__name__}"
        )

    return cfg


def parse_connection(url):
    """Parse a MeshCore connection URL into (kind, target, dict).

    Supported schemes:
    - serial://<path>[?baud=N] → ("serial", path, {"baud": N or 115200})
    - tcp://host:port → ("tcp", (host, port), {})
    - ble://<addr> → ("ble", addr, {})

    Raises ValueError for unsupported schemes or malformed URLs.
    """
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme

    if scheme == "serial":
        path = parsed.netloc + parsed.path
        if not path:
            raise ValueError("serial:// requires a path")
        query_params = urllib.parse.parse_qs(parsed.query)
        baud = 115200
        if "baud" in query_params:
            try:
                baud = int(query_params["baud"][0])
            except (ValueError, IndexError):
                raise ValueError("serial:// baud must be an integer")
        return "serial", path, {"baud": baud}

    elif scheme == "tcp":
        if not parsed.hostname or parsed.port is None:
            raise ValueError("tcp:// requires host:port")
        return "tcp", (parsed.hostname, parsed.port), {}

    elif scheme == "ble":
        addr = parsed.netloc + parsed.path
        if not addr:
            raise ValueError("ble:// requires an address")
        return "ble", addr, {}

    else:
        raise ValueError(
            f"unsupported connection scheme: {scheme!r}; "
            "supported: serial://, tcp://, ble://"
        )


def channels_by_index(cfg):
    """Build reverse mapping from channel index to channel name.

    Returns dict[int, str] mapping channel index to name.
    """
    return {
        channel_spec["index"]: name
        for name, channel_spec in cfg["channels"].items()
    }


def normalize_event(ev, by_index):
    """Parse a MeshCore event dict into (name, sender, text, ts) or None.

    Args:
        ev: dict with keys kind, channel_idx, sender, text, ts (optional).
        by_index: dict[int, str] mapping channel index to channel name.

    Returns:
        (name, sender, text, ts) tuple if valid channel_msg event, else None.

    Filters:
    - kind != "channel_msg" → None
    - missing or empty text → None
    - unmapped channel_idx → None
    - missing sender → None

    Timestamp: ev.get("ts") (may be None).
    """
    # Type filter
    if ev.get("kind") != "channel_msg":
        return None

    # Text validation
    text = ev.get("text")
    if not text or not isinstance(text, str):
        return None

    # Sender validation (required, presented as given)
    sender = ev.get("sender")
    if sender is None:
        return None

    # Channel mapping
    channel_idx = ev.get("channel_idx")
    if channel_idx is None:
        return None
    if channel_idx not in by_index:
        return None
    name = by_index[channel_idx]

    ts = ev.get("ts")

    return name, sender, text, ts


def hello_max_payload(cfg):
    """Advertised Hello capabilities.max_payload for this config.

    160 is the hard MeshCore-practical ceiling regardless of config: it
    keeps the advertised cap (which the daemon min()s against its own
    policy caps to decide truncation) independent of the local defensive
    check in Bridge.handle_send (cfg["max_text_bytes"]), so one
    misconfigured max_text_bytes can't disable both safety layers at once.
    A lower operator max_text_bytes tightens the advertised cap; a higher
    one can never loosen it past 160.
    """
    return min(MESHCORE_MAX_PAYLOAD, cfg["max_text_bytes"])
