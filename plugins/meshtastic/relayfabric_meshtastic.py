"""RelayFabric Meshtastic plugin: bridges Meshtastic MQTT text uplinks over Plugin Protocol v1.

Module top level is stdlib-only (logging) so config/parser/loop-guard helpers stay
importable without cbor2, paho-mqtt, or meshtastic/protobuf packages (GPL).
relay_ipc and backend components are imported lazily inside the methods that need them.
Text bytes are never logged, only names/types.
"""

import logging

log = logging.getLogger(__name__)

PLUGIN_VERSION = "0.1.0"


def load_config(raw):
    """Load and validate Meshtastic plugin configuration.

    Required fields: broker, topic_root, channels (non-empty dict).
    Each channel value must be a dict with required int 'index' and str 'topic_channel'.

    Defaults: gateway_id None, max_text_bytes 200.

    Returns a copy of the config dict with channels deep-copied.
    Raises ValueError if validation fails.
    """
    cfg = dict(raw)

    if not cfg.get("broker"):
        raise ValueError("config requires 'broker'")
    if not cfg.get("topic_root"):
        raise ValueError("config requires 'topic_root'")
    if not cfg.get("channels"):
        raise ValueError("config requires a non-empty 'channels' mapping")

    # Validate and copy channels
    channels_copy = {}
    for name, channel_spec in cfg["channels"].items():
        if not isinstance(channel_spec, dict):
            raise TypeError(f"channel '{name}' must be a dict")
        if "index" not in channel_spec:
            raise ValueError(f"channel '{name}' requires 'index'")
        if "topic_channel" not in channel_spec:
            raise ValueError(f"channel '{name}' requires 'topic_channel'")
        idx = channel_spec["index"]
        if not isinstance(idx, int):
            raise TypeError(f"channel '{name}' index must be int, got {type(idx).__name__}")
        if not isinstance(channel_spec["topic_channel"], str):
            raise TypeError(f"channel '{name}' topic_channel must be str")

        # Deep copy each channel spec
        channels_copy[name] = dict(channel_spec)

    cfg["channels"] = channels_copy
    cfg.setdefault("gateway_id", None)
    cfg.setdefault("max_text_bytes", 200)

    return cfg


def channels_by_index(cfg):
    """Build reverse mapping from channel index to channel name.

    Returns dict[int, str] mapping channel index to name.
    """
    return {
        channel_spec["index"]: name
        for name, channel_spec in cfg["channels"].items()
    }


def parse_uplink(topic, event, by_index, gateway_id):
    """Parse a Meshtastic text uplink event into (name, sender, text, ts) or None.

    Args:
        topic: MQTT topic string, form <root>/2/json/<TopicChannel>/<!gatewayhex>
        event: dict with type, payload, channel, sender (optional), from (optional), timestamp (optional)
        by_index: dict[int, str] mapping channel index to channel name (from channels_by_index)
        gateway_id: str gateway_id from config (may be None for no filtering)

    Returns:
        (name, sender, text, ts) tuple if valid text event, else None.

    Gateway filtering: if gateway_id is set, compares last topic segment against it;
    mismatch returns None.

    Channel mapping: event["channel"] is looked up in by_index; unmapped returns None.

    Sender resolution: prefers event.get("sender"), falls back to f"!{event['from']:08x}" if
    'from' field is present, else None (drops message).

    Text validation: event["type"] must be "text", and payload["text"] must be
    non-empty string, else None.

    Timestamp: event.get("timestamp") (may be None).
    """
    # Type filter
    if event.get("type") != "text":
        return None

    # Text validation
    payload = event.get("payload") or {}
    text = payload.get("text")
    if not text or not isinstance(text, str):
        return None

    # Channel mapping
    channel_idx = event.get("channel")
    if channel_idx is None:
        return None
    if channel_idx not in by_index:
        return None
    name = by_index[channel_idx]

    # Sender resolution
    sender = event.get("sender")
    if sender is None:
        from_val = event.get("from")
        if from_val is not None:
            sender = f"!{from_val:08x}"
        else:
            return None

    # Gateway filter (if gateway_id is set, check last topic segment)
    if gateway_id is not None:
        last_segment = topic.rsplit("/", 1)[-1] if "/" in topic else None
        if last_segment != gateway_id:
            return None

    ts = event.get("timestamp")

    return name, sender, text, ts
