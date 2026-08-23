"""RelayFabric Plugin Protocol v1 codec: 4-byte BE length prefix + CBOR.

Moved from plugins/lxmf/relay_ipc.py into the SDK so the fleet (lxmf,
signal, meshtastic, meshcore) shares one copy instead of importing across
plugin directories.

Dict key order matters: frames must be byte-identical to the Rust
relay-ipc encoding (locked by canonical_hello_frame_bytes_are_stable).
"""

from datetime import datetime, timezone

import cbor2

MAX_FRAME = 16 * 1024 * 1024
PROTOCOL_VERSION = 1


def write_frame(fileobj, obj):
    body = cbor2.dumps(obj)
    if len(body) > MAX_FRAME:
        raise ValueError(f"frame {len(body)} B exceeds MAX_FRAME")
    fileobj.write(len(body).to_bytes(4, "big") + body)
    fileobj.flush()


def _read_exact(fileobj, n):
    data = b""
    while len(data) < n:
        chunk = fileobj.read(n - len(data))
        if not chunk:
            raise EOFError("daemon connection closed")
        data += chunk
    return data


def read_frame(fileobj):
    length = int.from_bytes(_read_exact(fileobj, 4), "big")
    if length > MAX_FRAME:
        raise ValueError(f"frame {length} B exceeds MAX_FRAME")
    return cbor2.loads(_read_exact(fileobj, length))


def capabilities(**overrides):
    caps = {
        "text": True, "direct_messages": False, "groups": False,
        "attachments": False, "location": False, "reactions": False,
        "receipts": False, "presence": False, "max_payload": None,
    }
    caps.update(overrides)
    return caps


def hello(plugin, version, caps):
    return {"t": "hello", "plugin": plugin, "version": version,
            "protocol_version": PROTOCOL_VERSION, "capabilities": caps}


def attachment(filename, mime, data):
    """Create an attachment dict for inbound frames.

    Args:
        filename: attachment filename
        mime: MIME type string
        data: bytes payload (encoded as CBOR byte string)

    Returns:
        dict with filename, mime, data keys
    """
    return {"filename": filename, "mime": mime, "data": data}


def inbound(endpoint, sender, body, created_at_epoch=None, *, attachments=None, priority=None):
    created = None
    if created_at_epoch is not None:
        try:
            created = (datetime.fromtimestamp(created_at_epoch, timezone.utc)
                       .isoformat().replace("+00:00", "Z"))
        except (OverflowError, OSError, ValueError):
            # sender-controlled timestamp out of range (e.g. 1e300); bridge
            # the message anyway and let the daemon stamp receive time.
            created = None
    return {"t": "inbound", "endpoint": endpoint, "sender": sender,
            "kind": "text", "body": body, "created_at": created,
            "attachments": attachments or [], "priority": priority}


def delivery_result(corr, delivered, detail=None):
    return {"t": "delivery_result", "corr": corr, "delivered": delivered,
            "detail": detail}


def gauges(values):
    """Create a Gauges frame (design §3, cycle D) from a dict of gauge name
    -> numeric value.

    Mirrors the Rust side's `PluginToDaemon::Gauges { gauges: BTreeMap<String,
    f64> }`: keys are sorted here too, so a frame built from the same
    name/value set on either side of the wire encodes identically. Values are
    coerced to float (BTreeMap<String, f64> on the Rust side has no integer
    variant). Name sanitization and the 32-gauge cap are enforced daemon-side
    on receipt, not here.
    """
    return {"t": "gauges", "gauges": {k: float(values[k]) for k in sorted(values)}}


def pong():
    """Reply to a daemon Ping (liveness probe). The daemon restarts a
    connected plugin that stops answering, so a healthy plugin must respond
    promptly -- see relay_ipc PluginToDaemon::Pong."""
    return {"t": "pong"}
