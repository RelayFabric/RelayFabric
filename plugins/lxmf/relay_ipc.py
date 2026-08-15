"""RelayFabric Plugin Protocol v1 codec: 4-byte BE length prefix + CBOR.

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


def inbound(endpoint, sender, body, created_at_epoch=None):
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
            "kind": "text", "body": body, "created_at": created}


def delivery_result(corr, delivered, detail=None):
    return {"t": "delivery_result", "corr": corr, "delivered": delivered,
            "detail": detail}
