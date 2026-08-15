"""RelayFabric Signal plugin: bridges Signal groups over Plugin Protocol v1
via a signal-cli JSON-RPC/SSE daemon."""

import threading
import time


def load_config(raw):
    cfg = dict(raw)
    if not cfg.get("account"):
        raise ValueError("config requires 'account'")
    if not cfg.get("groups"):
        raise ValueError("config requires a non-empty 'groups' mapping")
    cfg["groups"] = dict(cfg["groups"])
    cfg.setdefault("rpc_url", "http://127.0.0.1:7583")
    cfg.setdefault("allowed_users", None)
    return cfg


def parse_signal_event(event, own_account):
    envelope = event.get("envelope") or {}
    data = envelope.get("dataMessage")
    sync = data is None
    if sync:
        data = (envelope.get("syncMessage") or {}).get("sentMessage") or {}
    text = data.get("message") or ""
    if not text:
        return None
    source = (envelope.get("sourceUuid")
              or envelope.get("sourceNumber")
              or envelope.get("source"))
    if source is None:
        return None
    if not sync and (envelope.get("sourceNumber") == own_account
                     or envelope.get("source") == own_account):
        return None
    group_id = (data.get("groupInfo") or {}).get("groupId")
    return source, group_id, text, envelope.get("timestamp")


class SentCache:
    """Loop guard for linked-device sync echoes of our own bridged posts."""

    def __init__(self, ttl_secs=86400):
        self.ttl = ttl_secs
        self._entries = {}
        self._lock = threading.Lock()

    def record(self, group_id, text, now=None):
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            self._entries[(group_id, text)] = now

    def match(self, group_id, text, now=None):
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            return self._entries.pop((group_id, text), None) is not None

    def _prune(self, now):
        # ponytail: O(n) prune per call, fine at gateway volumes
        for key in [k for k, t in self._entries.items() if now - t > self.ttl]:
            del self._entries[key]
