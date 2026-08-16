"""SentCache: loop guard for echoes of our own bridged posts.

Moved from plugins/signal/relayfabric_signal.py into the SDK. Signal uses
it to catch linked-device sync echoes; meshtastic and meshcore use it
(with a shorter ttl_secs) to catch radio/firmware echoes of their own
downlinked messages.
"""

import threading
import time


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
        # O(n) prune per call, fine at gateway volumes
        for key in [k for k, t in self._entries.items() if now - t > self.ttl]:
            del self._entries[key]
