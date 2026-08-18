import unittest

from relayfabric_sdk import FakeSock, SentCache
from relayfabric_sdk.bridge import FrameWriter, capped_text_send


class _Bridge(FrameWriter):
    def __init__(self, sock, publish):
        super().__init__(sock)
        self.cfg = {"channels": {"ch": {"index": 3}}, "max_text_bytes": 10}
        self.sent_cache = SentCache(ttl_secs=60)
        self.publish = publish


SEND = {"t": "send", "corr": "c1", "endpoint": "ch", "body": "hi"}


class FrameWriterTests(unittest.TestCase):
    def test_send_frame_writes_one_frame(self):
        sock = FakeSock()
        FrameWriter(sock)._send_frame({"t": "gauges", "values": {}})
        self.assertEqual(sock.frames(), [{"t": "gauges", "values": {}}])


class CappedTextSendTests(unittest.TestCase):
    def _run(self, frame, publish):
        sock = FakeSock()
        bridge = _Bridge(sock, publish)
        capped_text_send(bridge, frame, "Test", "Test message", bridge.publish)
        return sock.frames(), bridge

    def test_success_delivers_and_records(self):
        published = []
        frames, bridge = self._run(SEND, lambda spec, ep, body: published.append((spec, ep, body)))
        self.assertEqual(published, [({"index": 3}, "ch", "hi")])
        self.assertEqual(frames, [{"t": "delivery_result", "corr": "c1",
                                   "delivered": True, "detail": None}])
        self.assertTrue(bridge.sent_cache.match("ch", "hi"))

    def test_unknown_endpoint_rejected(self):
        frames, bridge = self._run(dict(SEND, endpoint="nope"), lambda *a: None)
        self.assertFalse(frames[0]["delivered"])
        self.assertEqual(frames[0]["detail"], "unknown endpoint")
        self.assertFalse(bridge.sent_cache.match("nope", "hi"))

    def test_oversize_body_rejected(self):
        frames, _ = self._run(dict(SEND, body="x" * 11), lambda *a: None)
        self.assertFalse(frames[0]["delivered"])
        self.assertIn("exceeds max_text_bytes", frames[0]["detail"])

    def test_publish_failure_reported_not_raised(self):
        def boom(spec, ep, body):
            raise RuntimeError("relay down")

        frames, bridge = self._run(SEND, boom)
        self.assertFalse(frames[0]["delivered"])
        self.assertEqual(frames[0]["detail"], "relay down")
        self.assertFalse(bridge.sent_cache.match("ch", "hi"))


if __name__ == "__main__":
    unittest.main()
