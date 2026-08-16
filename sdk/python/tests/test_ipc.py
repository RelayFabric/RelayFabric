import io
import unittest

from relayfabric_sdk import FakeSock
from relayfabric_sdk import ipc as relay_ipc

CANONICAL_HELLO_HEX = "000000a5a561746568656c6c6f66706c7567696e646c786d666776657273696f6e65302e312e307070726f746f636f6c5f76657273696f6e016c6361706162696c6974696573a96474657874f56f6469726563745f6d65737361676573f56667726f757073f56b6174746163686d656e7473f4686c6f636174696f6ef4697265616374696f6e73f4687265636569707473f46870726573656e6365f46b6d61785f7061796c6f6164f6"

CANONICAL_INBOUND_ATTACHMENT_HEX = "0000008fa8617467696e626f756e6468656e64706f696e74646368616e6673656e6465726173646b696e64647465787464626f64796268696a637265617465645f6174f66b6174746163686d656e747381a36866696c656e616d6565612e62696e646d696d6578186170706c69636174696f6e2f6f637465742d73747265616d646461746143010203687072696f72697479f6"


class CodecTests(unittest.TestCase):
    def test_roundtrip(self):
        buf = io.BytesIO()
        msg = relay_ipc.delivery_result(42, True)
        relay_ipc.write_frame(buf, msg)
        buf.seek(0)
        self.assertEqual(relay_ipc.read_frame(buf), msg)

    def test_matches_rust_canonical_hello(self):
        buf = io.BytesIO()
        relay_ipc.write_frame(
            buf,
            relay_ipc.hello(
                "lxmf", "0.1.0",
                relay_ipc.capabilities(direct_messages=True, groups=True),
            ),
        )
        self.assertEqual(buf.getvalue().hex(), CANONICAL_HELLO_HEX)

    def test_oversize_rejected_both_ways(self):
        buf = io.BytesIO()
        with self.assertRaises(ValueError):
            relay_ipc.write_frame(buf, {"t": "inbound", "body": "x" * (17 * 1024 * 1024)})
        hdr = (relay_ipc.MAX_FRAME + 1).to_bytes(4, "big")
        with self.assertRaises(ValueError):
            relay_ipc.read_frame(io.BytesIO(hdr))

    def test_eof_raises(self):
        with self.assertRaises(EOFError):
            relay_ipc.read_frame(io.BytesIO(b""))
        with self.assertRaises(EOFError):
            relay_ipc.read_frame(io.BytesIO(b"\x00\x00\x00\x10short"))

    def test_inbound_bogus_timestamp_falls_back_to_none(self):
        msg = relay_ipc.inbound("pasadena", "a91d00aa", "hello", 1e300)
        self.assertIsNone(msg["created_at"])
        self.assertEqual(msg["body"], "hello")
        self.assertEqual(msg["endpoint"], "pasadena")
        self.assertEqual(msg["sender"], "a91d00aa")

    def test_inbound_valid_timestamp_sets_created_at(self):
        msg = relay_ipc.inbound("pasadena", "a91d00aa", "hello", 0)
        self.assertEqual(msg["created_at"], "1970-01-01T00:00:00Z")

    def test_attachment_builder(self):
        att = relay_ipc.attachment("a.bin", "application/octet-stream", b"\x01\x02\x03")
        self.assertEqual(att["filename"], "a.bin")
        self.assertEqual(att["mime"], "application/octet-stream")
        self.assertEqual(att["data"], b"\x01\x02\x03")

    def test_inbound_no_attachments_backward_compat(self):
        # Existing callers without attachments should emit empty list
        msg = relay_ipc.inbound("chan", "s", "hi")
        self.assertEqual(msg["attachments"], [])

    def test_inbound_no_priority_backward_compat(self):
        # Existing callers without priority still get the key, defaulted to
        # None — the daemon normalizes a missing/unrecognized class to
        # "normal" itself, so the plugin need not know the class list.
        msg = relay_ipc.inbound("chan", "s", "hi")
        self.assertIn("priority", msg)
        self.assertIsNone(msg["priority"])

    def test_inbound_with_priority_passes_through(self):
        msg = relay_ipc.inbound("chan", "s", "hi", priority="emergency")
        self.assertEqual(msg["priority"], "emergency")

    def test_inbound_with_attachments_roundtrip(self):
        # Roundtrip with attachments
        buf = io.BytesIO()
        att = relay_ipc.attachment("a.bin", "application/octet-stream", b"\x01\x02\x03")
        msg = relay_ipc.inbound("chan", "s", "hi", attachments=[att])
        relay_ipc.write_frame(buf, msg)
        buf.seek(0)
        decoded = relay_ipc.read_frame(buf)
        self.assertEqual(decoded["attachments"], [att])
        self.assertEqual(decoded["body"], "hi")

    def test_send_direct_frame_roundtrips(self):
        # SendDirect is daemon->plugin only; plugins never build/emit it
        # (no relay_ipc helper for it), only read it off the wire.
        buf = io.BytesIO()
        msg = {"t": "send_direct", "corr": 17, "native_ref": "a91d00aa",
               "body": "verification code"}
        relay_ipc.write_frame(buf, msg)
        buf.seek(0)
        self.assertEqual(relay_ipc.read_frame(buf), msg)

    def test_matches_rust_canonical_inbound_attachment(self):
        # Golden test: must byte-match Rust canonical encoding
        buf = io.BytesIO()
        att = relay_ipc.attachment("a.bin", "application/octet-stream", b"\x01\x02\x03")
        msg = relay_ipc.inbound("chan", "s", "hi", attachments=[att])
        relay_ipc.write_frame(buf, msg)
        self.assertEqual(buf.getvalue().hex(), CANONICAL_INBOUND_ATTACHMENT_HEX)

    def test_gauges_builder_roundtrip(self):
        buf = io.BytesIO()
        msg = relay_ipc.gauges({"rssi": -71, "queue_depth": 3})
        relay_ipc.write_frame(buf, msg)
        buf.seek(0)
        decoded = relay_ipc.read_frame(buf)
        self.assertEqual(decoded, {"t": "gauges",
                                    "gauges": {"queue_depth": 3.0, "rssi": -71.0}})

    def test_gauges_builder_coerces_values_to_float(self):
        msg = relay_ipc.gauges({"queue_depth": 3})
        self.assertIsInstance(msg["gauges"]["queue_depth"], float)

    def test_gauges_builder_sorts_keys_like_a_btreemap(self):
        # Key order must match Rust's BTreeMap<String, f64> iteration order
        # so a frame built here and one built in Rust from the same
        # name/value set encode identically byte-for-byte.
        msg = relay_ipc.gauges({"snr": 1.0, "rssi": -71.0, "queue_depth": 3.0})
        self.assertEqual(list(msg["gauges"].keys()), ["queue_depth", "rssi", "snr"])

    def test_gauges_builder_empty_dict(self):
        msg = relay_ipc.gauges({})
        self.assertEqual(msg, {"t": "gauges", "gauges": {}})


class FakeSockTests(unittest.TestCase):
    """FakeSock exercised against one recorded exchange: a queued Hello
    read followed by a written HelloAck, mirroring the real
    handshake half of a plugin main loop.
    """

    def test_recorded_hello_exchange(self):
        hello_frame = relay_ipc.hello("lxmf", "0.1.0", relay_ipc.capabilities())
        sock = FakeSock(queued_frames=[hello_frame])

        received = relay_ipc.read_frame(sock)
        self.assertEqual(received, hello_frame)
        with self.assertRaises(EOFError):
            relay_ipc.read_frame(sock)

        ack = {"t": "hello_ack", "error": None}
        relay_ipc.write_frame(sock, ack)
        self.assertEqual(sock.frames(), [ack])

    def test_no_queued_frames_is_write_only_capture(self):
        # Default construction matches the old per-plugin FakeSock: no
        # readable frames, just an outbound capture buffer.
        sock = FakeSock()
        with self.assertRaises(EOFError):
            relay_ipc.read_frame(sock)
        relay_ipc.write_frame(sock, {"t": "delivery_result", "corr": 1,
                                     "delivered": True, "detail": None})
        self.assertEqual(sock.frames(),
                         [{"t": "delivery_result", "corr": 1,
                           "delivered": True, "detail": None}])


if __name__ == "__main__":
    unittest.main()
