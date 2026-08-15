import io
import unittest

import relay_ipc

CANONICAL_HELLO_HEX = "000000a5a561746568656c6c6f66706c7567696e646c786d666776657273696f6e65302e312e307070726f746f636f6c5f76657273696f6e016c6361706162696c6974696573a96474657874f56f6469726563745f6d65737361676573f56667726f757073f56b6174746163686d656e7473f4686c6f636174696f6ef4697265616374696f6e73f4687265636569707473f46870726573656e6365f46b6d61785f7061796c6f6164f6"


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


if __name__ == "__main__":
    unittest.main()
