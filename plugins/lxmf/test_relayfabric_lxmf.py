import io
import os
import shutil
import stat
import tempfile
import threading
import types
import unittest

import media
import relayfabric_lxmf as plug

try:
    from PIL import Image
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

try:
    import pycodec2
    HAVE_PYCODEC2 = True
except ImportError:
    HAVE_PYCODEC2 = False

HAVE_FFMPEG = shutil.which("ffmpeg") is not None

CFG = {
    "storage": "/tmp/rf-lxmf-test",
    "channels": [
        {"name": "pasadena", "members": ["A91D00AA"], "open": False},
        {"name": "lounge", "members": [], "open": True},
    ],
}


class ConfigTests(unittest.TestCase):
    def test_defaults_and_normalization(self):
        cfg = plug.load_config(CFG)
        self.assertEqual(cfg["announce_interval"], 3600)
        self.assertIsNone(cfg["stamp_cost"])
        self.assertEqual(cfg["channels"][0]["members"], ["a91d00aa"])
        self.assertFalse(cfg["channels"][0]["open"])

    def test_attachment_defaults(self):
        cfg = plug.load_config(CFG)
        self.assertEqual(cfg["max_attachment_bytes"], 1_000_000)
        self.assertIsNone(cfg["image_max_bytes"])
        self.assertIsNone(cfg["voice_to_codec2"])
        self.assertEqual(cfg["lxmf_delivery_limit_kb"], 8192)

    def test_attachment_config_overridable(self):
        cfg = plug.load_config(dict(CFG, max_attachment_bytes=42,
                                     image_max_bytes=7, voice_to_codec2=1200,
                                     lxmf_delivery_limit_kb=256))
        self.assertEqual(cfg["max_attachment_bytes"], 42)
        self.assertEqual(cfg["image_max_bytes"], 7)
        self.assertEqual(cfg["voice_to_codec2"], 1200)
        self.assertEqual(cfg["lxmf_delivery_limit_kb"], 256)

    def test_missing_storage_rejected(self):
        with self.assertRaises(ValueError):
            plug.load_config({"channels": []})

    def test_channel_without_name_rejected(self):
        with self.assertRaises(ValueError):
            plug.load_config({"storage": "/x", "channels": [{"members": []}]})


class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.cfg = plug.load_config(CFG)

    def test_member_lookup_config_and_dynamic(self):
        self.assertEqual(
            plug.channel_for_member(self.cfg, "a91d00aa", {})["name"], "pasadena")
        self.assertIsNone(plug.channel_for_member(self.cfg, "ffff0000", {}))
        dyn = {"lounge": ["ffff0000"]}
        self.assertEqual(
            plug.channel_for_member(self.cfg, "ffff0000", dyn)["name"], "lounge")

    def test_channel_members_merges_without_dupes(self):
        ch = plug.channel_by_name(self.cfg, "pasadena")
        dyn = {"pasadena": ["a91d00aa", "bbbb1111"]}
        self.assertEqual(plug.channel_members(ch, dyn), ["a91d00aa", "bbbb1111"])


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.cfg = plug.load_config(CFG)
        self.dyn = {}

    def test_join_open_channel(self):
        reply, changed = plug.command_reply(self.cfg, self.dyn, "cccc2222", "/join lounge")
        self.assertIn("Joined", reply)
        self.assertTrue(changed)
        self.assertIn("cccc2222", self.dyn["lounge"])

    def test_join_closed_channel_denied(self):
        reply, changed = plug.command_reply(self.cfg, self.dyn, "cccc2222", "/join pasadena")
        self.assertIn("closed", reply)
        self.assertFalse(changed)

    def test_join_unknown_and_double_join(self):
        reply, _ = plug.command_reply(self.cfg, self.dyn, "c1", "/join nope")
        self.assertIn("No such channel", reply)
        plug.command_reply(self.cfg, self.dyn, "c1", "/join lounge")
        reply, changed = plug.command_reply(self.cfg, self.dyn, "c1", "/join lounge")
        self.assertIn("Already", reply)
        self.assertFalse(changed)

    def test_leave_paths(self):
        plug.command_reply(self.cfg, self.dyn, "c1", "/join lounge")
        reply, changed = plug.command_reply(self.cfg, self.dyn, "c1", "/leave lounge")
        self.assertIn("Left", reply)
        self.assertTrue(changed)
        reply, changed = plug.command_reply(self.cfg, self.dyn, "a91d00aa", "/leave pasadena")
        self.assertIn("operator", reply)
        self.assertFalse(changed)

    def test_channels_listing_and_usage(self):
        reply, _ = plug.command_reply(self.cfg, self.dyn, "a91d00aa", "/channels")
        self.assertIn("pasadena (member)", reply)
        self.assertIn("lounge (open)", reply)
        reply, _ = plug.command_reply(self.cfg, self.dyn, "a91d00aa", "/bogus")
        self.assertIn("/join", reply)


class FanoutTests(unittest.TestCase):
    def test_delivered_when_any_member_succeeds(self):
        t = plug.FanoutTracker(corr=7, members=["a", "b", "c"])
        self.assertIsNone(t.member_done("a", True))
        self.assertIsNone(t.member_done("b", False))
        result = t.member_done("c", False)
        self.assertEqual(result["corr"], 7)
        self.assertTrue(result["delivered"])
        self.assertIn("b", result["detail"])
        self.assertIn("c", result["detail"])

    def test_all_failures_reports_undelivered(self):
        t = plug.FanoutTracker(corr=8, members=["a"])
        result = t.member_done("a", False)
        self.assertFalse(result["delivered"])

    def test_double_fire_reports_result_exactly_once(self):
        t = plug.FanoutTracker(corr=9, members=["a"])
        result = t.member_done("a", True)
        self.assertIsNotNone(result)
        self.assertTrue(result["delivered"])
        # a buggy double-fired callback for the same (already-terminal)
        # member must not produce a second result frame
        self.assertIsNone(t.member_done("a", True))
        self.assertIsNone(t.member_done("a", False))


class HardenStorageTests(unittest.TestCase):
    def test_tightens_dir_and_identity_perms(self):
        storage = tempfile.mkdtemp()
        try:
            os.chmod(storage, 0o755)
            identity_path = os.path.join(storage, "identity")
            with open(identity_path, "w") as f:
                f.write("dummy-key-bytes")
            os.chmod(identity_path, 0o644)

            plug._harden_storage(storage, identity_path)

            self.assertEqual(stat.S_IMODE(os.stat(storage).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(identity_path).st_mode), 0o600)
        finally:
            shutil.rmtree(storage)

    def test_missing_identity_file_is_a_noop(self):
        storage = tempfile.mkdtemp()
        try:
            os.chmod(storage, 0o755)
            identity_path = os.path.join(storage, "identity")

            plug._harden_storage(storage, identity_path)  # must not raise

            self.assertEqual(stat.S_IMODE(os.stat(storage).st_mode), 0o700)
            self.assertFalse(os.path.exists(identity_path))
        finally:
            shutil.rmtree(storage)


class AttachmentFieldsTests(unittest.TestCase):
    """attachment_fields: egress (daemon attachments -> LXMF fields)."""

    def test_first_image_inline_rest_as_files_oversize_dropped(self):
        fields, notes = plug.attachment_fields(
            [("a.png", "image/png", b"img1"),
             ("b.jpg", "image/jpeg", b"img2"),
             ("notes.txt", "text/plain", b"doc"),
             ("big.bin", "application/x", b"x" * 20)],
            10)
        self.assertEqual(fields[media.FIELD_IMAGE], ["png", b"img1"])
        self.assertEqual(fields[media.FIELD_FILE_ATTACHMENTS],
                         [["b.jpg", b"img2"], ["notes.txt", b"doc"]])
        self.assertEqual(notes, ["[dropped big.bin: 20 B over 10 B limit]"])

    def test_empty_loaded_returns_empty(self):
        self.assertEqual(plug.attachment_fields([], 10), ({}, []))

    def test_undecodable_image_over_cap_drops_with_note(self):
        _, notes = plug.attachment_fields([("x.png", "image/png", b"z" * 30)], 10)
        self.assertIn("dropped x.png", notes[0])

    @unittest.skipUnless(HAVE_PIL, "Pillow not installed")
    def test_large_image_shrinks_to_fit_image_budget(self):
        buf = io.BytesIO()
        Image.frombytes(
            "RGB", (600, 600), os.urandom(600 * 600 * 3)).save(buf, "PNG")
        big_png = buf.getvalue()
        self.assertGreater(len(big_png), 10000)

        fields, notes = plug.attachment_fields(
            [("photo.png", "image/png", big_png)], 1000000,
            image_max_bytes=10000)

        fmt, data = fields[media.FIELD_IMAGE]
        self.assertEqual(fmt, "webp")
        self.assertLessEqual(len(data), 10000)
        self.assertEqual(notes, [])

    @unittest.skipUnless(HAVE_PYCODEC2 and HAVE_FFMPEG,
                         "pycodec2 and/or ffmpeg not available")
    def test_voice_to_codec2_transcodes_audio_attachment(self):
        frame = bytes(pycodec2.Codec2(1200).bytes_per_frame())
        wav = media.codec2_to_wav(media.AM_CODEC2_1200, frame)
        self.assertIsNotNone(wav)

        fields, _ = plug.attachment_fields(
            [("v.m4a", "audio/mp4", wav)], 100000, voice_codec2_bitrate=2400)

        self.assertEqual(fields[media.FIELD_AUDIO][0], media.AM_CODEC2_2400)


class LxmfAttachmentsTests(unittest.TestCase):
    """lxmf_attachments: inbound (LXMF fields -> daemon attachments)."""

    def test_extraction_and_size_cap(self):
        kept, notes = plug.lxmf_attachments(
            {media.FIELD_IMAGE: ["webp", b"12345"],
             media.FIELD_FILE_ATTACHMENTS: [["big.bin", b"123456789"]]}, 5)
        self.assertEqual(kept, [("image.webp", b"12345")])
        self.assertEqual(notes, ["[dropped big.bin: 9 B over 5 B limit]"])

    def test_opus_audio_becomes_playable_ogg(self):
        kept, _ = plug.lxmf_attachments(
            {media.FIELD_AUDIO: [media.AM_OPUS_OGG, b"OGGDATA"]}, 100)
        self.assertEqual(kept, [("voice.ogg", b"OGGDATA")])

    def test_undecodable_codec2_audio_passes_through_raw(self):
        kept, _ = plug.lxmf_attachments(
            {media.FIELD_AUDIO: [media.AM_CODEC2_1200, b"C2"]}, 100)
        self.assertEqual(kept, [("voice.c2", b"C2")])

    def test_none_fields_returns_empty(self):
        self.assertEqual(plug.lxmf_attachments(None, 5), ([], []))

    def test_path_traversal_name_is_basenamed(self):
        kept, _ = plug.lxmf_attachments(
            {media.FIELD_FILE_ATTACHMENTS: [["../evil", b"x"]]}, 5)
        self.assertEqual(kept, [("evil", b"x")])

    @unittest.skipUnless(HAVE_PIL, "Pillow not installed")
    def test_oversize_image_shrinks_instead_of_dropping(self):
        buf = io.BytesIO()
        Image.frombytes(
            "RGB", (600, 600), os.urandom(600 * 600 * 3)).save(buf, "PNG")
        big_png = buf.getvalue()

        kept, notes = plug.lxmf_attachments(
            {media.FIELD_IMAGE: ["png", big_png]}, 10000)

        self.assertEqual(notes, [])
        self.assertEqual(kept[0][0], "image.webp")
        self.assertLessEqual(len(kept[0][1]), 10000)

    @unittest.skipUnless(HAVE_PYCODEC2 and HAVE_FFMPEG,
                         "pycodec2 and/or ffmpeg not available")
    def test_codec2_frame_transcodes_to_wav(self):
        frame = bytes(pycodec2.Codec2(1200).bytes_per_frame())
        kept, _ = plug.lxmf_attachments(
            {media.FIELD_AUDIO: [media.AM_CODEC2_1200, frame]}, 100000)
        self.assertEqual(kept[0][0], "voice.wav")


class _ImmediatePool:
    """Stand-in for ThreadPoolExecutor that runs submissions synchronously."""

    def submit(self, fn, *args, **kwargs):
        fn(*args, **kwargs)


def _bare_bridge(cfg):
    """A Bridge with __init__ (RNS/LXMF stack setup) skipped, for testing
    the attachment-wiring logic in _handle_lxmf/handle_send/send_lxmf in
    isolation. write_lock/pool/dynamic_members are the only pieces those
    methods touch besides cfg.
    """
    bridge = plug.Bridge.__new__(plug.Bridge)
    bridge.cfg = cfg
    bridge.dynamic_members = {}
    bridge.write_lock = threading.Lock()
    bridge.pool = _ImmediatePool()
    return bridge


class FakeSock:
    """Captures frames the bridge writes to the daemon.

    Copied from plugins/signal/test_relayfabric_signal.py's FakeSock (same
    pattern across the plugin test suites): exercises the real _send_frame/
    write_lock path instead of stubbing it out.
    """

    def __init__(self):
        import io
        self.buf = io.BytesIO()

    def write(self, data):
        self.buf.write(data)

    def flush(self):
        pass

    def frames(self):
        import io

        import relay_ipc
        out, rd = [], io.BytesIO(self.buf.getvalue())
        while True:
            try:
                out.append(relay_ipc.read_frame(rd))
            except EOFError:
                return out


def _bare_bridge_with_sock(cfg):
    """Like _bare_bridge, but with a real wfile (FakeSock) instead of a
    stubbed _send_frame, for tests that want to assert on the actual wire
    frames written under the write lock.
    """
    bridge = plug.Bridge.__new__(plug.Bridge)
    bridge.cfg = cfg
    bridge.dynamic_members = {}
    bridge.write_lock = threading.Lock()
    bridge.pool = _ImmediatePool()
    sock = FakeSock()
    bridge.wfile = sock
    return bridge, sock


class BridgeInboundAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.cfg = plug.load_config(CFG)
        self.bridge = _bare_bridge(self.cfg)
        self.sent = []
        self.bridge._send_frame = self.sent.append

    def _message(self, content=b"", fields=None, timestamp=1700000000):
        return types.SimpleNamespace(
            source_hash=bytes.fromhex("a91d00aa"),
            content=content,
            signature_validated=True,
            timestamp=timestamp,
            fields=fields or {},
        )

    def test_attachment_only_message_bridges_with_no_text(self):
        message = self._message(
            content=b"", fields={media.FIELD_IMAGE: ["png", b"img-bytes"]})

        self.bridge._handle_lxmf(message)

        self.assertEqual(len(self.sent), 1)
        frame = self.sent[0]
        self.assertEqual(frame["body"], "")
        self.assertEqual(len(frame["attachments"]), 1)
        att = frame["attachments"][0]
        self.assertEqual(att["filename"], "image.png")
        self.assertEqual(att["mime"], "image/png")
        self.assertEqual(att["data"], b"img-bytes")

    def test_truly_empty_message_does_not_bridge(self):
        message = self._message(content=b"", fields={})

        self.bridge._handle_lxmf(message)

        self.assertEqual(self.sent, [])

    def test_drop_note_appended_to_body(self):
        message = self._message(
            content=b"hello",
            fields={media.FIELD_FILE_ATTACHMENTS: [["big.bin", b"x" * 20]]})
        self.bridge.cfg = dict(self.cfg, max_attachment_bytes=10)

        self.bridge._handle_lxmf(message)

        frame = self.sent[0]
        self.assertIn("hello", frame["body"])
        self.assertIn("[dropped big.bin: 20 B over 10 B limit]", frame["body"])
        self.assertEqual(frame["attachments"], [])

    def test_unknown_extension_falls_back_to_octet_stream(self):
        message = self._message(
            content=b"file",
            fields={media.FIELD_FILE_ATTACHMENTS: [["data.rfblob", b"xyz"]]})

        self.bridge._handle_lxmf(message)

        att = self.sent[0]["attachments"][0]
        self.assertEqual(att["mime"], "application/octet-stream")

    def test_non_member_sender_still_drops_regardless_of_attachments(self):
        message = types.SimpleNamespace(
            source_hash=bytes.fromhex("ffff0000"),
            content=b"",
            signature_validated=True,
            timestamp=1700000000,
            fields={media.FIELD_IMAGE: ["png", b"img"]},
        )

        self.bridge._handle_lxmf(message)

        self.assertEqual(self.sent, [])


class BridgeEgressAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.cfg = plug.load_config(CFG)
        self.bridge = _bare_bridge(self.cfg)
        self.sent = []
        self.bridge._send_frame = self.sent.append
        self.send_calls = []

        def fake_send_lxmf(dest_hex, text, on_result=None, method=None, fields=None):
            self.send_calls.append(
                {"dest": dest_hex, "text": text, "fields": fields})
            if on_result:
                on_result(True)

        self.bridge.send_lxmf = fake_send_lxmf

    def test_attachments_become_fields_kwarg_on_send(self):
        attachments = [{"filename": "a.png", "mime": "image/png", "data": b"img1"}]

        self.bridge.handle_send(1, "pasadena", "look", attachments)

        self.assertEqual(len(self.send_calls), 1)
        call = self.send_calls[0]
        self.assertEqual(call["fields"][media.FIELD_IMAGE], ["png", b"img1"])
        self.assertEqual(call["text"], "look")

    def test_drop_notes_appended_to_outgoing_text(self):
        attachments = [{"filename": "big.bin",
                        "mime": "application/octet-stream", "data": b"x" * 20}]
        self.bridge.cfg = dict(self.cfg, max_attachment_bytes=10)

        self.bridge.handle_send(1, "pasadena", "look", attachments)

        call = self.send_calls[0]
        self.assertIn("look", call["text"])
        self.assertIn("[dropped big.bin: 20 B over 10 B limit]", call["text"])
        self.assertIsNone(call["fields"])

    def test_no_attachments_passes_none_fields(self):
        self.bridge.handle_send(1, "pasadena", "hello", None)

        call = self.send_calls[0]
        self.assertIsNone(call["fields"])
        self.assertEqual(call["text"], "hello")


class SendDirectTests(unittest.TestCase):
    """handle_send_direct: a single one-shot direct send, no FanoutTracker
    (that's for channel fan-out). FakeSock-driven so the real _send_frame/
    write_lock path is exercised, not stubbed.
    """

    def setUp(self):
        self.cfg = plug.load_config(CFG)
        self.bridge, self.sock = _bare_bridge_with_sock(self.cfg)
        self.send_calls = []

    def _stub_send_lxmf(self, outcome):
        def fake(dest_hex, text, on_result=None, method=None, fields=None):
            self.send_calls.append({"dest": dest_hex, "text": text})
            if on_result:
                on_result(outcome)
        self.bridge.send_lxmf = fake

    def test_valid_ref_calls_send_lxmf_and_reports_delivered(self):
        self._stub_send_lxmf(True)

        self.bridge.handle_send_direct(11, "a91d00aa", "verification code: 042817")

        self.assertEqual(self.send_calls,
                          [{"dest": "a91d00aa", "text": "verification code: 042817"}])
        frames = self.sock.frames()
        self.assertEqual(frames[-1],
                          {"t": "delivery_result", "corr": 11,
                           "delivered": True, "detail": None})

    def test_valid_ref_failure_callback_reports_failed(self):
        self._stub_send_lxmf(False)

        self.bridge.handle_send_direct(12, "a91d00aa", "x")

        frames = self.sock.frames()
        self.assertEqual(frames[-1]["corr"], 12)
        self.assertFalse(frames[-1]["delivered"])

    def test_invalid_ref_reports_failed_immediately_without_sending(self):
        self._stub_send_lxmf(True)

        self.bridge.handle_send_direct(13, "not-a-hex-ref!", "x")

        self.assertEqual(self.send_calls, [])
        frames = self.sock.frames()
        self.assertEqual(frames[-1],
                          {"t": "delivery_result", "corr": 13,
                           "delivered": False, "detail": "invalid destination ref"})

    def test_empty_ref_is_invalid(self):
        self._stub_send_lxmf(True)

        self.bridge.handle_send_direct(14, "", "x")

        self.assertEqual(self.send_calls, [])
        self.assertFalse(self.sock.frames()[-1]["delivered"])


if __name__ == "__main__":
    unittest.main()
