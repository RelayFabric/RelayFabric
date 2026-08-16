import io
import os
import shutil
import unittest

import media

try:
    from PIL import Image  # noqa: F401
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

try:
    import pycodec2  # noqa: F401
    HAVE_PYCODEC2 = True
except ImportError:
    HAVE_PYCODEC2 = False

try:
    import LXMF  # noqa: F401
    HAVE_LXMF = True
except ImportError:
    HAVE_LXMF = False

HAVE_FFMPEG = shutil.which("ffmpeg") is not None


class ShrinkImageTests(unittest.TestCase):
    def test_undecodable_bytes_returns_none(self):
        # PIL missing -> ImportError caught early; PIL present -> Image.open
        # raises on garbage bytes. Either way, None -- so this needs no skip.
        self.assertIsNone(media.shrink_image(b"not an image", 1000))

    @unittest.skipUnless(HAVE_PIL, "Pillow not installed")
    def test_shrinks_large_image_under_budget(self):
        from PIL import Image

        buf = io.BytesIO()
        Image.frombytes(
            "RGB", (600, 600), os.urandom(600 * 600 * 3)).save(buf, "PNG")
        big_png = buf.getvalue()
        self.assertGreater(len(big_png), 10000)

        result = media.shrink_image(big_png, 10000)

        self.assertIsNotNone(result)
        self.assertLessEqual(len(result), 10000)
        decoded = Image.open(io.BytesIO(result))
        self.assertEqual(decoded.format, "WEBP")


class LXMFConstantTests(unittest.TestCase):
    """media.py can't import LXMF at module top level, so the field/audio-
    mode identifiers are inlined as literals. These tests, when lxmf is
    installed, guard against the literals drifting from the real constants.
    """

    @unittest.skipUnless(HAVE_LXMF, "lxmf not installed")
    def test_field_literals_match_lxmf(self):
        import LXMF

        self.assertEqual(media.FIELD_IMAGE, LXMF.FIELD_IMAGE)
        self.assertEqual(media.FIELD_AUDIO, LXMF.FIELD_AUDIO)
        self.assertEqual(
            media.FIELD_FILE_ATTACHMENTS, LXMF.FIELD_FILE_ATTACHMENTS)

    @unittest.skipUnless(HAVE_LXMF, "lxmf not installed")
    def test_codec2_mode_literals_match_lxmf(self):
        import LXMF

        self.assertEqual(media.AM_CODEC2_450PWB, LXMF.AM_CODEC2_450PWB)
        self.assertEqual(media.AM_CODEC2_450, LXMF.AM_CODEC2_450)
        self.assertEqual(media.AM_CODEC2_700C, LXMF.AM_CODEC2_700C)
        self.assertEqual(media.AM_CODEC2_1200, LXMF.AM_CODEC2_1200)
        self.assertEqual(media.AM_CODEC2_1300, LXMF.AM_CODEC2_1300)
        self.assertEqual(media.AM_CODEC2_1400, LXMF.AM_CODEC2_1400)
        self.assertEqual(media.AM_CODEC2_1600, LXMF.AM_CODEC2_1600)
        self.assertEqual(media.AM_CODEC2_2400, LXMF.AM_CODEC2_2400)
        self.assertEqual(media.AM_CODEC2_3200, LXMF.AM_CODEC2_3200)
        self.assertEqual(media.AM_OPUS_OGG, LXMF.AM_OPUS_OGG)

    @unittest.skipUnless(HAVE_LXMF, "lxmf not installed")
    def test_tables_match_lxmf_built_equivalents(self):
        import LXMF

        expected_bitrates = {
            LXMF.AM_CODEC2_450PWB: 450, LXMF.AM_CODEC2_450: 450,
            LXMF.AM_CODEC2_700C: 700, LXMF.AM_CODEC2_1200: 1200,
            LXMF.AM_CODEC2_1300: 1300, LXMF.AM_CODEC2_1400: 1400,
            LXMF.AM_CODEC2_1600: 1600, LXMF.AM_CODEC2_2400: 2400,
            LXMF.AM_CODEC2_3200: 3200,
        }
        expected_am_for_bitrate = {
            450: LXMF.AM_CODEC2_450, 700: LXMF.AM_CODEC2_700C,
            1200: LXMF.AM_CODEC2_1200, 1300: LXMF.AM_CODEC2_1300,
            1400: LXMF.AM_CODEC2_1400, 1600: LXMF.AM_CODEC2_1600,
            2400: LXMF.AM_CODEC2_2400, 3200: LXMF.AM_CODEC2_3200,
        }
        self.assertEqual(media.CODEC2_BITRATES, expected_bitrates)
        self.assertEqual(media.AM_FOR_BITRATE, expected_am_for_bitrate)


class TranscodeTests(unittest.TestCase):
    @unittest.skipUnless(
        HAVE_PYCODEC2 and HAVE_FFMPEG, "pycodec2 and/or ffmpeg not available")
    def test_codec2_wav_roundtrip(self):
        import pycodec2

        frame = bytes(pycodec2.Codec2(1200).bytes_per_frame())
        wav = media.codec2_to_wav(media.AM_CODEC2_1200, frame)
        self.assertIsNotNone(wav)
        self.assertGreater(len(wav), 0)
        self.assertEqual(wav[:4], b"RIFF")

        encoded = media.audio_to_codec2(wav, 2400)
        self.assertIsNotNone(encoded)
        self.assertGreater(len(encoded), 0)

    def test_codec2_to_wav_none_when_deps_missing(self):
        if HAVE_PYCODEC2:
            self.skipTest("pycodec2 installed; None-fallback path not exercised")
        self.assertIsNone(
            media.codec2_to_wav(media.AM_CODEC2_1200, b"\x00" * 100))

    def test_audio_to_codec2_none_when_deps_missing(self):
        if HAVE_PYCODEC2:
            self.skipTest("pycodec2 installed; None-fallback path not exercised")
        self.assertIsNone(media.audio_to_codec2(b"not audio", 2400))

    def test_audio_to_codec2_unknown_bitrate_returns_none(self):
        self.assertIsNone(media.audio_to_codec2(b"anything", 99999))

    def test_codec2_to_wav_unknown_mode_returns_none(self):
        self.assertIsNone(media.codec2_to_wav(0xFE, b"anything"))


class AttachmentSigTests(unittest.TestCase):
    def test_two_tuple(self):
        self.assertEqual(media.attachment_sig([("a", b"xx")]), "|a:2")

    def test_three_tuple_uses_name_first_data_last(self):
        self.assertEqual(media.attachment_sig([("a", "ct", b"xx")]), "|a:2")

    def test_empty_list(self):
        self.assertEqual(media.attachment_sig([]), "")

    def test_multiple_items_are_order_sensitive(self):
        self.assertEqual(
            media.attachment_sig([("a", b"x"), ("b", b"yy")]), "|a:1|b:2")


if __name__ == "__main__":
    unittest.main()
