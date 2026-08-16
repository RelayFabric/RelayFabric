"""Shared media transforms: image downscaling, LXMF audio-mode tables, and
codec2<->WAV transcoding.

Ported from rns-signal-gateway's gateway.py. Module top level is
stdlib-only (io/logging/subprocess/wave) so this module stays importable
without PIL, pycodec2, numpy, or LXMF installed -- those are imported
inside the functions that need them. Bodies/media bytes are never logged,
only sizes and outcomes.
"""

import io
import logging
import subprocess
import wave

log = logging.getLogger(__name__)


def shrink_image(data, max_bytes):
    """Recompress (and if needed downscale) an image to WebP under max_bytes.

    Returns WebP bytes, or None if Pillow is missing or the data isn't a
    decodable image. Always terminates: dimensions halve each round.
    """
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        img = Image.open(io.BytesIO(data)).convert("RGB")
        while True:
            buf = io.BytesIO()
            img.save(buf, "WEBP", quality=75)
            if buf.tell() <= max_bytes or min(img.size) <= 32:
                return buf.getvalue()
            img = img.resize((max(img.width // 2, 16),
                              max(img.height // 2, 16)))
    except Exception as e:  # noqa: BLE001 - undecodable input falls through
        log.debug("Image downscale failed (%s)", e)
        return None


# LXMF field identifiers that gateway.py reaches for when building/reading
# FIELD_IMAGE / FIELD_AUDIO / FIELD_FILE_ATTACHMENTS. Mirrors LXMF.FIELD_*
# in LXMF/LXMF.py -- kept as literals here so this module never imports
# LXMF at top level. LXMFConstantTests in test_media.py asserts equality
# with the real constants whenever lxmf is installed.
FIELD_FILE_ATTACHMENTS = 0x05  # LXMF.FIELD_FILE_ATTACHMENTS
FIELD_IMAGE = 0x06             # LXMF.FIELD_IMAGE
FIELD_AUDIO = 0x07             # LXMF.FIELD_AUDIO

# LXMF codec2/opus audio-mode identifiers for the data structure in
# FIELD_AUDIO. Mirrors LXMF.AM_CODEC2_* / LXMF.AM_OPUS_OGG in LXMF/LXMF.py.
AM_CODEC2_450PWB = 0x01  # LXMF.AM_CODEC2_450PWB
AM_CODEC2_450 = 0x02     # LXMF.AM_CODEC2_450
AM_CODEC2_700C = 0x03    # LXMF.AM_CODEC2_700C
AM_CODEC2_1200 = 0x04    # LXMF.AM_CODEC2_1200
AM_CODEC2_1300 = 0x05    # LXMF.AM_CODEC2_1300
AM_CODEC2_1400 = 0x06    # LXMF.AM_CODEC2_1400
AM_CODEC2_1600 = 0x07    # LXMF.AM_CODEC2_1600
AM_CODEC2_2400 = 0x08    # LXMF.AM_CODEC2_2400
AM_CODEC2_3200 = 0x09    # LXMF.AM_CODEC2_3200
AM_OPUS_OGG = 0x10       # LXMF.AM_OPUS_OGG

CODEC2_BITRATES = {
    AM_CODEC2_450PWB: 450, AM_CODEC2_450: 450,
    AM_CODEC2_700C: 700, AM_CODEC2_1200: 1200,
    AM_CODEC2_1300: 1300, AM_CODEC2_1400: 1400,
    AM_CODEC2_1600: 1600, AM_CODEC2_2400: 2400,
    AM_CODEC2_3200: 3200,
}

AM_FOR_BITRATE = {
    450: AM_CODEC2_450, 700: AM_CODEC2_700C,
    1200: AM_CODEC2_1200, 1300: AM_CODEC2_1300,
    1400: AM_CODEC2_1400, 1600: AM_CODEC2_1600,
    2400: AM_CODEC2_2400, 3200: AM_CODEC2_3200,
}


def audio_to_codec2(data, bitrate):
    """Transcode any ffmpeg-readable audio to raw codec2 frames.

    Optional feature: requires ffmpeg and pycodec2. Returns None on any
    failure so callers can fall back to passing the original through.
    """
    if bitrate not in AM_FOR_BITRATE:
        return None
    try:
        import numpy as np
        import pycodec2
        pcm = subprocess.run(
            ["ffmpeg", "-v", "quiet", "-i", "pipe:0",
             "-f", "s16le", "-ar", "8000", "-ac", "1", "pipe:1"],
            input=data, capture_output=True, check=True, timeout=60).stdout
        codec = pycodec2.Codec2(bitrate)
        frame_len = codec.samples_per_frame() * 2
        out = bytearray()
        for i in range(0, len(pcm) - frame_len + 1, frame_len):
            samples = np.frombuffer(pcm[i:i + frame_len], dtype=np.int16)
            out += codec.encode(samples)
        return bytes(out) or None
    except Exception as e:  # noqa: BLE001 - fall back to passthrough
        log.debug(
            "codec2 encode unavailable/failed (%s), passing audio through", e)
        return None


def codec2_to_wav(mode, data):
    """Decode raw codec2 frames to WAV bytes; None if not decodable here.

    Optional feature: requires pycodec2 (which needs libcodec2).
    """
    bitrate = CODEC2_BITRATES.get(mode)
    if bitrate is None:
        return None
    try:
        import pycodec2
        codec = pycodec2.Codec2(bitrate)
        frame_bytes = codec.bytes_per_frame()
        pcm = bytearray()
        for i in range(0, len(data) - frame_bytes + 1, frame_bytes):
            pcm += codec.decode(data[i:i + frame_bytes]).tobytes()
        if not pcm:
            return None
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wav:
            wav.setnchannels(1)
            wav.setsampwidth(2)
            # ponytail: 8 kHz for all modes; 450PWB is nominally 16 kHz and
            # will play slow -- special-case it if anyone actually uses it
            wav.setframerate(8000)
            wav.writeframes(bytes(pcm))
        return buf.getvalue()
    except Exception as e:  # noqa: BLE001 - fall back to raw .c2 forwarding
        log.debug(
            "codec2 transcode unavailable/failed (%s), forwarding raw", e)
        return None
