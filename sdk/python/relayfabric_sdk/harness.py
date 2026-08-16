"""FakeSock: scripted duplex socket double for plugin frame-IO tests.

Superset of the write-capture-only fake each plugin suite used to
re-implement locally (lxmf/signal/meshtastic/meshcore all had a
byte-identical copy): construct with no arguments for the common case
(capture frames a Bridge writes via write_frame(), decode them back with
frames()); optionally pass queued_frames to script the read side too
(read_frame() consumes them in order, then hits EOFError once exhausted,
mirroring a closed daemon connection) for main-loop-style tests.
"""

import io

from . import ipc


class FakeSock:
    def __init__(self, queued_frames=None):
        self._in = io.BytesIO()
        for obj in queued_frames or []:
            ipc.write_frame(self._in, obj)
        self._in.seek(0)
        self._out = io.BytesIO()

    def read(self, n):
        return self._in.read(n)

    def write(self, data):
        self._out.write(data)

    def flush(self):
        pass

    def frames(self):
        out, rd = [], io.BytesIO(self._out.getvalue())
        while True:
            try:
                out.append(ipc.read_frame(rd))
            except EOFError:
                return out
