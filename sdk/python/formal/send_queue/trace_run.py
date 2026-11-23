"""Run the real send queue and worker of relayfabric_sdk.runner, and log each step.

    python sdk/python/formal/send_queue/trace_run.py OUTDIR

writes one log per scenario into OUTDIR. Each line is one step of the run, as a
TLA+ record. VERIFY.md next to this file says how to check that the model
SendQueue.tla can take the same steps in the same order (the trace check).

runner.py is not changed. This script swaps the three objects that _SendQueue
builds in __init__ for subclasses that log, so a line is written at every place
where the code touches them, not once per call of offer or release:

- _q: queue.Queue calls _put and _get with its own mutex held, so "Put" and
  "Get" lines are written inside the step that they report; "Size" is written
  by qsize with that mutex held, with the size that offer is given;
- _pending: "Check", "Add" and "Discard" lines are written by the set, while
  the caller holds _SendQueue._lock;
- _lock: "Lock" is written after the lock is taken, and "Unlock" before it is
  given back, with the content of _pending at that moment.

"Receive", "Shutdown" and "Lost" come from a wrapper around runner.read_frame.
"Dispatch", "Busy" and "Exit" come from the bridge that the scenario supplies.

Each scenario must fit SendQueueTrace.cfg: corr 1 or 2 or none, a queue bound
of MAX_QUEUE, and at most five send frames.
"""

import io
import os
import queue
import random
import sys
import threading
import time
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from relayfabric_sdk import FakeSock, ipc, runner

MAX_QUEUE = 2  # MaxQueue in SendQueueTrace.cfg
WAIT = 10  # seconds before a scenario gives up on a step that must happen
HELLO_ACK = {"t": "hello_ack", "error": None}
PLUGIN = "trace"

_sink = []  # the log of the scenario that is running; each traced object keeps the one it was built with


def _by():
    name = threading.current_thread().name
    return "worker" if name == f"{PLUGIN}-sender" else "reader"


def _corr(frame):
    corr = frame.get("corr") if isinstance(frame, dict) else frame
    if corr is None:
        return 0  # NoCorr in the model
    if corr not in (1, 2):
        raise ValueError(f"corr {corr!r} does not fit SendQueueTrace.cfg")
    return corr


def _log(sink, action, corr=0, **more):
    fields = [f'action |-> "{action}"', f'by |-> "{_by()}"', f"corr |-> {corr}"]
    fields += [f"{key} |-> {value}" for key, value in more.items()]
    sink.append("[" + ", ".join(fields) + "]")  # list.append is one indivisible step


def _traced_queue(built, sink):
    """A queue of the same class and bound as the one that _SendQueue.__init__ built, that logs."""
    if not isinstance(built, queue.Queue):
        raise TypeError(f"_SendQueue._q is a {type(built).__name__}, which this script cannot trace")

    class _TracedQueue(type(built)):
        def _put(self, item):
            super()._put(item)
            if item is None:
                _log(sink, "PutStop")
            else:
                _log(sink, "Put", _corr(item[1]))

        def _get(self):
            item = super()._get()
            if item is None:
                _log(sink, "GetStop")
            else:
                _log(sink, "Get", _corr(item[1]))
            return item

        def qsize(self):
            with self.mutex:  # as queue.Queue.qsize does, so the line is written inside the step
                size = self._qsize()
                _log(sink, "Size", size=size)
                return size

    return _TracedQueue(maxsize=built.maxsize)


def _traced_set(built, sink):
    """A set of the same class as the one that _SendQueue.__init__ built, that logs."""
    if not isinstance(built, set):
        raise TypeError(f"_SendQueue._pending is a {type(built).__name__}, which this script cannot trace")

    class _TracedSet(type(built)):
        def __contains__(self, corr):
            found = super().__contains__(corr)
            _log(sink, "Check", _corr(corr), found="TRUE" if found else "FALSE")
            return found

        def add(self, corr):
            super().add(corr)
            _log(sink, "Add", _corr(corr))

        def discard(self, corr):
            super().discard(corr)
            _log(sink, "Discard", _corr(corr))

    return _TracedSet()


class _TracedLock:
    def __init__(self, lock, pending, sink):
        self._lock = lock
        self._pending = pending
        self._sink = sink

    def __enter__(self):
        self._lock.acquire()
        _log(self._sink, "Lock")
        return self

    def __exit__(self, *exc):
        held = ", ".join(str(c) for c in sorted(set(self._pending)))
        _log(self._sink, "Unlock", pending="{" + held + "}")
        self._lock.release()


class _TracedSendQueue(runner._SendQueue):
    def __init__(self, maxsize=runner.SEND_QUEUE_MAX):
        super().__init__(maxsize=maxsize)
        self._q = _traced_queue(self._q, _sink)
        self._pending = _traced_set(self._pending, _sink)
        self._lock = _TracedLock(self._lock, self._pending, _sink)


_real_read_frame = runner.read_frame


def _traced_read_frame(sock):
    try:
        frame = _real_read_frame(sock)
    except (EOFError, OSError, ValueError):
        _log(sock.sink, "Lost")
        raise
    kind = frame.get("t")
    if kind in ("send", "send_direct"):
        _log(sock.sink, "Receive", _corr(frame))
    elif kind == "shutdown":
        _log(sock.sink, "Shutdown")
    return frame


class _ScriptedSock(FakeSock):
    """FakeSock that calls gates[i] before the read loop gets frame i (0 is the first frame after hello_ack)."""

    def __init__(self, frames, gates, sink):
        super().__init__([HELLO_ACK, *frames])
        self.sink = sink
        buf = io.BytesIO()
        ipc.write_frame(buf, HELLO_ACK)
        self._starts = {}
        for i, frame in enumerate(frames):
            self._starts[buf.tell()] = i
            ipc.write_frame(buf, frame)
        self._starts[buf.tell()] = len(frames)  # the end of the stream
        self._gates = dict(gates)

    def read(self, n):
        gate = self._gates.pop(self._starts.get(self._in.tell()), None)
        if gate is not None:
            gate()
        return super().read(n)


class _Bridge:
    """Stands for a plugin's bridge. on_dispatch(n) runs inside the n-th handle_send or handle_send_direct."""

    on_dispatch = staticmethod(lambda n: None)

    def __init__(self, cfg, sock):
        self.calls = 0
        self._sink = sock.sink

    def _send_frame(self, obj):
        if obj.get("t") == "delivery_result" and obj.get("detail") == "plugin busy":
            _log(self._sink, "Busy", _corr(obj))

    def handle_send(self, frame):
        _log(self._sink, "Dispatch", _corr(frame))
        self.calls += 1
        self.on_dispatch(self.calls)

    handle_send_direct = handle_send

    def stop(self):
        _log(self._sink, "Exit")


def _must(event, what):
    if not event.wait(WAIT):
        raise RuntimeError(f"scenario stalled: {what}")


def _send(corr=None, kind="send"):
    frame = {"t": kind, "endpoint": "x", "body": "b"}
    if corr is not None:
        frame["corr"] = corr
    return frame


SHUTDOWN = {"t": "shutdown"}


def _start(frames, gates, on_dispatch):
    """Start run_plugin on a thread. Returns the thread and a dict that gets its exit code and its log."""
    global _sink
    _sink = []
    bridge_cls = type("_ScenarioBridge", (_Bridge,), {"on_dispatch": staticmethod(on_dispatch)})
    sock = _ScriptedSock(frames, gates, _sink)
    result = {"sink": _sink}

    def run():
        try:
            runner.run_plugin(PLUGIN, "0", bridge_cls, ipc.capabilities(),
                              socket_env="TRACE_SOCKET", config_env="TRACE_CONFIG",
                              connect=lambda path: sock)
        except SystemExit as e:
            result["code"] = e.code

    thread = threading.Thread(target=run, name=f"{PLUGIN}-reader", daemon=True)
    thread.start()
    return thread, result


def _finish(thread, result, want_code):
    thread.join(WAIT)
    if result.get("code") != want_code:
        raise RuntimeError(f"run_plugin ended with {result.get('code')!r}, not {want_code!r}")
    # The process would be gone at "Exit" or "Lost", so drop what the worker thread logs after that.
    events = list(result["sink"])
    for i, line in enumerate(events):
        if '"Exit"' in line or '"Lost"' in line:
            return events[: i + 1]
    raise RuntimeError("the run logged no Exit and no Lost")


def redispatch():
    """A corr is sent again while its first send is inside the bridge; the queue drains at shutdown."""
    started, go = threading.Event(), threading.Event()

    def on_dispatch(n):
        if n == 1:
            started.set()
            _must(go, "the bridge was never released")

    frames = [_send(1), _send(1), _send(2, "send_direct"), _send(), _send(1), SHUTDOWN]
    gates = {1: lambda: _must(started, "the first send never reached the bridge"), 5: go.set}
    return _finish(*_start(frames, gates, on_dispatch), want_code=0)


def overflow():
    """The queue is full, a send is refused with "plugin busy", and its retry is accepted later."""
    started, go, second = threading.Event(), threading.Event(), threading.Event()

    def on_dispatch(n):
        if n == 1:
            started.set()
            _must(go, "the bridge was never released")
        elif n == 2:
            second.set()

    def make_room():
        go.set()
        _must(second, "the worker never took the next send")

    frames = [_send(), _send(1), _send(), _send(2), _send(2), SHUTDOWN]
    gates = {1: lambda: _must(started, "the first send never reached the bridge"), 4: make_room}
    return _finish(*_start(frames, gates, on_dispatch), want_code=0)


def free_running():
    """No gate holds a thread: each frame arrives, and each send takes, a random time under 0.3 ms.

    So the two threads meet in an order that differs from run to run, and this log differs with it.
    """
    def pause(*_):
        time.sleep(random.uniform(0, 0.0003))

    frames = [_send(1), _send(2), _send(1, "send_direct"), _send(), _send(2), SHUTDOWN]
    gates = {i: pause for i in range(len(frames))}
    return _finish(*_start(frames, gates, pause), want_code=0)


def connection_lost():
    """The daemon connection ends while one send is inside the bridge and one is queued."""
    started, go = threading.Event(), threading.Event()

    def on_dispatch(n):
        if n == 1:
            started.set()
            go.wait(WAIT)

    frames = [_send(1), _send(2)]
    gates = {1: lambda: _must(started, "the first send never reached the bridge")}
    try:
        return _finish(*_start(frames, gates, on_dispatch), want_code=1)
    finally:
        go.set()


def join_timeout():
    """Shutdown while a send is stuck in the bridge and the queue has room: join gives up after 2 s."""
    started, go = threading.Event(), threading.Event()

    def on_dispatch(n):
        if n == 1:
            started.set()
            go.wait(WAIT)

    frames = [_send(1), _send(2), SHUTDOWN]
    gates = {1: lambda: _must(started, "the first send never reached the bridge")}
    try:
        return _finish(*_start(frames, gates, on_dispatch), want_code=0)
    finally:
        go.set()


def shutdown_when_full():
    """Shutdown while a send is stuck in the bridge and the queue is full: close does not wait for room."""
    started, go, at_shutdown = threading.Event(), threading.Event(), threading.Event()

    def on_dispatch(n):
        if n == 1:
            started.set()
            go.wait(WAIT)

    frames = [_send(1), _send(2), _send(), SHUTDOWN]
    gates = {1: lambda: _must(started, "the first send never reached the bridge"), 3: at_shutdown.set}
    thread, result = _start(frames, gates, on_dispatch)
    try:
        _must(at_shutdown, "the read loop never reached the shutdown frame")
        thread.join(3.0)  # longer than the 2 s of sender.join in run_plugin
        if thread.is_alive():
            raise RuntimeError("scenario stalled: 3 s after the shutdown frame run_plugin has not exited, "
                               "so close() waited for the stuck send")
        return _finish(thread, result, want_code=0)
    finally:
        go.set()


SCENARIOS = [redispatch, overflow, free_running, connection_lost, join_timeout, shutdown_when_full]


def main(argv):
    if len(argv) != 2:
        print(__doc__.split("\n\n")[1].strip(), file=sys.stderr)
        return 2
    out = Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)
    said = io.StringIO()  # what run_plugin prints on stderr; shown only when a scenario fails
    try:
        with mock.patch.dict(os.environ, {"TRACE_SOCKET": "unused"}, clear=True), \
                mock.patch.object(runner, "SEND_QUEUE_MAX", MAX_QUEUE), \
                mock.patch.object(runner, "_SendQueue", _TracedSendQueue), \
                mock.patch.object(runner, "read_frame", _traced_read_frame), \
                mock.patch.object(sys, "stderr", said):
            for scenario in SCENARIOS:
                events = scenario()
                path = out / f"{scenario.__name__}.log"
                path.write_text("\n".join(events) + "\n")
                print(f"{path}: {len(events)} steps")
    except Exception:
        sys.stderr.write(said.getvalue())
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
