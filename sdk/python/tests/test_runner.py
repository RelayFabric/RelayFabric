import io
import os
import threading
import time
import unittest
from unittest import mock

from relayfabric_sdk import FakeSock, run_plugin
from relayfabric_sdk import ipc as relay_ipc
from relayfabric_sdk import runner

HELLO_ACK_OK = {"t": "hello_ack", "error": None}

SOCKET_ENV = "TEST_RF_SOCKET"
CONFIG_ENV = "TEST_RF_CONFIG"


class _RecordingBridge:
    """Full-shape bridge: handle_send, handle_send_direct, start, stop."""

    def __init__(self, cfg, sock):
        self.cfg = cfg
        self.sock = sock
        self.send_calls = []
        self.direct_calls = []
        self.started = False
        self.stopped = False

    def handle_send(self, frame):
        self.send_calls.append(frame)

    def handle_send_direct(self, frame):
        self.direct_calls.append(frame)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


class _MinimalBridge:
    """Bridge with only the required handle_send -- no send_direct/start/stop."""

    def __init__(self, cfg, sock):
        self.cfg = cfg
        self.sock = sock
        self.send_calls = []

    def handle_send(self, frame):
        self.send_calls.append(frame)


def _env(**overrides):
    base = {SOCKET_ENV: "/tmp/does-not-matter.sock"}
    base.update(overrides)
    return base


class MissingEnvTests(unittest.TestCase):
    def test_missing_socket_env_exits_2(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop(SOCKET_ENV, None)
            with self.assertRaises(SystemExit) as ctx:
                run_plugin("p", "1.0", _MinimalBridge, relay_ipc.capabilities(),
                           socket_env=SOCKET_ENV, config_env=CONFIG_ENV)
            self.assertEqual(ctx.exception.code, 2)


class DefaultEnvTests(unittest.TestCase):
    def test_default_config_env_is_relayfabric_plugin_config(self):
        # Carried fix from the Task 2 review: the daemon actually sets
        # RELAYFABRIC_PLUGIN_CONFIG (switchyardd's plugins.rs `supervise()`),
        # not the placeholder RELAYFABRIC_CONFIG the default used to name --
        # this exercises the real default (no config_env= override) end to
        # end, unlike every other test in this file.
        sock = FakeSock(queued_frames=[HELLO_ACK_OK, {"t": "shutdown"}])
        holder = {}

        def factory(cfg, s):
            holder["cfg"] = cfg
            return _MinimalBridge(cfg, s)

        env = {SOCKET_ENV: "/tmp/does-not-matter.sock",
               "RELAYFABRIC_PLUGIN_CONFIG": '{"real": true}'}
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(SystemExit) as ctx:
            run_plugin("p", "1.0", factory, relay_ipc.capabilities(),
                       socket_env=SOCKET_ENV, connect=lambda path: sock)
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(holder["cfg"], {"real": True})


class ConfigEnvScrubbedTests(unittest.TestCase):
    def test_config_env_popped_after_handshake(self):
        # The config env var carries fully-resolved secrets (e.g. a ${env:}
        # or ${file:} reference already substituted by the daemon). Plugins
        # that spawn children (lxmf's media.py runs ffmpeg over
        # attacker-supplied audio) must not leak those into that child's
        # inherited environment.
        sock = FakeSock(queued_frames=[HELLO_ACK_OK, {"t": "shutdown"}])
        env = _env(**{CONFIG_ENV: '{"token": "shh-secret"}'})
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(SystemExit) as ctx:
                run_plugin("p", "1.0", _MinimalBridge, relay_ipc.capabilities(),
                           socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                           connect=lambda path: sock)
            self.assertEqual(ctx.exception.code, 0)
            self.assertNotIn(CONFIG_ENV, os.environ)


class HandshakeTests(unittest.TestCase):
    def test_ok_sends_hello_and_calls_bridge_factory(self):
        sock = FakeSock(queued_frames=[HELLO_ACK_OK, {"t": "shutdown"}])
        factories = []

        def factory(cfg, s):
            factories.append((cfg, s))
            return _RecordingBridge(cfg, s)

        caps = relay_ipc.capabilities(groups=True)
        with mock.patch.dict(os.environ, _env(), clear=True), self.assertRaises(SystemExit) as ctx:
            run_plugin("lxmf", "0.1.0", factory, caps,
                       socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                       connect=lambda path: sock)
        self.assertEqual(ctx.exception.code, 0)

        frames = sock.frames()
        self.assertEqual(frames[0], relay_ipc.hello("lxmf", "0.1.0", caps))
        self.assertEqual(factories, [({}, sock)])

    def test_mismatched_ack_exits_1(self):
        sock = FakeSock(queued_frames=[{"t": "hello_ack", "error": "nope"}])
        with mock.patch.dict(os.environ, _env(), clear=True), self.assertRaises(SystemExit) as ctx:
            run_plugin("lxmf", "0.1.0", _MinimalBridge, relay_ipc.capabilities(),
                       socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                       connect=lambda path: sock)
        self.assertEqual(ctx.exception.code, 1)

    def test_wrong_frame_type_for_ack_exits_1(self):
        sock = FakeSock(queued_frames=[{"t": "inbound"}])
        with mock.patch.dict(os.environ, _env(), clear=True), self.assertRaises(SystemExit) as ctx:
            run_plugin("lxmf", "0.1.0", _MinimalBridge, relay_ipc.capabilities(),
                       socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                       connect=lambda path: sock)
        self.assertEqual(ctx.exception.code, 1)


class CallableCapabilitiesTests(unittest.TestCase):
    def test_callable_capabilities_receives_cfg_and_result_sent_in_hello(self):
        sock = FakeSock(queued_frames=[HELLO_ACK_OK, {"t": "shutdown"}])
        seen = {}

        def caps_fn(cfg):
            seen["cfg"] = cfg
            return relay_ipc.capabilities(max_payload=123)

        env = _env(**{CONFIG_ENV: '{"max_text_bytes": 123}'})
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(SystemExit) as ctx:
            run_plugin("p", "1.0", _MinimalBridge, caps_fn,
                       socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                       connect=lambda path: sock)
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(seen["cfg"], {"max_text_bytes": 123})
        hello_frame = sock.frames()[0]
        self.assertEqual(hello_frame["capabilities"]["max_payload"], 123)

    def test_invalid_config_from_caps_callable_exits_1(self):
        def caps_fn(cfg):
            raise ValueError("config requires 'broker'")

        sock = FakeSock(queued_frames=[HELLO_ACK_OK])
        with mock.patch.dict(os.environ, _env(), clear=True), self.assertRaises(SystemExit) as ctx:
            run_plugin("p", "1.0", _MinimalBridge, caps_fn,
                       socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                       connect=lambda path: sock)
        self.assertEqual(ctx.exception.code, 1)

    def test_invalid_config_from_bridge_factory_exits_1(self):
        def factory(cfg, s):
            raise TypeError("max_text_bytes must be int")

        sock = FakeSock(queued_frames=[HELLO_ACK_OK])
        with mock.patch.dict(os.environ, _env(), clear=True), self.assertRaises(SystemExit) as ctx:
            run_plugin("p", "1.0", factory, relay_ipc.capabilities(),
                       socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                       connect=lambda path: sock)
        self.assertEqual(ctx.exception.code, 1)


class DispatchTests(unittest.TestCase):
    def _run(self, bridge_cls, frames):
        sock = FakeSock(queued_frames=[HELLO_ACK_OK, *frames])
        holder = {}

        def factory(cfg, s):
            holder["bridge"] = bridge_cls(cfg, s)
            return holder["bridge"]

        env = _env(**{CONFIG_ENV: '{"k": 1}'})
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(SystemExit) as ctx:
            run_plugin("p", "1.0", factory, relay_ipc.capabilities(),
                       socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                       connect=lambda path: sock)
        return ctx.exception.code, holder["bridge"]

    def test_send_dispatches_to_handle_send(self):
        send_frame = {"t": "send", "corr": 1, "endpoint": "x", "body": "hi"}
        code, bridge = self._run(_RecordingBridge, [send_frame, {"t": "shutdown"}])
        self.assertEqual(code, 0)
        self.assertEqual(bridge.send_calls, [send_frame])
        self.assertEqual(bridge.cfg, {"k": 1})

    def test_send_direct_dispatches_when_handler_present(self):
        direct_frame = {"t": "send_direct", "corr": 2, "native_ref": "ab", "body": "x"}
        code, bridge = self._run(_RecordingBridge, [direct_frame, {"t": "shutdown"}])
        self.assertEqual(code, 0)
        self.assertEqual(bridge.direct_calls, [direct_frame])

    def test_send_direct_ignored_when_handler_absent(self):
        direct_frame = {"t": "send_direct", "corr": 2, "native_ref": "ab", "body": "x"}
        code, bridge = self._run(_MinimalBridge, [direct_frame, {"t": "shutdown"}])
        self.assertEqual(code, 0)
        self.assertEqual(bridge.send_calls, [])  # no crash, no misdispatch

    def test_unknown_type_ignored(self):
        code, _bridge = self._run(_MinimalBridge, [{"t": "bogus"}, {"t": "shutdown"}])
        self.assertEqual(code, 0)

    def test_shutdown_exits_0_and_calls_stop_if_present(self):
        code, bridge = self._run(_RecordingBridge, [{"t": "shutdown"}])
        self.assertEqual(code, 0)
        self.assertTrue(bridge.stopped)

    def test_start_called_before_loop_when_present(self):
        _code, bridge = self._run(_RecordingBridge, [{"t": "shutdown"}])
        self.assertTrue(bridge.started)

    def test_minimal_bridge_without_start_stop_is_fine(self):
        code, _bridge = self._run(_MinimalBridge, [{"t": "shutdown"}])
        self.assertEqual(code, 0)

    def test_io_error_on_exhausted_frames_exits_1(self):
        # No shutdown frame queued: after hello_ack, the next read hits
        # EOFError (FakeSock's queued frames are exhausted), which must
        # surface as exit 1, mirroring a closed daemon connection.
        code, _bridge = self._run(_MinimalBridge, [])
        self.assertEqual(code, 1)


class MalformedDispatchTests(unittest.TestCase):
    """A malformed send/send_direct frame must not kill the plugin: the loop
    logs and keeps going (symmetry with the hardened read path)."""

    def test_malformed_send_does_not_kill_the_loop(self):
        class _RaisingBridge(_MinimalBridge):
            def handle_send(self, frame):
                # simulate capped_text_send's KeyError on a missing field
                raise KeyError("endpoint")

        # a bad send, then a good shutdown: if the bad send killed the loop we
        # would exit(1) on the raise; instead we must reach shutdown -> exit(0)
        sock = FakeSock(queued_frames=[HELLO_ACK_OK, {"t": "send"}, {"t": "shutdown"}])
        env = _env(**{CONFIG_ENV: "{}"})
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(SystemExit) as ctx:
            run_plugin("p", "1.0", _RaisingBridge, relay_ipc.capabilities(),
                       socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                       connect=lambda path: sock)
        self.assertEqual(ctx.exception.code, 0, "a bad send frame must not crash the plugin")


class SendConcurrencyTests(unittest.TestCase):
    """Sends run on a worker thread, so a slow/blocking send must not stall
    the read loop -- ping liveness (and shutdown) keep flowing regardless.
    If handle_send ran inline (the pre-refactor behavior), the read loop would
    block inside it and never reach the ping, so no pong would be written."""

    def test_a_blocking_send_does_not_stall_ping_liveness(self):
        started = threading.Event()
        release = threading.Event()
        captured = []

        class _SlowBridge(_MinimalBridge):
            def _send_frame(self, obj):
                captured.append(obj)

            def handle_send(self, frame):
                started.set()
                release.wait(5)  # block the worker until the test releases it

        # send (will block the worker), then a ping the read loop must still
        # answer; after ping the queued frames exhaust -> the loop exits(1).
        sock = FakeSock(queued_frames=[
            HELLO_ACK_OK,
            {"t": "send", "corr": 1, "endpoint": "x", "body": "hi"},
            {"t": "ping"},
        ])

        def run():
            with mock.patch.dict(os.environ, _env(**{CONFIG_ENV: "{}"}), clear=True):
                try:
                    run_plugin("p", "1.0", _SlowBridge, relay_ipc.capabilities(),
                               socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                               connect=lambda path: sock)
                except SystemExit:
                    pass

        t = threading.Thread(target=run, daemon=True)
        t.start()
        self.assertTrue(started.wait(5), "the send should have started on the worker")
        # the read loop must have moved past the blocked send to answer the ping
        deadline = time.time() + 5
        while time.time() < deadline and not any(f.get("t") == "pong" for f in captured):
            time.sleep(0.01)
        self.assertTrue(
            any(f.get("t") == "pong" for f in captured),
            "ping must be answered while a send is still blocked on the worker",
        )
        release.set()
        t.join(5)


class PingTests(unittest.TestCase):
    """A daemon Ping (liveness probe) must be answered with a Pong, or the
    daemon will restart the plugin as wedged."""

    def test_ping_is_answered_with_pong_via_socket_fallback(self):
        sock = FakeSock(queued_frames=[HELLO_ACK_OK, {"t": "ping"}, {"t": "shutdown"}])
        env = _env(**{CONFIG_ENV: "{}"})
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(SystemExit) as ctx:
            run_plugin("p", "1.0", _MinimalBridge, relay_ipc.capabilities(),
                       socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                       connect=lambda path: sock)
        self.assertEqual(ctx.exception.code, 0)
        written = sock.frames()
        self.assertTrue(any(f.get("t") == "pong" for f in written),
                        f"ping must be answered with pong: {written}")

    def test_ping_uses_the_bridges_locked_writer_when_available(self):
        class _LockedBridge(_MinimalBridge):
            def __init__(self, cfg, s):
                super().__init__(cfg, s)
                self.sent = []

            def _send_frame(self, obj):
                self.sent.append(obj)

        sock = FakeSock(queued_frames=[HELLO_ACK_OK, {"t": "ping"}, {"t": "shutdown"}])
        holder = {}

        def factory(cfg, s):
            holder["b"] = _LockedBridge(cfg, s)
            return holder["b"]

        env = _env(**{CONFIG_ENV: "{}"})
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(SystemExit):
            run_plugin("p", "1.0", factory, relay_ipc.capabilities(),
                       socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                       connect=lambda path: sock)
        self.assertTrue(any(f.get("t") == "pong" for f in holder["b"].sent),
                        f"pong must go through the bridge's locked writer: {holder['b'].sent}")


class SendQueueTests(unittest.TestCase):
    """The daemon re-dispatches a delivery whose result has not arrived
    within its reclaim window, so a backlog longer than that gets its tail
    queued twice. The queue dedups on corr (queued or in flight) and is
    bounded so the daemon is told to back off instead of growing an
    unbounded duplicate-laden backlog."""

    def test_duplicate_corr_is_dropped_until_released(self):
        q = runner._SendQueue(maxsize=8)
        self.assertEqual(q.offer("send", {"corr": 1}), "queued")
        self.assertEqual(q.offer("send", {"corr": 1}), "duplicate")
        self.assertEqual(q.get(), ("send", {"corr": 1}))
        # still in flight: the worker has taken it but not finished
        self.assertEqual(q.offer("send", {"corr": 1}), "duplicate")
        q.release(1)
        self.assertEqual(q.offer("send", {"corr": 1}), "queued")

    def test_send_and_send_direct_share_the_corr_namespace(self):
        q = runner._SendQueue(maxsize=8)
        self.assertEqual(q.offer("send", {"corr": 5}), "queued")
        self.assertEqual(q.offer("send_direct", {"corr": 5}), "duplicate")

    def test_frames_without_a_corr_are_never_deduped(self):
        q = runner._SendQueue(maxsize=8)
        self.assertEqual(q.offer("send", {}), "queued")
        self.assertEqual(q.offer("send", {}), "queued")

    def test_unhashable_corr_is_queued_not_raised(self):
        q = runner._SendQueue(maxsize=8)
        self.assertEqual(q.offer("send", {"corr": ["x"]}), "queued")
        q.release(["x"])  # must not raise either

    def test_overflow_reports_full_and_keeps_existing_entries(self):
        q = runner._SendQueue(maxsize=2)
        self.assertEqual(q.offer("send", {"corr": 1}), "queued")
        self.assertEqual(q.offer("send", {"corr": 2}), "queued")
        self.assertEqual(q.offer("send", {"corr": 3}), "full")
        # a refused corr is not reserved: the daemon's retry must be accepted
        self.assertEqual(q.get(), ("send", {"corr": 1}))
        self.assertEqual(q.offer("send", {"corr": 3}), "queued")

    def test_default_bound_is_256(self):
        self.assertEqual(runner.SEND_QUEUE_MAX, 256)


class _BlockingBridge(_MinimalBridge):
    """handle_send blocks on `release` for the first frame; records every
    frame it is given."""
    started = threading.Event()
    release = threading.Event()

    def __init__(self, cfg, s):
        super().__init__(cfg, s)
        self.sent = []

    def _send_frame(self, obj):
        self.sent.append(obj)

    def handle_send(self, frame):
        self.send_calls.append(frame)
        if len(self.send_calls) == 1:
            _BlockingBridge.started.set()
            _BlockingBridge.release.wait(5)


class _GatedSock(FakeSock):
    """FakeSock whose reads past the first `gate_after` queued frames wait
    for `gate` -- lets a test hand the worker its first send and only then
    let the read loop see the rest, so queue occupancy is deterministic."""

    def __init__(self, queued_frames, gate, gate_after):
        super().__init__(queued_frames)
        buf = io.BytesIO()
        for obj in queued_frames[:gate_after]:
            relay_ipc.write_frame(buf, obj)
        self._gate_at = buf.tell()
        self._gate = gate

    def read(self, n):
        if self._in.tell() >= self._gate_at:
            self._gate.wait(5)
        return super().read(n)


def _run_blocking(frames, holder):
    """Run run_plugin on a thread with a _BlockingBridge. The first send is
    handed to the worker before any later frame is read; returns the thread."""
    _BlockingBridge.started.clear()
    _BlockingBridge.release.clear()
    sock = _GatedSock([HELLO_ACK_OK, *frames, {"t": "ping"}],
                      _BlockingBridge.started, gate_after=2)

    def factory(cfg, s):
        holder["b"] = _BlockingBridge(cfg, s)
        return holder["b"]

    def run():
        with mock.patch.dict(os.environ, _env(**{CONFIG_ENV: "{}"}), clear=True):
            try:
                run_plugin("p", "1.0", factory, relay_ipc.capabilities(),
                           socket_env=SOCKET_ENV, config_env=CONFIG_ENV,
                           connect=lambda path: sock)
            except SystemExit:
                pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def _wait_for_pong(bridge):
    deadline = time.time() + 5
    while time.time() < deadline and not any(f.get("t") == "pong" for f in bridge.sent):
        time.sleep(0.01)
    return any(f.get("t") == "pong" for f in bridge.sent)


def _wait_for_sends(bridge, count):
    deadline = time.time() + 5
    while time.time() < deadline and len(bridge.send_calls) < count:
        time.sleep(0.01)
    return [f["corr"] for f in bridge.send_calls]


class SendDedupIntegrationTests(unittest.TestCase):
    def test_redispatch_of_an_in_flight_corr_is_dispatched_once(self):
        holder = {}
        t = _run_blocking([
            {"t": "send", "corr": 1, "endpoint": "x", "body": "a"},
            {"t": "send", "corr": 1, "endpoint": "x", "body": "a"},  # daemon re-dispatch
            {"t": "send", "corr": 2, "endpoint": "x", "body": "b"},
        ], holder)
        self.assertTrue(_BlockingBridge.started.wait(5))
        self.assertTrue(_wait_for_pong(holder["b"]), "read loop must keep answering pings")
        _BlockingBridge.release.set()
        t.join(5)
        corrs = _wait_for_sends(holder["b"], 2)
        self.assertEqual(corrs, [1, 2], "the duplicate corr 1 must not be sent twice")

    def test_overflow_answers_delivery_result_plugin_busy(self):
        holder = {}
        with mock.patch.object(runner, "SEND_QUEUE_MAX", 1):
            t = _run_blocking([
                {"t": "send", "corr": 1, "endpoint": "x", "body": "a"},  # in flight (blocked)
                {"t": "send", "corr": 2, "endpoint": "x", "body": "b"},  # queued (fills the bound)
                {"t": "send", "corr": 3, "endpoint": "x", "body": "c"},  # overflow
            ], holder)
            self.assertTrue(_BlockingBridge.started.wait(5))
            self.assertTrue(_wait_for_pong(holder["b"]))
            busy = [f for f in holder["b"].sent if f.get("t") == "delivery_result"]
            self.assertEqual(busy, [relay_ipc.delivery_result(3, False, "plugin busy")])
            _BlockingBridge.release.set()
            t.join(5)
        corrs = _wait_for_sends(holder["b"], 2)
        self.assertEqual(corrs, [1, 2])


if __name__ == "__main__":
    unittest.main()
