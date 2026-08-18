import os
import unittest
from unittest import mock

from relayfabric_sdk import FakeSock, run_plugin
from relayfabric_sdk import ipc as relay_ipc

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


if __name__ == "__main__":
    unittest.main()
