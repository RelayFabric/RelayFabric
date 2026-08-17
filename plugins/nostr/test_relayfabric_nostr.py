import asyncio
import copy
import json
import os
import queue
import subprocess
import sys
import threading
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "sdk", "python"))

import relayfabric_nostr as plug
from relayfabric_sdk import FakeSock, SentCache, nip01

# "Known nsec" golden vector: nsec=1 is the best-known private key in
# secp256k1 (scalar 1); its x-only pubkey is the curve generator point G,
# independently verifiable against any secp256k1 reference (e.g. SEC2) --
# 79be667ef9dcbbac...16f81798. Used here only as a ready-made
# (privkey_hex, pubkey_hex) identity for tests that don't exercise
# event_id/sign_event/verify_event's own correctness -- see
# sdk/python/tests/test_nip01.py's EventIdGoldenVectorTests /
# SignVerifyRoundTripTests / VerifyEventRejectsTests for the locked
# known-answer id/sig vector and the sign/verify/tamper matrix (moved there
# in cycle J alongside the event_id/verify_event/sign_event/
# load_or_create_identity promotion to relayfabric_sdk.nip01).
GOLDEN_PRIVKEY_HEX = "0" * 63 + "1"
GOLDEN_PUBKEY_HEX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def valid_relay_cfg(**overrides):
    cfg = {
        "relays": ["wss://relay.example.com"],
        "channels": {
            "regional": {"filter": {"kinds": [1], "#t": ["pasadena"]}},
        },
    }
    cfg.update(overrides)
    return cfg


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = plug.load_config(valid_relay_cfg())
        self.assertEqual(cfg["max_text_bytes"], 280)
        self.assertIsNone(cfg["identity_file"])

    def test_relays_required_missing(self):
        with self.assertRaises(ValueError):
            plug.load_config({"channels": {"a": {"filter": {}}}})

    def test_relays_required_empty(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_relay_cfg(relays=[]))

    def test_relays_must_be_list(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(relays="wss://relay.example.com"))

    def test_relay_url_must_be_str(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(relays=[123]))

    def test_relay_url_must_have_ws_scheme(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_relay_cfg(relays=["https://relay.example.com"]))

    def test_relay_ws_and_wss_both_accepted(self):
        cfg = plug.load_config(valid_relay_cfg(relays=["ws://a", "wss://b"]))
        self.assertEqual(cfg["relays"], ["ws://a", "wss://b"])

    def test_channels_required_missing(self):
        with self.assertRaises(ValueError):
            plug.load_config({"relays": ["wss://a"]})

    def test_channels_required_empty(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_relay_cfg(channels={}))

    def test_channels_must_be_dict(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(channels=["regional"]))

    def test_channel_spec_must_be_dict(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(channels={"regional": "not-a-dict"}))

    def test_channel_filter_required(self):
        with self.assertRaises(ValueError):
            plug.load_config(valid_relay_cfg(channels={"regional": {}}))

    def test_channel_filter_must_be_dict(self):
        with self.assertRaises(TypeError):
            plug.load_config(
                valid_relay_cfg(channels={"regional": {"filter": ["kinds"]}}))

    def test_channel_relays_optional_list(self):
        cfg = plug.load_config(valid_relay_cfg(channels={
            "regional": {"filter": {"kinds": [1]}, "relays": ["wss://c"]},
        }))
        self.assertEqual(cfg["channels"]["regional"]["relays"], ["wss://c"])

    def test_channel_relays_must_be_list(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(channels={
                "regional": {"filter": {"kinds": [1]}, "relays": "wss://c"},
            }))

    def test_channel_publish_tags_optional_list(self):
        cfg = plug.load_config(valid_relay_cfg(channels={
            "regional": {"filter": {"kinds": [1]},
                        "publish_tags": [["t", "pasadena"]]},
        }))
        self.assertEqual(cfg["channels"]["regional"]["publish_tags"],
                         [["t", "pasadena"]])

    def test_channel_publish_tags_must_be_list(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(channels={
                "regional": {"filter": {"kinds": [1]}, "publish_tags": "t"},
            }))

    def test_max_text_bytes_default(self):
        cfg = plug.load_config(valid_relay_cfg())
        self.assertEqual(cfg["max_text_bytes"], 280)

    def test_max_text_bytes_override(self):
        cfg = plug.load_config(valid_relay_cfg(max_text_bytes=140))
        self.assertEqual(cfg["max_text_bytes"], 140)

    def test_max_text_bytes_must_be_int(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(max_text_bytes="280"))

    def test_identity_file_optional_default_none(self):
        cfg = plug.load_config(valid_relay_cfg())
        self.assertIsNone(cfg["identity_file"])

    def test_identity_file_override(self):
        cfg = plug.load_config(valid_relay_cfg(identity_file="/etc/nostr.nsec"))
        self.assertEqual(cfg["identity_file"], "/etc/nostr.nsec")

    def test_identity_file_must_be_str(self):
        with self.assertRaises(TypeError):
            plug.load_config(valid_relay_cfg(identity_file=42))

    def test_channels_are_copied_not_aliased(self):
        raw = valid_relay_cfg()
        cfg = plug.load_config(raw)
        cfg["channels"]["regional"]["filter"]["kinds"] = [9999]
        self.assertEqual(raw["channels"]["regional"]["filter"]["kinds"], [1])

    def test_deny_by_default_only_configured_channels(self):
        # No hidden default channel: load_config never invents entries beyond
        # what was configured.
        cfg = plug.load_config(valid_relay_cfg())
        self.assertEqual(list(cfg["channels"].keys()), ["regional"])


class NormalizeEventTests(unittest.TestCase):
    def setUp(self):
        self.channels_by_sub = {"sub-regional": "regional"}

    def _signed(self, **overrides):
        kwargs = {"privkey_hex": GOLDEN_PRIVKEY_HEX, "created_at": 1700000020,
                  "kind": 1, "tags": [], "content": "hello channel"}
        kwargs.update(overrides)
        return nip01.sign_event(kwargs["privkey_hex"], kwargs["created_at"],
                                kwargs["kind"], kwargs["tags"], kwargs["content"])

    def test_valid_event_normalizes(self):
        event = self._signed()
        result = plug.normalize_event(event, "sub-regional", self.channels_by_sub)
        self.assertIsNotNone(result)
        channel, sender, text, ts = result
        self.assertEqual(channel, "regional")
        self.assertEqual(sender, f"nostr:{GOLDEN_PUBKEY_HEX}")
        self.assertEqual(text, "hello channel")
        self.assertEqual(ts, 1700000020)

    def test_kind_not_1_dropped(self):
        event = self._signed(kind=0)
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.channels_by_sub))

    def test_bad_sig_dropped(self):
        # design Sec80: a relay is untrusted -- bad/wrong sig must never bridge.
        event = self._signed()
        event["sig"] = "0" * 128
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.channels_by_sub))

    def test_tampered_id_dropped(self):
        event = self._signed()
        event["id"] = "f" * 64
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.channels_by_sub))

    def test_empty_content_dropped(self):
        event = self._signed(content="")
        self.assertIsNone(
            plug.normalize_event(event, "sub-regional", self.channels_by_sub))

    def test_unmapped_subscription_dropped(self):
        event = self._signed()
        self.assertIsNone(
            plug.normalize_event(event, "sub-unknown", self.channels_by_sub))

    def test_malformed_event_dropped_not_raised(self):
        try:
            result = plug.normalize_event({"kind": 1}, "sub-regional",
                                          self.channels_by_sub)
        except Exception as e:  # noqa: BLE001 - the property under test
            self.fail(f"normalize_event raised {e!r}")
        self.assertIsNone(result)


class HelloMaxPayloadTests(unittest.TestCase):
    def test_default_cap(self):
        cfg = plug.load_config(valid_relay_cfg())
        self.assertEqual(plug.hello_max_payload(cfg), 280)

    def test_lower_max_text_bytes_tightens_cap(self):
        cfg = plug.load_config(valid_relay_cfg(max_text_bytes=100))
        self.assertEqual(plug.hello_max_payload(cfg), 100)

    def test_higher_max_text_bytes_capped_at_280(self):
        cfg = plug.load_config(valid_relay_cfg(max_text_bytes=5000))
        self.assertEqual(plug.hello_max_payload(cfg), 280)


class SentCacheImportSmokeTests(unittest.TestCase):
    """Task 2's Bridge will use relayfabric_sdk.SentCache the same way
    meshcore/signal do; this just confirms the sys.path-inserted sdk import
    works from the nostr plugin directory."""

    def test_sentcache_record_and_match_round_trips(self):
        cache = SentCache(ttl_secs=3600)
        cache.record("regional", "hi")
        self.assertTrue(cache.match("regional", "hi"))
        self.assertFalse(cache.match("regional", "hi"))  # consumed on match


class ImportCleanlinessTests(unittest.TestCase):
    """Module top level must be stdlib-only (coincurve/websockets/cbor2/
    relayfabric_sdk imported lazily inside functions) so config/event
    helpers stay importable without those deps. Run in a subprocess so
    modules other tests in this file already imported (e.g. coincurve, for
    the crypto tests themselves) can't mask a leaked top-level import."""

    def test_module_top_level_is_stdlib_only(self):
        plugin_dir = os.path.dirname(os.path.abspath(__file__))
        script = (
            "import sys\n"
            "import relayfabric_nostr\n"
            "leaked = [m for m in "
            "('coincurve', 'websockets', 'cbor2', 'relayfabric_sdk') "
            "if m in sys.modules]\n"
            "assert not leaked, leaked\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script], cwd=plugin_dir,
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


class DeepCopyRegressionTests(unittest.TestCase):
    def test_load_config_does_not_mutate_raw(self):
        raw = valid_relay_cfg()
        raw_copy = copy.deepcopy(raw)
        plug.load_config(raw)
        self.assertEqual(raw, raw_copy)


# ---------------------------------------------------------------------------
# Task 2: Backend, Bridge, main, executable
# ---------------------------------------------------------------------------

# Reuse Task 1's golden-vector keypair as a ready-made (privkey_hex,
# pubkey_hex) identity for backend/bridge tests that don't exercise
# load_or_create_identity itself.
IDENTITY = (GOLDEN_PRIVKEY_HEX, GOLDEN_PUBKEY_HEX)


def loaded_cfg(**overrides):
    return plug.load_config(valid_relay_cfg(**overrides))


def _running_loop():
    """A live asyncio event loop on its own daemon thread -- lets a test
    call NostrBackend.publish() (which needs a running self._loop for
    run_coroutine_threadsafe) without going through the full start()/
    websockets machinery."""
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    return loop


def _stop_and_close_loop(loop):
    """Test-only cleanup for a backend's private event loop: cancels and
    awaits any still-pending tasks (e.g. a _relay_loop parked in its
    reconnect-backoff asyncio.sleep()) before stopping, so close() doesn't
    warn "Task was destroyed but it is pending" -- cancel() only schedules
    delivery of CancelledError at the task's next resumption, so it must
    run as a coroutine on the loop (awaiting gather()) rather than a plain
    call_soon_threadsafe callback, which would stop the loop before
    cancellation actually lands. Then stop()/close() the same way
    meshcore's test helper does (stop() is scheduled onto the loop thread
    asynchronously, so poll briefly for it to actually take effect before
    close(), which raises on a still-running loop)."""
    async def _cancel_all():
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    fut = asyncio.run_coroutine_threadsafe(_cancel_all(), loop)
    try:
        fut.result(timeout=2)
    except Exception:  # noqa: BLE001, S110 - best-effort cleanup, never fail the test on it
        pass
    loop.call_soon_threadsafe(loop.stop)
    deadline = time.time() + 2
    while loop.is_running() and time.time() < deadline:
        time.sleep(0.01)
    if not loop.is_running():
        loop.close()


class NostrBackendInitTests(unittest.TestCase):
    def test_subid_channel_maps(self):
        cfg = loaded_cfg()
        backend = plug.NostrBackend(cfg["relays"], cfg["channels"], IDENTITY)
        self.assertEqual(backend._subid_to_channel, {"rf-regional": "regional"})
        self.assertEqual(backend._channel_to_subid, {"regional": "rf-regional"})

    def test_relay_channels_falls_back_to_default_relays(self):
        cfg = loaded_cfg()
        backend = plug.NostrBackend(cfg["relays"], cfg["channels"], IDENTITY)
        self.assertEqual(backend._relay_channels,
                         {"wss://relay.example.com": ["regional"]})

    def test_relay_channels_uses_channel_specific_relays(self):
        cfg = loaded_cfg(channels={
            "regional": {"filter": {"kinds": [1]}, "relays": ["wss://only-mine"]},
        })
        backend = plug.NostrBackend(cfg["relays"], cfg["channels"], IDENTITY)
        self.assertEqual(backend._relay_channels, {"wss://only-mine": ["regional"]})

    def test_two_channels_sharing_a_relay_get_one_connection(self):
        cfg = loaded_cfg(channels={
            "a": {"filter": {"kinds": [1]}},
            "b": {"filter": {"kinds": [1]}},
        })
        backend = plug.NostrBackend(cfg["relays"], cfg["channels"], IDENTITY)
        self.assertEqual(len(backend._relay_channels), 1)
        self.assertCountEqual(
            backend._relay_channels["wss://relay.example.com"], ["a", "b"])

    def test_queue_is_bounded(self):
        cfg = loaded_cfg()
        backend = plug.NostrBackend(cfg["relays"], cfg["channels"], IDENTITY)
        self.assertEqual(backend._queue.maxsize, 256)

    def test_events_yields_from_queue(self):
        cfg = loaded_cfg()
        backend = plug.NostrBackend(cfg["relays"], cfg["channels"], IDENTITY)
        backend._queue.put(("regional", "nostr:ab", "hi", 1))
        gen = backend.events()
        self.assertEqual(next(gen), ("regional", "nostr:ab", "hi", 1))


class HandleMessageTests(unittest.TestCase):
    """Exercises NostrBackend._handle_message directly with scripted
    EVENT/OK/EOSE/NOTICE frame text -- the design doc's FakeRelay: a
    scripted relay-delivered frame, no real WebSocket, no network. This is
    design Sec80's test: a good-sig EVENT ends up normalized in the queue;
    a bad-sig EVENT never does.
    """

    def setUp(self):
        cfg = loaded_cfg()
        self.backend = plug.NostrBackend(cfg["relays"], cfg["channels"], IDENTITY)

    def _signed_event(self, **overrides):
        kwargs = {"created_at": 1700000100, "kind": 1, "tags": [], "content": "hi"}
        kwargs.update(overrides)
        return nip01.sign_event(GOLDEN_PRIVKEY_HEX, kwargs["created_at"],
                                kwargs["kind"], kwargs["tags"], kwargs["content"])

    def test_good_sig_event_bridges(self):
        event = self._signed_event(content="hello relay")
        raw = json.dumps(["EVENT", "rf-regional", event])
        self.backend._handle_message(raw)
        self.assertEqual(self.backend._queue.qsize(), 1)
        channel, sender, text, ts = self.backend._queue.get_nowait()
        self.assertEqual(channel, "regional")
        self.assertEqual(sender, f"nostr:{GOLDEN_PUBKEY_HEX}")
        self.assertEqual(text, "hello relay")
        self.assertEqual(ts, 1700000100)

    def test_bad_sig_event_dropped(self):
        # design Sec80: a relay is untrusted -- a bad-sig EVENT must never
        # be queued for bridging.
        event = self._signed_event()
        event["sig"] = "0" * 128
        raw = json.dumps(["EVENT", "rf-regional", event])
        self.backend._handle_message(raw)
        self.assertEqual(self.backend._queue.qsize(), 0)

    def test_unmapped_subid_dropped(self):
        event = self._signed_event()
        raw = json.dumps(["EVENT", "rf-unknown", event])
        self.backend._handle_message(raw)
        self.assertEqual(self.backend._queue.qsize(), 0)

    def test_ok_frame_ignored_not_queued(self):
        self.backend._handle_message(json.dumps(["OK", "someid", True, ""]))
        self.assertEqual(self.backend._queue.qsize(), 0)

    def test_eose_frame_ignored_not_queued(self):
        self.backend._handle_message(json.dumps(["EOSE", "rf-regional"]))
        self.assertEqual(self.backend._queue.qsize(), 0)

    def test_notice_frame_ignored_not_queued(self):
        self.backend._handle_message(json.dumps(["NOTICE", "rate limited"]))
        self.assertEqual(self.backend._queue.qsize(), 0)

    def test_garbage_json_does_not_raise(self):
        try:
            self.backend._handle_message("not json{{{")
        except Exception as e:  # noqa: BLE001 - the property under test
            self.fail(f"_handle_message raised {e!r}")
        self.assertEqual(self.backend._queue.qsize(), 0)

    def test_non_list_frame_does_not_raise(self):
        try:
            self.backend._handle_message(json.dumps({"not": "a list"}))
        except Exception as e:  # noqa: BLE001 - the property under test
            self.fail(f"_handle_message raised {e!r}")

    def test_short_event_frame_does_not_raise(self):
        try:
            self.backend._handle_message(json.dumps(["EVENT", "rf-regional"]))
        except Exception as e:  # noqa: BLE001 - the property under test
            self.fail(f"_handle_message raised {e!r}")

    def test_unhashable_subid_does_not_raise(self):
        event = self._signed_event()
        raw = json.dumps(["EVENT", ["not", "hashable"], event])
        try:
            self.backend._handle_message(raw)
        except Exception as e:  # noqa: BLE001 - the property under test
            self.fail(f"_handle_message raised {e!r}")
        self.assertEqual(self.backend._queue.qsize(), 0)

    def test_queue_full_drops_newest(self):
        self.backend._queue = queue.Queue(maxsize=1)
        first = self._signed_event(content="first")
        self.backend._handle_message(json.dumps(["EVENT", "rf-regional", first]))
        second = self._signed_event(created_at=1700000200, content="second")
        self.backend._handle_message(json.dumps(["EVENT", "rf-regional", second]))
        self.assertEqual(self.backend._queue.qsize(), 1)
        _channel, _sender, text, _ts = self.backend._queue.get_nowait()
        self.assertEqual(text, "first")


class FakeSendOnlyWs:
    """Minimal fake for a NostrBackend._connections entry, used only by
    PublishTests: just an async send() (records text, or raises if
    constructed with fail=True). PublishTests populates backend._connections
    directly and never calls start(), so no context-manager/iterator
    behavior is needed here (that's FakeWebSocket, below, for the
    start()-wiring integration test)."""

    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    async def send(self, data):
        if self.fail:
            raise RuntimeError("send failed")
        self.sent.append(data)


class PublishTests(unittest.TestCase):
    def setUp(self):
        cfg = loaded_cfg(channels={
            "regional": {"filter": {"kinds": [1]}, "relays": ["wss://a", "wss://b"],
                        "publish_tags": [["t", "pasadena"]]},
        })
        self.backend = plug.NostrBackend(cfg["relays"], cfg["channels"], IDENTITY)
        self.backend._loop = _running_loop()
        self.addCleanup(_stop_and_close_loop, self.backend._loop)

    def test_publish_before_start_raises(self):
        cfg = loaded_cfg()
        backend = plug.NostrBackend(cfg["relays"], cfg["channels"], IDENTITY)
        with self.assertRaises(RuntimeError):
            backend.publish("regional", "hi")

    def test_publish_unknown_channel_raises(self):
        with self.assertRaises(RuntimeError):
            self.backend.publish("nope", "hi")

    def test_publish_builds_kind1_event_with_channel_tags_and_content(self):
        fake_ws = FakeSendOnlyWs()
        self.backend._connections["wss://a"] = fake_ws
        self.backend.publish("regional", "hello world")
        self.assertEqual(len(fake_ws.sent), 1)
        frame = json.loads(fake_ws.sent[0])
        self.assertEqual(frame[0], "EVENT")
        event = frame[1]
        self.assertEqual(event["kind"], 1)
        self.assertEqual(event["tags"], [["t", "pasadena"]])
        self.assertEqual(event["content"], "hello world")
        self.assertEqual(event["pubkey"], GOLDEN_PUBKEY_HEX)
        # the signature must actually verify -- publish() must sign through
        # sign_event, not hand-roll something verify_event would reject.
        self.assertTrue(nip01.verify_event(event))

    def test_publish_sends_to_every_connected_relay_in_channel_set(self):
        ws_a, ws_b = FakeSendOnlyWs(), FakeSendOnlyWs()
        self.backend._connections["wss://a"] = ws_a
        self.backend._connections["wss://b"] = ws_b
        self.backend.publish("regional", "hi")
        self.assertEqual(len(ws_a.sent), 1)
        self.assertEqual(len(ws_b.sent), 1)

    def test_publish_succeeds_if_any_relay_accepts(self):
        ws_a = FakeSendOnlyWs(fail=True)
        ws_b = FakeSendOnlyWs(fail=False)
        self.backend._connections["wss://a"] = ws_a
        self.backend._connections["wss://b"] = ws_b
        self.backend.publish("regional", "hi")  # must not raise
        self.assertEqual(len(ws_b.sent), 1)

    def test_publish_all_relays_fail_raises_runtime_error(self):
        self.backend._connections["wss://a"] = FakeSendOnlyWs(fail=True)
        self.backend._connections["wss://b"] = FakeSendOnlyWs(fail=True)
        with self.assertRaises(RuntimeError):
            self.backend.publish("regional", "hi")

    def test_publish_no_connections_at_all_raises_runtime_error(self):
        # no relay currently connected -- backend._connections is empty
        with self.assertRaises(RuntimeError):
            self.backend.publish("regional", "hi")


class FakeWebSocket:
    """Fake async WebSocket connection standing in for websockets'
    WebSocketClientProtocol: an async context manager that's also an async
    iterator over a scripted list of raw text frames, with a send() that
    records outgoing text. Used only for the start()-wiring integration
    test below; PublishTests uses the simpler FakeSendOnlyWs since it
    bypasses start()/_relay_loop entirely.
    """

    def __init__(self, scripted_frames=None):
        self._frames = list(scripted_frames or [])
        self.sent = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def send(self, data):
        self.sent.append(data)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._frames:
            raise StopAsyncIteration
        return self._frames.pop(0)


class NostrBackendStartIntegrationTests(unittest.TestCase):
    """Exercises NostrBackend.start() against a fake `websockets` module
    injected via sys.modules (never a real import, per the module's
    no-network-in-tests constraint -- meshcore precedent) -- confirms the
    REQ-per-channel wiring and that a scripted good-sig EVENT flows all the
    way from the fake socket into the backend's queue.
    """

    def test_start_sends_req_and_queues_scripted_event(self):
        cfg = loaded_cfg()
        good_event = nip01.sign_event(GOLDEN_PRIVKEY_HEX, 1700000300, 1, [],
                                      "integration hello")
        fake_ws = FakeWebSocket(scripted_frames=[
            json.dumps(["EVENT", "rf-regional", good_event]),
            json.dumps(["EOSE", "rf-regional"]),
        ])
        fake_module = types.ModuleType("websockets")
        fake_module.connect = lambda url, **kw: fake_ws

        backend = plug.NostrBackend(cfg["relays"], cfg["channels"], IDENTITY)
        with mock.patch.dict(sys.modules, {"websockets": fake_module}):
            backend.start()
        self.addCleanup(_stop_and_close_loop, backend._loop)

        deadline = time.time() + 2
        while backend._queue.qsize() < 1 and time.time() < deadline:
            time.sleep(0.01)

        self.assertEqual(len(fake_ws.sent), 1)
        req = json.loads(fake_ws.sent[0])
        self.assertEqual(req[0], "REQ")
        self.assertEqual(req[1], "rf-regional")
        self.assertEqual(req[2], {"kinds": [1], "#t": ["pasadena"]})

        channel, _sender, text, _ts = backend._queue.get_nowait()
        self.assertEqual(channel, "regional")
        self.assertEqual(text, "integration hello")


class FakeBackend:
    """Captures publish() calls; events() replays a scripted list of
    already-normalized (channel, sender, text, ts) tuples -- the shape
    NostrBackend.events() actually yields (verification/normalization
    happens backend-side; see NostrBackend/Bridge docstrings), unlike
    meshcore's FakeBackend which replays raw dicts for Bridge-side
    normalization."""

    def __init__(self, scripted_events=None):
        self.published = []
        self.fail_with = None
        self._scripted = scripted_events or []

    def publish(self, channel, text):
        if self.fail_with:
            raise self.fail_with
        self.published.append((channel, text))

    def events(self):
        yield from self._scripted


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = loaded_cfg()
        self.backend = FakeBackend()
        self.sock = FakeSock()
        self.bridge = plug.Bridge(self.cfg, self.backend, self.sock)

    def test_sent_cache_ttl_is_one_hour(self):
        self.assertEqual(self.bridge.sent_cache.ttl, 3600)

    def test_inbound_event_bridges(self):
        self.bridge.handle_event(
            ("regional", f"nostr:{GOLDEN_PUBKEY_HEX}", "hello", 1700000000))
        frames = self.sock.frames()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["t"], "inbound")
        self.assertEqual(frames[0]["endpoint"], "regional")
        self.assertEqual(frames[0]["sender"], f"nostr:{GOLDEN_PUBKEY_HEX}")
        self.assertEqual(frames[0]["body"], "hello")

    def test_loop_guard_drops_reechoed_own_text(self):
        # our own published note comes back to us on the subscription we
        # hold for the same channel/relay -- must not re-bridge.
        self.bridge.handle_send({"corr": 1, "endpoint": "regional", "body": "out"})
        self.assertEqual(len(self.sock.frames()), 1)  # only the delivery_result
        self.bridge.handle_event(("regional", "nostr:someone", "out", 1700000001))
        self.assertEqual(len(self.sock.frames()), 1)  # still just the delivery_result

    def test_loop_guard_different_text_still_flows(self):
        self.bridge.handle_send({"corr": 1, "endpoint": "regional", "body": "out"})
        self.bridge.handle_event(("regional", "nostr:someone", "different", 1700000002))
        frames = self.sock.frames()
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[-1]["t"], "inbound")
        self.assertEqual(frames[-1]["body"], "different")

    def test_publish_call_args(self):
        self.bridge.handle_send({"corr": 2, "endpoint": "regional", "body": "ping"})
        self.assertEqual(self.backend.published, [("regional", "ping")])

    def test_send_success_delivered_true(self):
        self.bridge.handle_send({"corr": 3, "endpoint": "regional", "body": "hi"})
        frames = self.sock.frames()
        self.assertEqual(frames[-1],
                         {"t": "delivery_result", "corr": 3,
                          "delivered": True, "detail": None})

    def test_send_unknown_endpoint_delivered_false(self):
        self.bridge.handle_send({"corr": 4, "endpoint": "nope", "body": "hi"})
        frames = self.sock.frames()
        self.assertFalse(frames[-1]["delivered"])
        self.assertEqual(self.backend.published, [])

    def test_send_backend_failure_delivered_false_with_detail(self):
        self.backend.fail_with = RuntimeError("relay unreachable")
        self.bridge.handle_send({"corr": 5, "endpoint": "regional", "body": "hi"})
        frames = self.sock.frames()
        self.assertFalse(frames[-1]["delivered"])
        self.assertIn("relay unreachable", frames[-1]["detail"])

    def test_send_failure_does_not_poison_loop_guard(self):
        # a failed publish must not record into SentCache: it never
        # actually went out to any relay, so a later inbound event of the
        # same text is a real (not echoed) message and must still bridge.
        self.backend.fail_with = RuntimeError("relay unreachable")
        self.bridge.handle_send({"corr": 5, "endpoint": "regional", "body": "out"})
        self.backend.fail_with = None
        self.bridge.handle_event(("regional", "nostr:someone", "out", 1700000003))
        frames = self.sock.frames()
        self.assertEqual(len(frames), 2)  # failed delivery_result + inbound
        self.assertEqual(frames[-1]["t"], "inbound")
        self.assertEqual(frames[-1]["body"], "out")

    def test_oversize_body_defensive_drop(self):
        cfg = loaded_cfg(max_text_bytes=5)
        bridge = plug.Bridge(cfg, self.backend, self.sock)
        bridge.handle_send({"corr": 6, "endpoint": "regional", "body": "way too long"})
        frames = self.sock.frames()
        self.assertFalse(frames[-1]["delivered"])
        self.assertIsNotNone(frames[-1]["detail"])
        self.assertEqual(self.backend.published, [])


if __name__ == "__main__":
    unittest.main()
