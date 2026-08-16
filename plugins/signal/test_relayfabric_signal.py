import os
import shutil
import sys
import tempfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lxmf"))

import unittest

import relayfabric_signal as plug

OWN = "+15550001111"


def data_event(source="+15552223333", uuid="abc-uuid", group="GRP==", text="hi",
               ts=1755280000000, attachments=None):
    msg = {"message": text, "groupInfo": {"groupId": group}}
    if attachments is not None:
        msg["attachments"] = attachments
    return {"envelope": {
        "source": source, "sourceNumber": source, "sourceUuid": uuid,
        "timestamp": ts,
        "dataMessage": msg,
    }}


def sync_event(group="GRP==", text="hi", ts=1755280000000):
    return {"envelope": {
        "source": OWN, "sourceNumber": OWN, "sourceUuid": "own-uuid",
        "timestamp": ts,
        "syncMessage": {"sentMessage": {"message": text,
                                        "groupInfo": {"groupId": group}}},
    }}


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = plug.load_config({"account": OWN, "groups": {"pas": "GRP=="}})
        self.assertEqual(cfg["rpc_url"], "http://127.0.0.1:7583")
        self.assertIsNone(cfg["allowed_users"])
        self.assertEqual(cfg["attachment_dir"],
                          "~/.local/share/signal-cli/attachments")
        self.assertEqual(cfg["max_attachment_bytes"], 8_000_000)

    def test_required_fields(self):
        with self.assertRaises(ValueError):
            plug.load_config({"groups": {"pas": "G"}})
        with self.assertRaises(ValueError):
            plug.load_config({"account": OWN})
        with self.assertRaises(ValueError):
            plug.load_config({"account": OWN, "groups": {}})

    def test_attachment_config_overridable(self):
        cfg = plug.load_config({"account": OWN, "groups": {"pas": "GRP=="},
                                "attachment_dir": "/custom/dir",
                                "max_attachment_bytes": 500})
        self.assertEqual(cfg["attachment_dir"], "/custom/dir")
        self.assertEqual(cfg["max_attachment_bytes"], 500)


class ParserTests(unittest.TestCase):
    def test_data_message_parsed_uuid_preferred(self):
        source, group, text, ts, attachments = plug.parse_signal_event(data_event(), OWN)
        self.assertEqual(source, "abc-uuid")
        self.assertEqual(group, "GRP==")
        self.assertEqual(text, "hi")
        self.assertEqual(ts, 1755280000000)
        self.assertEqual(attachments, [])

    def test_sync_sent_message_parsed(self):
        _, group, text, _, attachments = plug.parse_signal_event(sync_event(), OWN)
        self.assertEqual(group, "GRP==")
        self.assertEqual(text, "hi")
        self.assertEqual(attachments, [])

    def test_own_account_non_sync_dropped(self):
        ev = data_event(source=OWN, uuid="own-uuid")
        self.assertIsNone(plug.parse_signal_event(ev, OWN))

    def test_no_text_no_attachments_dropped(self):
        self.assertIsNone(plug.parse_signal_event(data_event(text=""), OWN))

    def test_sourceless_dropped(self):
        ev = data_event()
        for k in ("source", "sourceNumber", "sourceUuid"):
            ev["envelope"].pop(k)
        self.assertIsNone(plug.parse_signal_event(ev, OWN))

    def test_attachments_only_message_kept(self):
        atts = [{"id": "att1", "filename": "photo.jpg", "contentType": "image/jpeg"}]
        source, _group, text, _ts, attachments = plug.parse_signal_event(
            data_event(text="", attachments=atts), OWN)
        self.assertEqual(source, "abc-uuid")
        self.assertEqual(text, "")
        self.assertEqual(attachments, atts)

    def test_dm_yields_group_none(self):
        ev = data_event()
        del ev["envelope"]["dataMessage"]["groupInfo"]
        _, group, _, _, _ = plug.parse_signal_event(ev, OWN)
        self.assertIsNone(group)


class SentCacheTests(unittest.TestCase):
    def test_match_consumes(self):
        c = plug.SentCache(ttl_secs=60)
        c.record("G", "body")
        self.assertTrue(c.match("G", "body"))
        self.assertFalse(c.match("G", "body"))

    def test_expiry_and_group_scoping(self):
        c = plug.SentCache(ttl_secs=60)
        c.record("G", "body", now=1000.0)
        self.assertFalse(c.match("H", "body", now=1001.0))
        self.assertFalse(c.match("G", "body", now=1061.0))


class LoadSignalAttachmentsTests(unittest.TestCase):
    """load_signal_attachments: ported from rns-signal-gateway's
    (gateway.py:511-529) function of the same name."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_loads_existing_file_with_content_type(self):
        with open(os.path.join(self.dir, "photo.jpg"), "wb") as f:
            f.write(b"jpegbytes")
        loaded, notes = plug.load_signal_attachments(
            self.dir,
            [{"id": "photo.jpg", "filename": "photo.jpg", "contentType": "image/jpeg"}])
        self.assertEqual(loaded, [("photo.jpg", "image/jpeg", b"jpegbytes")])
        self.assertEqual(notes, [])

    def test_missing_content_type_defaults_empty_string(self):
        with open(os.path.join(self.dir, "f.bin"), "wb") as f:
            f.write(b"x")
        loaded, _ = plug.load_signal_attachments(self.dir, [{"id": "f.bin"}])
        self.assertEqual(loaded, [("f.bin", "", b"x")])

    def test_missing_file_notes_unavailable(self):
        loaded, notes = plug.load_signal_attachments(
            self.dir, [{"id": "ghost.jpg", "filename": "ghost.jpg"}])
        self.assertEqual(loaded, [])
        self.assertEqual(notes, ["[attachment ghost.jpg unavailable]"])

    def test_no_id_notes_unavailable(self):
        loaded, notes = plug.load_signal_attachments(
            self.dir, [{"filename": "noid.txt"}])
        self.assertEqual(loaded, [])
        self.assertEqual(notes, ["[attachment noid.txt unavailable]"])

    def test_oversize_file_dropped_with_note(self):
        path = os.path.join(self.dir, "big.bin")
        with open(path, "wb") as f:
            f.seek(plug.ATTACHMENT_LOAD_CAP)
            f.write(b"\0")
        loaded, notes = plug.load_signal_attachments(
            self.dir, [{"id": "big.bin", "filename": "big.bin"}])
        self.assertEqual(loaded, [])
        self.assertEqual(len(notes), 1)
        self.assertIn("big.bin", notes[0])

    def test_path_traversal_id_never_escapes_attachment_dir(self):
        # basename() strips the traversal, so this resolves to
        # <dir>/passwd -- which doesn't exist there, so it must be
        # reported unavailable, and /etc/passwd itself must never be read.
        loaded, notes = plug.load_signal_attachments(
            self.dir, [{"id": "../../etc/passwd", "filename": "passwd"}])
        self.assertEqual(loaded, [])
        self.assertEqual(notes, ["[attachment passwd unavailable]"])

    def test_expanduser_applied_at_use(self):
        with open(os.path.join(self.dir, "h.txt"), "wb") as f:
            f.write(b"home")
        with mock.patch.dict(os.environ, {"HOME": self.dir}):
            loaded, _ = plug.load_signal_attachments("~", [{"id": "h.txt"}])
        self.assertEqual(loaded, [("h.txt", "", b"home")])


class CapAttachmentsTests(unittest.TestCase):
    def test_keeps_items_under_cap(self):
        kept, notes = plug.cap_attachments([("a.txt", "text/plain", b"1234")], 10)
        self.assertEqual(kept, [("a.txt", "text/plain", b"1234")])
        self.assertEqual(notes, [])

    def test_drops_items_over_cap_with_note(self):
        kept, notes = plug.cap_attachments(
            [("big.bin", "application/octet-stream", b"x" * 20)], 10)
        self.assertEqual(kept, [])
        self.assertEqual(notes, ["[dropped big.bin: 20 B over 10 B limit]"])

    def test_mixed_keeps_only_under_cap(self):
        loaded = [("small.txt", "text/plain", b"ok"),
                  ("big.bin", "application/octet-stream", b"x" * 20)]
        kept, notes = plug.cap_attachments(loaded, 10)
        self.assertEqual(kept, [("small.txt", "text/plain", b"ok")])
        self.assertEqual(len(notes), 1)


class FakeBackend:
    def __init__(self):
        self.sent = []
        self.fail_with = None

    def send_group(self, group_id, text, attachment_paths=None):
        if self.fail_with:
            raise self.fail_with
        captured = []
        for p in (attachment_paths or []):
            with open(p, "rb") as f:
                captured.append((os.path.basename(p), f.read()))
        self.sent.append((group_id, text, captured))


class FakeSock:
    """Captures frames the bridge writes to the daemon."""
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


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.cfg = plug.load_config(
            {"account": OWN, "groups": {"pas": "GRP=="}})
        self.backend = FakeBackend()
        self.sock = FakeSock()
        self.bridge = plug.Bridge(self.cfg, self.backend, self.sock)

    def test_inbound_mapped_group_bridges(self):
        self.bridge.handle_event(data_event())
        frames = self.sock.frames()
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["t"], "inbound")
        self.assertEqual(frames[0]["endpoint"], "pas")
        self.assertEqual(frames[0]["sender"], "abc-uuid")
        self.assertEqual(frames[0]["body"], "hi")
        self.assertEqual(frames[0]["attachments"], [])

    def test_unmapped_group_and_dm_dropped(self):
        self.bridge.handle_event(data_event(group="OTHER=="))
        ev = data_event()
        del ev["envelope"]["dataMessage"]["groupInfo"]
        self.bridge.handle_event(ev)
        self.assertEqual(self.sock.frames(), [])

    def test_allowed_users_acl(self):
        self.cfg["allowed_users"] = ["someone-else"]
        bridge = plug.Bridge(self.cfg, self.backend, self.sock)
        bridge.handle_event(data_event())
        self.assertEqual(self.sock.frames(), [])

    def test_allowed_users_empty_list_denies_all(self):
        self.cfg["allowed_users"] = []
        bridge = plug.Bridge(self.cfg, self.backend, self.sock)
        bridge.handle_event(data_event())
        self.assertEqual(self.sock.frames(), [])

    def test_send_success_records_loop_guard(self):
        self.bridge.handle_send({"corr": 5, "endpoint": "pas", "body": "out"})
        self.assertEqual(self.backend.sent, [("GRP==", "out", [])])
        frames = self.sock.frames()
        self.assertEqual(frames[-1],
                         {"t": "delivery_result", "corr": 5,
                          "delivered": True, "detail": None})
        # the sync echo of our own post is now dropped
        self.bridge.handle_event(sync_event(text="out"))
        self.assertEqual(len(self.sock.frames()), 1)  # still only the result

    def test_send_failure_reports_detail(self):
        self.backend.fail_with = RuntimeError("boom")
        self.bridge.handle_send({"corr": 6, "endpoint": "pas", "body": "x"})
        frames = self.sock.frames()
        self.assertFalse(frames[-1]["delivered"])
        self.assertIn("boom", frames[-1]["detail"])

    def test_send_unknown_endpoint(self):
        self.bridge.handle_send({"corr": 7, "endpoint": "nope", "body": "x"})
        self.assertFalse(self.sock.frames()[-1]["delivered"])
        self.assertEqual(self.backend.sent, [])


class BridgeInboundAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = plug.load_config(
            {"account": OWN, "groups": {"pas": "GRP=="},
             "attachment_dir": self.dir, "max_attachment_bytes": 1000})
        self.backend = FakeBackend()
        self.sock = FakeSock()
        self.bridge = plug.Bridge(self.cfg, self.backend, self.sock)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_loaded_attachment_bridges_as_relay_ipc_attachment(self):
        with open(os.path.join(self.dir, "photo.jpg"), "wb") as f:
            f.write(b"jpegbytes")
        atts = [{"id": "photo.jpg", "filename": "photo.jpg", "contentType": "image/jpeg"}]
        self.bridge.handle_event(data_event(text="look", attachments=atts))
        frame = self.sock.frames()[0]
        self.assertEqual(frame["body"], "look")
        self.assertEqual(len(frame["attachments"]), 1)
        att = frame["attachments"][0]
        self.assertEqual(att["filename"], "photo.jpg")
        self.assertEqual(att["mime"], "image/jpeg")
        self.assertEqual(att["data"], b"jpegbytes")

    def test_missing_contenttype_falls_back_to_octet_stream(self):
        with open(os.path.join(self.dir, "f.bin"), "wb") as f:
            f.write(b"x")
        atts = [{"id": "f.bin", "filename": "f.bin"}]
        self.bridge.handle_event(data_event(text="hi", attachments=atts))
        att = self.sock.frames()[0]["attachments"][0]
        self.assertEqual(att["mime"], "application/octet-stream")

    def test_unavailable_attachment_notes_appended_to_body(self):
        atts = [{"id": "ghost.jpg", "filename": "ghost.jpg"}]
        self.bridge.handle_event(data_event(text="", attachments=atts))
        frame = self.sock.frames()[0]
        self.assertEqual(frame["body"], "[attachment ghost.jpg unavailable]")
        self.assertEqual(frame["attachments"], [])

    def test_oversize_attachment_dropped_with_note(self):
        with open(os.path.join(self.dir, "big.bin"), "wb") as f:
            f.write(b"x" * 2000)  # over cfg max_attachment_bytes=1000
        atts = [{"id": "big.bin", "filename": "big.bin"}]
        self.bridge.handle_event(data_event(text="hi", attachments=atts))
        frame = self.sock.frames()[0]
        self.assertIn("dropped big.bin", frame["body"])
        self.assertEqual(frame["attachments"], [])

    def test_path_traversal_id_never_escapes_attachment_dir(self):
        atts = [{"id": "../../etc/passwd", "filename": "passwd"}]
        self.bridge.handle_event(data_event(text="", attachments=atts))
        frame = self.sock.frames()[0]
        self.assertEqual(frame["attachments"], [])
        self.assertIn("unavailable", frame["body"])


class BridgeEgressAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.cfg = plug.load_config(
            {"account": OWN, "groups": {"pas": "GRP=="}, "max_attachment_bytes": 1000})
        self.backend = FakeBackend()
        self.sock = FakeSock()
        self.bridge = plug.Bridge(self.cfg, self.backend, self.sock)

    def test_attachments_written_to_tempdir_and_sent(self):
        frame = {"corr": 1, "endpoint": "pas", "body": "look",
                 "attachments": [{"filename": "photo.jpg", "mime": "image/jpeg",
                                   "data": b"jpegbytes"}]}
        self.bridge.handle_send(frame)
        self.assertEqual(len(self.backend.sent), 1)
        group_id, text, captured = self.backend.sent[0]
        self.assertEqual(group_id, "GRP==")
        self.assertEqual(text, "look")
        self.assertEqual(captured, [("photo.jpg", b"jpegbytes")])
        self.assertTrue(self.sock.frames()[-1]["delivered"])

    def test_attachment_filename_basename_sanitized(self):
        frame = {"corr": 1, "endpoint": "pas", "body": "x",
                 "attachments": [{"filename": "../../etc/evil.sh", "mime": "text/plain",
                                   "data": b"payload"}]}
        self.bridge.handle_send(frame)
        _, _, captured = self.backend.sent[0]
        self.assertEqual(captured, [("evil.sh", b"payload")])

    def test_oversize_attachment_dropped_with_note_but_sends_text(self):
        frame = {"corr": 1, "endpoint": "pas", "body": "x",
                 "attachments": [{"filename": "big.bin", "mime": "application/octet-stream",
                                   "data": b"y" * 2000}]}
        self.bridge.handle_send(frame)
        _, text, captured = self.backend.sent[0]
        self.assertIn("dropped big.bin", text)
        self.assertEqual(captured, [])
        self.assertTrue(self.sock.frames()[-1]["delivered"])

    def test_tempdir_removed_after_send(self):
        real_send = self.backend.send_group
        captured_dirs = []

        def spy(group_id, text, attachment_paths=None):
            if attachment_paths:
                captured_dirs.append(os.path.dirname(attachment_paths[0]))
            return real_send(group_id, text, attachment_paths)

        self.backend.send_group = spy
        frame = {"corr": 1, "endpoint": "pas", "body": "x",
                 "attachments": [{"filename": "a.bin", "mime": "application/octet-stream",
                                   "data": b"z"}]}
        self.bridge.handle_send(frame)
        self.assertTrue(captured_dirs)
        self.assertFalse(os.path.isdir(captured_dirs[0]))

    def test_no_attachments_sends_empty_captured(self):
        frame = {"corr": 1, "endpoint": "pas", "body": "x"}
        self.bridge.handle_send(frame)
        _, _, captured = self.backend.sent[0]
        self.assertEqual(captured, [])


if __name__ == "__main__":
    unittest.main()
