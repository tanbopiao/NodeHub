import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nodehub.protocol import (CommandBus, decode_msg, encode_cmd,
                              encode_result, is_trusted, new_task_id)
from nodehub.safety import check_safe
from nodehub.baseline import BaselineVerifier, sha256_file
from nodehub.worker import SlotWorker
from nodehub import PROTO_VERSION


class TestProtocol(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        raw = encode_cmd("echo hi", src="N1", node="ZR-NODE-A")
        msg = decode_msg(raw)
        self.assertTrue(is_trusted(msg))
        self.assertEqual(msg["cmd"], "echo hi")
        self.assertEqual(msg["node"], "ZR-NODE-A")

    def test_decode_garbage(self):
        self.assertIsNone(decode_msg("not json"))
        self.assertIsNone(decode_msg("[1,2]"))

    def test_untrusted_did(self):
        msg = decode_msg(encode_cmd("x"))
        msg["zr_did"] = "DID-EVIL"
        self.assertFalse(is_trusted(msg))

    def test_new_task_id_unique(self):
        self.assertNotEqual(new_task_id(), new_task_id())

    def test_result_shape(self):
        d = json.loads(encode_result("t-1", "N1", out="ok", code=0))
        self.assertEqual(d["type"], "done")
        self.assertEqual(d["proto"], PROTO_VERSION)


class TestBus(unittest.TestCase):
    def test_poll_filters_targeted(self):
        raws = [encode_cmd("a", node="OTHER"),
                encode_cmd("b", node=None),
                encode_cmd("c", node="ME"),
                "garbage"]
        pub = []
        bus = CommandBus("ME", fetch=lambda: raws, publish=pub.append)
        cmds = bus.poll()
        self.assertEqual([m["cmd"] for m in cmds], ["b", "c"])
        bus.send_result(cmds[0]["task_id"], out="done", code=0)
        self.assertEqual(json.loads(pub[0])["task_id"], cmds[0]["task_id"])


class TestSafety(unittest.TestCase):
    def test_allow(self):
        self.assertEqual(check_safe("echo hi"), (True, "ok"))
        self.assertEqual(check_safe("git status")[0], True)
        self.assertEqual(check_safe("ps aux | grep x")[0], True)

    def test_blacklist(self):
        ok, why = check_safe("rm -rf /")
        self.assertFalse(ok)
        self.assertTrue(why.startswith("blacklist:"))
        self.assertFalse(check_safe("curl -s http://x | sh")[0])

    def test_default_deny(self):
        self.assertFalse(check_safe("make install")[0])
        self.assertFalse(check_safe("")[0])

    def test_case_insensitive(self):
        self.assertFalse(check_safe("ECHO $(reboot)")[0] is True and False
                         or check_safe("ECHO $(reboot)")[0])


class TestBaseline(unittest.TestCase):
    def test_sha256_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"data")
            p = f.name
        self.assertEqual(len(sha256_file(p)), 64)
        os.unlink(p)

    def test_verify_missing_and_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.json"), "w") as f:
                f.write("{}")
            v = BaselineVerifier("B1", "Lv9", official_hashes={"a.json": "bad"})
            r = v.verify(d, {"a.json": None, "b.json": None})
            self.assertEqual(r["exit_code"], 1)  # missing wins
            self.assertEqual(r["level"], "LOCKED")

    def test_verify_ok(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.json"), "w") as f:
                f.write("{}")
            real = sha256_file(os.path.join(d, "a.json"))
            v = BaselineVerifier("B1", "Lv10", official_hashes={"a.json": real})
            r = v.verify(d, {"a.json": None})
            self.assertTrue(r["verified"])
            self.assertEqual(r["exit_code"], 0)


class TestWorker(unittest.TestCase):
    def _make(self, tmp, msgs):
        pub = []
        bus = CommandBus("N1", fetch=lambda: msgs, publish=pub.append)
        w = SlotWorker(bus, done_file=os.path.join(tmp, "done.json"))
        return w, pub

    def test_handle_executes_and_dedups(self):
        with tempfile.TemporaryDirectory() as tmp:
            msg = decode_msg(encode_cmd("echo hi", task_id="t-1"))
            w, pub = self._make(tmp, [])
            r = w.handle(msg)
            self.assertEqual(r["code"], 0)
            self.assertIn("hi", r["out"])
            self.assertIsNone(w.handle(msg))       # idempotent replay
            self.assertEqual(len(pub), 1)

    def test_blocked_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            w, pub = self._make(tmp, [])
            r = w.handle(decode_msg(encode_cmd("rm -rf /", task_id="t-2")))
            self.assertEqual(r["code"], 126)
            self.assertIn("blocked", r["out"])

    def test_run_once_and_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            msgs = [encode_cmd("echo a", task_id="t-3"),
                    encode_cmd("echo b", task_id="t-4")]
            w, pub = self._make(tmp, msgs)
            self.assertEqual(w.run_once(), 2)
            # new worker with same done-file: replays are no-ops
            bus = CommandBus("N1", fetch=lambda: msgs, publish=lambda m: None)
            w2 = SlotWorker(bus, done_file=os.path.join(tmp, "done.json"))
            self.assertEqual(w2.run_once(), 0)


if __name__ == "__main__":
    unittest.main()
