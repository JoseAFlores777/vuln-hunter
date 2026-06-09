import json
import os
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import activity  # noqa: E402


class TestParseFields(unittest.TestCase):
    def test_parses_key_value_pairs(self):
        self.assertEqual(
            activity.parse_fields(["stage=SAST", "agent=sast-analyst"]),
            {"stage": "SAST", "agent": "sast-analyst"},
        )

    def test_value_may_contain_equals_and_spaces(self):
        self.assertEqual(
            activity.parse_fields(["summary=3 findings = ok"]),
            {"summary": "3 findings = ok"},
        )

    def test_ignores_tokens_without_equals(self):
        self.assertEqual(activity.parse_fields(["garbage", "k=v"]), {"k": "v"})


class TestAppendEvent(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "nested", "activity.jsonl")

    def test_appends_valid_jsonl_with_ts_and_type(self):
        rc = activity.append_event("stage:start", {"stage": "SAST"}, self.path)
        self.assertEqual(rc, 0)
        with open(self.path) as fh:
            lines = fh.read().strip().split("\n")
        self.assertEqual(len(lines), 1)
        rec = json.loads(lines[0])
        self.assertEqual(rec["type"], "stage:start")
        self.assertEqual(rec["stage"], "SAST")
        self.assertIsInstance(rec["ts"], str)

    def test_appends_do_not_overwrite(self):
        activity.append_event("run:start", {}, self.path)
        activity.append_event("run:done", {}, self.path)
        with open(self.path) as fh:
            lines = fh.read().strip().split("\n")
        self.assertEqual(len(lines), 2)

    def test_finding_state_is_a_valid_event(self):
        rc = activity.append_event("finding:state", {"id": "VULN-1", "state": "fixing"}, self.path)
        self.assertEqual(rc, 0)
        with open(self.path) as fh:
            rec = json.loads(fh.read().strip())
        self.assertEqual(rec["type"], "finding:state")
        self.assertEqual(rec["state"], "fixing")

    def test_unknown_type_returns_2_and_writes_nothing(self):
        rc = activity.append_event("bogus:type", {}, self.path)
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main()
