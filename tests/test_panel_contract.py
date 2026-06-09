import json
import os
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")


class TestFixtureShape(unittest.TestCase):
    def test_sample_ledger_is_valid_json_with_findings(self):
        with open(os.path.join(ROOT, "tests/fixtures/ledger.sample.json")) as fh:
            L = json.load(fh)
        self.assertEqual(L["schema_version"], "1.0")
        self.assertTrue(len(L["findings"]) >= 3)

    def test_sample_activity_is_valid_jsonl(self):
        path = os.path.join(ROOT, "tests/fixtures/activity.sample.jsonl")
        with open(path) as fh:
            lines = [ln for ln in fh.read().split("\n") if ln.strip()]
        for ln in lines:
            rec = json.loads(ln)
            self.assertIn("type", rec)
            self.assertIn("ts", rec)


class TestPanelReferences(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "panel/index.html")) as fh:
            self.html = fh.read()

    def test_fetches_both_data_files(self):
        self.assertIn("ledger.json", self.html)
        self.assertIn("activity.jsonl", self.html)

    def test_uses_react_and_babel_cdn(self):
        self.assertIn("react@18", self.html)
        self.assertIn("babel", self.html)

    def test_renders_core_sections(self):
        for token in ["AgentRoster", "PipelineBar", "FindingsTable", "ActivityTimeline"]:
            self.assertIn(token, self.html)

    def test_polls_on_an_interval(self):
        self.assertIn("setInterval", self.html)


if __name__ == "__main__":
    unittest.main()
