import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import ledger  # noqa: E402


class TestMigrate(unittest.TestCase):
    def test_sets_current_schema_version(self):
        L = ledger.migrate({"schema_version": "1.0", "findings": []})
        self.assertEqual(L["schema_version"], ledger.CURRENT_SCHEMA)

    def test_fills_missing_top_level_keys(self):
        L = ledger.migrate({})
        self.assertIsInstance(L["run"], dict)
        self.assertIsInstance(L["findings"], list)
        self.assertEqual(L["schema_version"], ledger.CURRENT_SCHEMA)

    def test_preserves_findings_and_state(self):
        src = {"schema_version": "1.0", "findings": [
            {"id": "VULN-1", "status": "closed", "triage": {"priority": "P0"}}]}
        L = ledger.migrate(src)
        self.assertEqual(len(L["findings"]), 1)
        self.assertEqual(L["findings"][0]["status"], "closed")
        self.assertEqual(L["findings"][0]["triage"]["priority"], "P0")

    def test_finding_without_status_gets_default(self):
        L = ledger.migrate({"findings": [{"id": "VULN-9"}]})
        self.assertEqual(L["findings"][0]["status"], "hypothesis")

    def test_is_idempotent(self):
        once = ledger.migrate({"findings": [{"id": "VULN-1"}]})
        twice = ledger.migrate(dict(once))
        self.assertEqual(once, twice)


class TestResumePoint(unittest.TestCase):
    def _rp(self, findings, **kw):
        L = {"findings": findings}
        L.update(kw)
        return ledger.resume_point(ledger.migrate(L))

    def test_no_findings_suggests_scan(self):
        self.assertEqual(self._rp([])["next_command"], "/vuln-hunter:scan")

    def test_sast_without_exploitability_suggests_redteam(self):
        rp = self._rp([{"id": "V1", "source": "sast", "sast": {}, "status": "hypothesis"}])
        self.assertEqual(rp["next_command"], "/vuln-hunter:redteam all")

    def test_exploitability_without_triage_suggests_triage(self):
        rp = self._rp([{"id": "V1", "source": "sast", "sast": {}, "exploitability": {"verdict": "EXPLOITABLE"}, "status": "confirmed"}])
        self.assertEqual(rp["next_command"], "/vuln-hunter:triage")

    def test_triaged_open_suggests_fix(self):
        rp = self._rp([{"id": "V1", "sast": {}, "exploitability": {}, "triage": {"priority": "P1"}, "status": "triaged"}])
        self.assertEqual(rp["next_command"], "/vuln-hunter:fix all")

    def test_fixed_suggests_verify(self):
        rp = self._rp([{"id": "V1", "sast": {}, "exploitability": {}, "triage": {}, "fix": {}, "status": "fixed"}])
        self.assertEqual(rp["next_command"], "/vuln-hunter:verify all")

    def test_all_closed_suggests_report(self):
        rp = self._rp([{"id": "V1", "sast": {}, "exploitability": {}, "triage": {}, "fix": {}, "verification": {}, "status": "closed"}])
        self.assertEqual(rp["next_command"], "/vuln-hunter:report")

    def test_completed_stages_tracked(self):
        rp = self._rp(
            [{"id": "V1", "sast": {}, "exploitability": {}, "triage": {}, "status": "triaged"}],
            attack_surface={"x": 1}, run={"stacks": ["python-django"]}, plan_ref=".vuln-hunter/plan.md")
        for stage in ["detect", "RECON", "SAST", "RED-TEAM", "TRIAGE", "plan"]:
            self.assertIn(stage, rp["completed"])
        self.assertNotIn("VERIFY", rp["completed"])


class TestFindingsUnder(unittest.TestCase):
    def setUp(self):
        self.L = {"findings": [
            {"id": "V1", "location": "apps/web/views.py:11", "status": "triaged"},
            {"id": "V2", "location": "apps/web/api/", "status": "fixed"},
            {"id": "V3", "location": "services/api/Main.cs:4", "status": "hypothesis"},
            {"id": "V4", "location": "Django@3.2.4", "status": "triaged"},
        ]}

    def test_matches_prefix_subtree(self):
        ids = [f["id"] for f in ledger.findings_under(self.L, "apps/web")]
        self.assertEqual(sorted(ids), ["V1", "V2"])

    def test_trailing_slash_ignored(self):
        ids = [f["id"] for f in ledger.findings_under(self.L, "apps/web/")]
        self.assertEqual(sorted(ids), ["V1", "V2"])

    def test_no_false_prefix_match(self):
        # "apps/we" must NOT match "apps/web/..."
        self.assertEqual(ledger.findings_under(self.L, "apps/we"), [])


if __name__ == "__main__":
    unittest.main()
