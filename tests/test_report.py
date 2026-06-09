import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import report  # noqa: E402


class TestComputeClosed(unittest.TestCase):
    def _L(self, findings):
        return {"schema_version": "1.2", "run": {}, "findings": findings}

    def test_closed_counts_status_closed(self):
        L = self._L([
            {"id": "V1", "status": "closed", "fix": {"applied": True},
             "verification": {"verdict": "CLOSED"}},
            {"id": "V2", "status": "fixed", "fix": {"applied": True}},
        ])
        C = report.compute(L)
        self.assertEqual(C["closed"], 1)

    def test_verified_counts_CLOSED_verdict(self):
        # Bug previo: contaba "pass"/"verified"; el verdict real del schema es CLOSED.
        L = self._L([{"id": "V1", "status": "closed",
                      "verification": {"verdict": "CLOSED"}}])
        C = report.compute(L)
        self.assertEqual(C["verified"], 1)

    def test_not_closed_verdict_does_not_count(self):
        L = self._L([{"id": "V1", "status": "fixed",
                      "verification": {"verdict": "NOT_CLOSED"}}])
        C = report.compute(L)
        self.assertEqual(C["verified"], 0)
        self.assertEqual(C["closed"], 0)

    def test_fixed_counts_applied(self):
        L = self._L([{"id": "V1", "status": "fixing", "fix": {"applied": True}}])
        self.assertEqual(report.compute(L)["fixed"], 1)


class TestBuildHtmlRich(unittest.TestCase):
    def setUp(self):
        L = {"schema_version": "1.2",
             "run": {"scope": "apps/example-app", "owasp_version": "2025"},
             "attack_surface": {"entrypoints": ["a.py"]},
             "findings": [
                 {"id": "V1", "title": "SQLi", "status": "closed", "source": "sast",
                  "owasp_2025": "A03:2025-Injection", "cwe": "CWE-89",
                  "triage": {"priority": "P0"}, "fix": {"applied": True, "root_cause": "rc", "summary": "param"},
                  "verification": {"verdict": "CLOSED", "evidence": "tests ok"}},
             ]}
        self.md = report.build_md(L, "x")
        self.html = report.build_html(self.md, False, "r.md", "r.pdf", L)

    def test_html_has_table_of_contents(self):
        self.assertIn('class="toc"', self.html)

    def test_html_has_svg_charts(self):
        self.assertIn("<svg", self.html)

    def test_html_has_glossary(self):
        self.assertIn("Glosario", self.md)

    def test_acronyms_get_abbr_tooltips(self):
        # CVSS/OWASP/CWE/CISA aparecen en el cuerpo; deben envolverse en <abbr title=...>
        self.assertIn("<abbr", self.html)
        self.assertIn('title="', self.html)

    def test_acronyms_not_wrapped_inside_code(self):
        # No debe romper el contenido en <code> (p.ej. rutas o reglas)
        self.assertNotIn("<code><abbr", self.html)

    def test_no_sidestripe_border_left_accent(self):
        # Ley impeccable: nada de border-left >1px como acento
        self.assertNotIn("border-left:4px", self.html)
        self.assertNotIn("border-left:2px solid transparent", self.html)

    def test_has_verdict_callout(self):
        self.assertIn("verdict", self.html)

    def test_severity_tokens_become_colored_chips(self):
        self.assertIn("sev-chip", self.html)

    def test_has_risk_matrix(self):
        self.assertIn("Riesgo", self.html)
        self.assertIn("matrix", self.html)


class TestRiskVerdict(unittest.TestCase):
    def test_p0_open_is_high_risk(self):
        L = {"findings": [{"id": "V1", "status": "triaged", "triage": {"priority": "P0"}}]}
        lvl, _txt, _c = report.risk_verdict(L)
        self.assertEqual(lvl, "alto")

    def test_all_closed_is_controlled(self):
        L = {"findings": [{"id": "V1", "status": "closed", "triage": {"priority": "P0"}}]}
        lvl, _txt, _c = report.risk_verdict(L)
        self.assertEqual(lvl, "controlado")


if __name__ == "__main__":
    unittest.main()
