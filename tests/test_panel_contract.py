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
        for token in ["PipelineGraph", "Bitacora", "FindingsTable"]:
            self.assertIn(token, self.html)

    def test_pipeline_graph_is_svg_with_spinner(self):
        self.assertIn("<svg", self.html)
        self.assertIn("spin", self.html)

    def test_graph_shows_parallel_fork(self):
        # RECON se bifurca a SAST e INTEL (corren en paralelo) y reconvergen
        self.assertIn('["RECON","SAST"]', self.html)
        self.assertIn('["RECON","INTEL"]', self.html)

    def test_polls_on_an_interval(self):
        self.assertIn("setInterval", self.html)

    def test_has_lifecycle_tabs(self):
        for t in ["Encontrados", "Mitigando", "Arreglados"]:
            self.assertIn(t, self.html)

    def test_no_horizontal_scrollbars(self):
        # "evita los horizontal sliders": ningun overflow-x:auto en el panel
        self.assertNotIn("overflow-x:auto", self.html)
        self.assertNotIn("overflow-x: auto", self.html)

    def test_pipeline_graph_is_responsive(self):
        # el grafo escala al ancho del contenedor en vez de hacer scroll horizontal
        self.assertIn("ResizeObserver", self.html)

    def test_has_copyable_claude_commands(self):
        self.assertIn("navigator.clipboard", self.html)
        for c in ["/vuln-hunter:status", "/vuln-hunter:hunt", "/vuln-hunter:fix",
                  "/vuln-hunter:redteam", "/vuln-hunter:verify"]:
            self.assertIn(c, self.html)

    def test_has_resume_and_nextstep_actions(self):
        self.assertIn("Reanudar", self.html)
        self.assertIn("Siguiente paso", self.html)

    def test_supports_multi_issue_selection(self):
        self.assertIn("seleccionado", self.html)


if __name__ == "__main__":
    unittest.main()
