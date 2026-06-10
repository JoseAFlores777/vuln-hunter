import json
import os
import re
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

    def test_uses_react_cdn_without_inbrowser_babel(self):
        # React desde CDN (pineado + SRI); el JSX se pre-compila, sin Babel-en-navegador.
        self.assertIn("react@18", self.html)
        self.assertIn("integrity=", self.html)          # SRI en los scripts CDN
        self.assertNotIn("text/babel", self.html)        # nada de transpile en cliente
        self.assertNotIn("@babel/standalone", self.html)

    def test_strict_csp_without_unsafe_eval(self):
        self.assertIn("Content-Security-Policy", self.html)
        # CSP por hash sha256 del script inline; sin 'unsafe-eval'
        self.assertIn("'sha256-", self.html)
        m = re.search(r"script-src[^\"]*", self.html)
        self.assertIsNotNone(m)
        self.assertNotIn("unsafe-eval", m.group(0))

    def test_renders_core_sections(self):
        for token in ["PipelineGraph", "Bitacora", "FindingsTable"]:
            self.assertIn(token, self.html)

    def test_pipeline_graph_is_svg_with_spinner(self):
        # El JSX <svg> se compila a React.createElement("svg", ...).
        self.assertIn('createElement("svg"', self.html)
        self.assertIn("spin", self.html)

    def test_panel_source_jsx_exists(self):
        # La fuente editable del panel (se compila con scripts/build-panel.sh).
        self.assertTrue(os.path.exists(os.path.join(ROOT, "panel/app.jsx")))

    def test_run_history_selector(self):
        # Selector de corridas: carga history/index.json y permite ver pasadas.
        self.assertIn("history/index.json", self.html)
        self.assertIn("RunSelector", self.html)
        self.assertIn("En vivo", self.html)

    def test_csp_hash_matches_inline_script(self):
        # Anti-drift: el hash de la CSP DEBE corresponder al <script> inline real.
        # Si alguien edita index.html sin correr build-panel.sh, este test falla.
        import base64
        import hashlib
        csp = re.search(r"script-src[^\"]*'sha256-([A-Za-z0-9+/=]+)'", self.html)
        self.assertIsNotNone(csp, "no hay hash sha256 en la CSP")
        inline = re.search(r"<script>(.*?)</script>", self.html, re.DOTALL)
        self.assertIsNotNone(inline, "no hay <script> inline")
        calc = base64.b64encode(hashlib.sha256(inline.group(1).encode()).digest()).decode()
        self.assertEqual(
            calc, csp.group(1),
            "el hash CSP no corresponde al script inline: corre scripts/build-panel.sh",
        )

    def test_graph_shows_parallel_fork(self):
        # RECON se bifurca a SAST e INTEL (corren en paralelo) y reconvergen.
        # Tolerante al espaciado del JS compilado (["RECON", "SAST"]).
        self.assertRegex(self.html, r'\["RECON",\s*"SAST"\]')
        self.assertRegex(self.html, r'\["RECON",\s*"INTEL"\]')

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
