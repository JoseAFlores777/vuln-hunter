import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import report  # noqa: E402

SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")


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

    def test_status_closed_without_verdict_not_counted_closed(self):
        # Honestidad (CLAUDE.md regla 9): status:closed sin verdict CLOSED NO cuenta.
        L = self._L([{"id": "V1", "status": "closed", "triage": {"priority": "P0"}}])
        C = report.compute(L)
        self.assertEqual(C["closed"], 0)
        self.assertEqual(C["closed_unverified"], 1)

    def test_rescan_autofix_not_counted_as_fixed(self):
        # Un 'fixed' por desaparecer del rescan no es evidencia de correccion.
        L = self._L([{"id": "V1", "status": "fixed",
                      "fix": {"applied": True, "source": "rescan"}}])
        self.assertEqual(report.compute(L)["fixed"], 0)

    def test_candidate_resolved_not_closed_not_fixed(self):
        # 'desaparecio en rescan' sigue abierto: no cuenta como cerrado ni corregido.
        L = self._L([{"id": "V1", "status": "candidate-resolved", "triage": {"priority": "P1"}}])
        C = report.compute(L)
        self.assertEqual(C["closed"], 0)
        self.assertEqual(C["fixed"], 0)
        self.assertTrue(report.is_open(L["findings"][0]))

    def test_nondict_finding_does_not_crash_compute(self):
        L = self._L(["poison", {"id": "V1", "status": "closed",
                                "verification": {"verdict": "CLOSED"}}])
        self.assertEqual(report.compute(L)["closed"], 1)


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

    def test_no_border_left_anywhere(self):
        # Version mas estricta que test_no_sidestripe_border_left_accent: cero
        # declaraciones border-left en todo el documento, ni siquiera nuevas.
        self.assertNotIn("border-left", self.html)

    def test_technical_html_has_collapsible_diagnostic_cards(self):
        # Requerimiento 4/10c: cards nativas <details class="fcard">, abiertas por
        # defecto solo para P0/P1/KEV (server-rendered, sin flash de JS).
        self.assertIn('<details class="fcard"', self.html)
        self.assertIn('id="V1"', self.html)
        # V1 es P0 -> debe venir con el atributo open ya server-rendered.
        self.assertRegex(self.html, r'<details class="fcard"[^>]*id="V1"[^>]* open>')

    def test_html_self_contained_no_external_resources(self):
        # El informe debe seguir siendo 100% offline: nada de <script src=http...>,
        # <link ... href=http...> ni @import remoto (los <a href=https://nvd...>
        # de justificacion SI estan permitidos, son contenido, no una carga de red).
        self.assertNotIn("<script src=", self.html)
        self.assertNotIn('href="http', self.html.split("<body")[0])  # nada externo en <head>
        self.assertNotIn("fonts.googleapis.com", self.html)
        self.assertNotIn("unpkg.com", self.html)
        self.assertNotIn("@import", self.html)


class TestRiskVerdict(unittest.TestCase):
    def test_p0_open_is_high_risk(self):
        L = {"findings": [{"id": "V1", "status": "triaged", "triage": {"priority": "P0"}}]}
        lvl, _txt, _c = report.risk_verdict(L)
        self.assertEqual(lvl, "alto")

    def test_all_closed_is_controlled(self):
        # 'controlado' exige cierre CON evidencia (verdict CLOSED), no solo el status.
        L = {"findings": [{"id": "V1", "status": "closed", "triage": {"priority": "P0"},
                           "verification": {"verdict": "CLOSED"}}]}
        lvl, _txt, _c = report.risk_verdict(L)
        self.assertEqual(lvl, "controlado")

    def test_closed_without_verdict_stays_high_risk(self):
        # status:closed sin verificacion -> sigue ABIERTO -> riesgo alto si es P0.
        L = {"findings": [{"id": "V1", "status": "closed", "triage": {"priority": "P0"}}]}
        lvl, _txt, _c = report.risk_verdict(L)
        self.assertEqual(lvl, "alto")


class TestExecutiveVsTechnicalHtml(unittest.TestCase):
    """Contrato de nombres + requerimiento 10: ambos modos se producen, cada uno
    self-contained, el ejecutivo es mas corto y solo muestra top findings completos."""

    def setUp(self):
        self.L = {
            "schema_version": "1.2",
            "run": {"scope": "apps/example-app", "owasp_version": "2025", "branch": "main"},
            "attack_surface": {"entrypoints": ["a.py"], "trust_boundaries": ["api"]},
            "findings": [
                {"id": "V1", "title": "SQLi critico", "status": "triaged", "source": "sast",
                 "owasp_2025": "A03:2025-Injection", "cwe": "CWE-89",
                 "sast": {"tool": "semgrep", "rule": "sqli", "confidence": 8, "hypothesis": "input sin sanitizar"},
                 "triage": {"priority": "P0", "cvss": 9.1, "cvss_version": "3.1", "rationale": "critico y explotable"},
                 "intel": {"in_cisa_kev": True, "package": "libx", "installed_version": "1.0",
                           "cve_ids": ["CVE-2024-0001"], "epss": 0.9, "fixed_version": "1.1"}},
                {"id": "V2", "title": "XSS reflejado", "status": "fixing",
                 "triage": {"priority": "P1", "cvss": 6.5, "cvss_version": "3.1", "rationale": "media exposicion"}},
                {"id": "V3", "title": "Header debil", "status": "hypothesis",
                 "triage": {"priority": "P2", "rationale": "bajo impacto"}},
                {"id": "V4", "title": "Cosmetico", "status": "hypothesis",
                 "triage": {"priority": "P3", "rationale": "informativo"}},
                {"id": "V5", "title": "Falso positivo", "status": "filtered",
                 "triage": {"priority": "FILTERED", "rationale": "no aplica en este contexto"}},
            ],
        }
        self.md = report.build_md(self.L, "x")
        self.tech_html = report.build_html(self.md, False, "audit-report.md", "audit-report.pdf", self.L, mode="technical")
        self.exec_html = report.build_executive_html(self.L, "audit-report.md", "audit-report-executive.pdf", "audit-report.html")

    def test_both_modes_produced_and_self_contained(self):
        for h in (self.tech_html, self.exec_html):
            self.assertIn("<!DOCTYPE html", h)
            self.assertNotIn("<script src=", h)
            self.assertNotIn("fonts.googleapis.com", h)
            self.assertNotIn("unpkg.com", h)

    def test_file_naming_contract_sibling_links(self):
        # B.html <-> B-executive.html, cruzados en ambas direcciones.
        self.assertIn("audit-report-executive.html", self.tech_html)
        self.assertIn("audit-report.html", self.exec_html)

    def test_executive_is_shorter_than_technical(self):
        self.assertLess(len(self.exec_html), len(self.tech_html))

    def test_executive_only_renders_full_cards_for_top_priority(self):
        # P0/KEV (V1) y P1 (V2) son cards completas; P2/P3/FILTERED colapsan en rollup.
        self.assertIn('id="V1"', self.exec_html)
        self.assertIn('id="V2"', self.exec_html)
        self.assertNotIn('id="V3"', self.exec_html)
        self.assertNotIn('id="V4"', self.exec_html)
        self.assertIn('class="rollup"', self.exec_html)
        # La tecnica en cambio trae los 5 hallazgos como card.
        for fid in ("V1", "V2", "V3", "V4", "V5"):
            self.assertIn(f'id="{fid}"', self.tech_html)

    def test_technical_findings_table_has_sortable_and_filterable_attrs(self):
        self.assertIn('id="findings-table"', self.tech_html)
        self.assertIn("data-sortcol=", self.tech_html)
        self.assertIn('data-sev="P0"', self.tech_html)
        self.assertIn('data-status=', self.tech_html)

    def test_lifecycle_stepper_present_and_no_fabricated_dates(self):
        self.assertIn('class="ltrack"', self.tech_html)
        # El stepper nunca debe traer fecha inventada (solo hay run.started_at).
        self.assertNotIn("started_at", self.tech_html)

    def test_closed_unverified_alert_visible_per_card(self):
        L2 = {"findings": [{"id": "V9", "title": "Cerrado sin verificar", "status": "closed",
                            "triage": {"priority": "P1", "rationale": "x"}}]}
        md2 = report.build_md(L2, "x")
        html2 = report.build_html(md2, False, "r.md", "r.pdf", L2)
        self.assertIn("no cuenta como cerrado", html2)


class TestReportRetrocompat(unittest.TestCase):
    """report.py corrido directamente (sin /hunt ni /resume antes) sobre el
    ledger de una auditoria ya corrida con una version anterior del plugin debe
    dejar el ledger EN DISCO con ids canonicalizados — no solo el informe."""

    def test_running_report_cli_canonicalizes_an_old_ledger_on_disk(self):
        with tempfile.TemporaryDirectory() as d:
            ledger_path = os.path.join(d, "ledger.json")
            with open(ledger_path, "w") as fh:
                json.dump({
                    "schema_version": "1.0",
                    "run": {"scope": "apps/old-repo"},
                    "findings": [
                        {"id": "VULN-101", "title": "SQLi", "status": "closed",
                         "verification": {"verdict": "CLOSED"}},
                        {"id": "VULN-201", "title": "Django CVE", "status": "triaged",
                         "triage": {"priority": "P0"}},
                    ],
                }, fh)
            out_base = os.path.join(d, "audit-report")
            result = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS_DIR, "report.py"), ledger_path, out_base],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("canonicalizados", result.stdout)

            with open(ledger_path) as fh:
                on_disk = json.load(fh)
            ids = sorted(f["id"] for f in on_disk["findings"])
            self.assertEqual(ids, ["VULN-001", "VULN-002"])
            self.assertEqual(on_disk["schema_version"], "1.2")
            by_title = {f["title"]: f for f in on_disk["findings"]}
            self.assertEqual(by_title["SQLi"]["origin_id"], "VULN-101")
            # el veredicto de la auditoria pasada no se pierde al canonicalizar
            self.assertEqual(by_title["SQLi"]["verification"]["verdict"], "CLOSED")

            with open(out_base + ".html") as fh:
                html = fh.read()
            self.assertIn("VULN-001", html)
            self.assertIn("VULN-002", html)
            self.assertNotIn("VULN-101", html)
            self.assertNotIn("VULN-201", html)

    def test_second_run_is_a_silent_noop(self):
        with tempfile.TemporaryDirectory() as d:
            ledger_path = os.path.join(d, "ledger.json")
            with open(ledger_path, "w") as fh:
                json.dump({"schema_version": "1.0",
                           "findings": [{"id": "VULN-101", "title": "SQLi", "status": "hypothesis"}]}, fh)
            out_base = os.path.join(d, "audit-report")
            subprocess.run([sys.executable, os.path.join(SCRIPTS_DIR, "report.py"), ledger_path, out_base],
                            capture_output=True, text=True, check=True)
            second = subprocess.run(
                [sys.executable, os.path.join(SCRIPTS_DIR, "report.py"), ledger_path, out_base],
                capture_output=True, text=True,
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertNotIn("canonicalizados", second.stdout)
            self.assertNotIn("migrado", second.stdout)


if __name__ == "__main__":
    unittest.main()
