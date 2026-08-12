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

    def test_retrocompat_canonicalizes_ids_of_an_already_audited_repo(self):
        # Simula un repo que ya corrio una auditoria completa con una version
        # anterior del plugin (ids de recoleccion VULN-1xx/2xx sin canonicalizar,
        # schema viejo). Actualizar el plugin y volver a tocar el ledger con
        # `migrate` (lo que ya hacen /hunt, /resume, /rescan y ahora tambien
        # report.py) debe dejarlo canonico sin ningun paso manual.
        old_repo_ledger = {
            "schema_version": "1.0",
            "findings": [
                {"id": "VULN-101", "title": "SQLi", "status": "closed",
                 "verification": {"verdict": "CLOSED"}},
                {"id": "VULN-201", "title": "Django CVE", "status": "triaged",
                 "triage": {"priority": "P0"}},
            ],
        }
        L = ledger.migrate(old_repo_ledger)
        ids = sorted(f["id"] for f in L["findings"])
        self.assertEqual(ids, ["VULN-001", "VULN-002"])
        self.assertEqual(L["schema_version"], ledger.CURRENT_SCHEMA)
        # el estado/veredicto de la auditoria pasada no se pierde
        by_title = {f["title"]: f for f in L["findings"]}
        self.assertEqual(by_title["SQLi"]["status"], "closed")
        self.assertEqual(by_title["SQLi"]["verification"]["verdict"], "CLOSED")
        self.assertEqual(by_title["SQLi"]["origin_id"], "VULN-101")


class TestStaleIdReferencesInFreeText(unittest.TestCase):
    """Auditoria real: triage.rationale citaba otros hallazgos por su id
    de ANTES de renumerar ("refutado en VULN-103") — tras renumber(), esos ids
    ya no existian en ningun lado del informe (57 de 64 menciones reales
    verificadas, en 9 campos distintos, no solo rationale). renumber() ya
    calculaba el remap completo pero solo lo aplicaba a triage.dedup_of."""

    def test_rationale_mention_gets_rewritten(self):
        L = {"findings": [
            {"id": "VULN-101", "title": "A", "status": "triaged", "triage": {"priority": "P1"}},
            {"id": "VULN-102", "title": "B", "status": "filtered",
             "triage": {"priority": "N/A", "rationale": "Duplicado, refutado en VULN-101 y VULN-103."}},
        ]}
        out = ledger.renumber(L)
        by_title = {f["title"]: f for f in out["findings"]}
        # VULN-101 -> VULN-001 (existe); VULN-103 no existe en este ledger y
        # NO esta en el remap -> se deja igual (no se inventa una correspondencia).
        self.assertIn("VULN-001", by_title["B"]["triage"]["rationale"])
        self.assertIn("VULN-103", by_title["B"]["triage"]["rationale"])
        self.assertNotIn("VULN-101", by_title["B"]["triage"]["rationale"])

    def test_generic_sweep_fixes_fields_not_on_an_explicit_allowlist(self):
        # related/superseded_by/dedup/dedup_of_all: ninguno declarado en el
        # schema, pero los agentes reales los escriben. El barrido es
        # recursivo (no una lista cerrada de nombres de campo), asi que los
        # corrige a todos sin que report.py necesite conocerlos.
        L = {"findings": [
            {"id": "VULN-101", "title": "A", "status": "triaged", "triage": {"priority": "P1"}},
            {"id": "VULN-102", "title": "B", "status": "filtered", "triage": {"priority": "N/A"},
             "related": ["VULN-101"], "superseded_by": "VULN-101",
             "dedup_of_all": ["VULN-101"], "custom_future_field": {"nested": ["ver VULN-101"]}},
        ]}
        out = ledger.renumber(L)
        b = {f["title"]: f for f in out["findings"]}["B"]
        self.assertEqual(b["related"], ["VULN-001"])
        self.assertEqual(b["superseded_by"], "VULN-001")
        self.assertEqual(b["dedup_of_all"], ["VULN-001"])
        self.assertIn("VULN-001", b["custom_future_field"]["nested"][0])

    def test_id_and_origin_id_fields_are_never_rewritten(self):
        L = {"findings": [{"id": "VULN-101", "title": "A", "status": "triaged",
                           "triage": {"priority": "P1"}, "notes": "self-ref VULN-101"}]}
        out = ledger.renumber(L)
        f = out["findings"][0]
        self.assertEqual(f["id"], "VULN-001")
        self.assertEqual(f["origin_id"], "VULN-101")  # el id VIEJO, intacto
        self.assertEqual(f["notes"], "self-ref VULN-001")  # pero el texto SI se actualiza

    def test_retroactively_heals_a_ledger_canonicalized_before_this_fix(self):
        # Simula el caso real: un ledger que YA paso por renumber() (origin_id
        # ya asignado) pero cuyo texto libre quedo con referencias rotas de
        # ANTES de que este fix existiera. Un migrate() posterior (sin
        # findings nuevos que renombrar) debe sanar el texto igual.
        already_canonical = {
            "findings": [
                {"id": "VULN-001", "origin_id": "VULN-101", "title": "A", "status": "triaged",
                 "triage": {"priority": "P1"}},
                {"id": "VULN-002", "origin_id": "VULN-102", "title": "B", "status": "filtered",
                 "triage": {"priority": "N/A", "rationale": "Duplicado de VULN-101."}},
            ]
        }
        out = ledger.migrate(already_canonical)
        by_title = {f["title"]: f for f in out["findings"]}
        self.assertIn("VULN-001", by_title["B"]["triage"]["rationale"])
        self.assertNotIn("VULN-101", by_title["B"]["triage"]["rationale"])
        # idempotente: una segunda pasada no cambia nada mas
        again = ledger.migrate(out)
        self.assertEqual(out, again)

    def test_noop_when_nothing_ever_renumbered(self):
        L = {"findings": [{"id": "V1", "title": "A", "status": "hypothesis", "notes": "sin ids aca"}]}
        out = ledger.renumber(dict(L))
        self.assertEqual(out["findings"][0]["notes"], "sin ids aca")


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

    def test_fixing_in_progress_resumes_fix(self):
        rp = self._rp([{"id": "V1", "sast": {}, "exploitability": {}, "triage": {}, "status": "fixing"}])
        self.assertEqual(rp["next_command"], "/vuln-hunter:fix all")

    def test_fixing_counts_as_open(self):
        rp = self._rp([{"id": "V1", "sast": {}, "exploitability": {}, "triage": {}, "status": "fixing"}])
        self.assertEqual(rp["open"], 1)

    def test_candidate_resolved_suggests_verify(self):
        rp = self._rp([{"id": "V1", "sast": {}, "exploitability": {}, "triage": {},
                        "status": "candidate-resolved"}])
        self.assertEqual(rp["next_command"], "/vuln-hunter:verify all")

    def test_candidate_resolved_counts_as_open(self):
        rp = self._rp([{"id": "V1", "status": "candidate-resolved"}])
        self.assertEqual(rp["open"], 1)

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


class TestRenumber(unittest.TestCase):
    def test_sequential_increasing_from_001(self):
        L = {"findings": [
            {"id": "VULN-107", "title": "SSRF"},
            {"id": "VULN-101", "title": "SQLi"},
            {"id": "VULN-201", "title": "Django CVE"},
        ]}
        out = ledger.renumber(L)
        ids = [f["id"] for f in out["findings"]]
        self.assertEqual(sorted(ids), ["VULN-001", "VULN-002", "VULN-003"])

    def test_orders_by_collection_id_not_list_order(self):
        # VULN-101 se descubrio antes que VULN-107 y VULN-201 aunque el ledger
        # los liste en otro orden -> debe quedar VULN-001.
        L = {"findings": [
            {"id": "VULN-201", "title": "Django CVE"},
            {"id": "VULN-107", "title": "SSRF"},
            {"id": "VULN-101", "title": "SQLi"},
        ]}
        out = ledger.renumber(L)
        by_title = {f["title"]: f["id"] for f in out["findings"]}
        self.assertEqual(by_title["SQLi"], "VULN-001")
        self.assertEqual(by_title["SSRF"], "VULN-002")
        self.assertEqual(by_title["Django CVE"], "VULN-003")

    def test_preserves_origin_id(self):
        L = {"findings": [{"id": "VULN-101", "title": "SQLi"}]}
        out = ledger.renumber(L)
        self.assertEqual(out["findings"][0]["origin_id"], "VULN-101")
        self.assertEqual(out["findings"][0]["id"], "VULN-001")

    def test_idempotent_does_not_renumber_twice(self):
        L = {"findings": [{"id": "VULN-101", "title": "SQLi"}]}
        once = ledger.renumber(L)
        twice = ledger.renumber(once)
        self.assertEqual(once, twice)
        self.assertEqual(twice["findings"][0]["id"], "VULN-001")
        self.assertEqual(twice["findings"][0]["origin_id"], "VULN-101")

    def test_incremental_new_findings_continue_the_sequence(self):
        # Un finding creado al vuelo (p.ej. appsec-fixer pide un SCA nuevo)
        # despues de un renumber previo debe seguir la secuencia, no chocar.
        L = {"findings": [{"id": "VULN-101", "title": "SQLi"}]}
        after_first = ledger.renumber(L)
        after_first["findings"].append({"id": "VULN-205", "title": "New CVE"})
        out = ledger.renumber(after_first)
        ids = {f["title"]: f["id"] for f in out["findings"]}
        self.assertEqual(ids["SQLi"], "VULN-001")
        self.assertEqual(ids["New CVE"], "VULN-002")

    def test_remaps_dedup_of_to_new_id(self):
        L = {"findings": [
            {"id": "VULN-101", "title": "SQLi A"},
            {"id": "VULN-102", "title": "SQLi B", "triage": {"dedup_of": "VULN-101"}},
        ]}
        out = ledger.renumber(L)
        self.assertEqual(out["findings"][1]["triage"]["dedup_of"], "VULN-001")

    def test_nondict_findings_do_not_crash(self):
        L = {"findings": ["poison", {"id": "VULN-101", "title": "SQLi"}]}
        out = ledger.renumber(L)
        real = [f for f in out["findings"] if isinstance(f, dict)]
        self.assertEqual(real[0]["id"], "VULN-001")


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
