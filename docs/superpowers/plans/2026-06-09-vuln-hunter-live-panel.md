# vuln-hunter Live Panel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A static React-via-CDN admin panel that reads `.vuln-hunter/ledger.json` + a new `.vuln-hunter/activity.jsonl` and auto-refreshes so the user watches findings appear and get mitigated live, served with `python3 -m http.server`.

**Architecture:** Two-file contract — `ledger.json` stays the single source of truth for state (findings, statuses, mitigation), a new append-only `activity.jsonl` carries the event timeline. A shared `scripts/activity.py` helper appends events; every stage command calls it at its boundaries. A single static `panel/index.html` (React 18 + Babel standalone via CDN, zero build) polls both files every 2s and renders a single-page view with expandable finding rows. Liveness is per-stage/per-finding (Task subagents are opaque) — see `docs/adr/0001-panel-liveness-architecture.md`.

**Tech Stack:** Python 3 stdlib (`activity.py`, `unittest`, `http.server`), React 18 UMD + `@babel/standalone` via unpkg CDN, vanilla CSS (kit palette from `report.py`).

---

## File Structure

| File | Responsibility |
|---|---|
| `scripts/activity.py` (create) | Append-only JSONL event logger. CLI `activity.py <type> [k=v …]`. Pure stdlib, testable. |
| `tests/test_activity.py` (create) | `unittest` coverage for `activity.py` (parse, append, validation, dir creation). |
| `tests/fixtures/ledger.sample.json` (create) | Realistic populated ledger for panel verification. |
| `tests/fixtures/activity.sample.jsonl` (create) | Matching event timeline for panel verification. |
| `tests/test_panel_contract.py` (create) | Smoke test: fixture shape + `index.html` references required fetch paths/components. |
| `panel/index.html` (create) | The panel: React CDN app, polls `ledger.json` + `activity.jsonl`, single page, expandable rows. |
| `commands/panel.md` (create) | `/vuln-hunter:panel` — copies the panel into `.vuln-hunter/`, serves it, opens the browser. |
| `commands/detect.md` (modify) | Emit `run:start` + `stage:start/end` for `detect`. |
| `commands/hunt.md` (modify) | Orchestrator emits `run:start`, every `stage:*`, `finding:new`, `deploy:blocked`, `run:done`. |
| `commands/{scan,watch,redteam,triage,plan,fix,verify}.md` (modify) | Each solo stage command emits its own `stage:start/end` (+ `finding:new` for scan/watch, `deploy:blocked` for triage). |
| `README.md` (modify) | Document the panel command. |

Canonical stage keys (used in `activity.py` events AND the panel's `STAGES` table — they must match exactly): `detect`, `RECON`, `SAST`, `INTEL`, `RED-TEAM`, `TRIAGE`, `plan`, `FIX`, `VERIFY`. Agent labels/icons come from the `agent-presentation` skill.

Event types (the only valid ones): `run:start`, `run:done`, `stage:start`, `stage:end`, `finding:new`, `deploy:blocked`.

---

### Task 1: Activity event logger (`scripts/activity.py`)

**Files:**
- Create: `scripts/activity.py`
- Test: `tests/test_activity.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_activity.py`:

```python
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

    def test_unknown_type_returns_2_and_writes_nothing(self):
        rc = activity.append_event("bogus:type", {}, self.path)
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 tests/test_activity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'activity'` (file does not exist yet).

- [ ] **Step 3: Write minimal implementation**

Create `scripts/activity.py`:

```python
#!/usr/bin/env python3
"""
vuln-hunter :: activity.py
Logger append-only de eventos para el panel vivo. Escribe una linea JSON por
evento en .vuln-hunter/activity.jsonl. No depende del LLM ni del ledger: es el
timeline que consume panel/index.html.

Uso:
    python3 scripts/activity.py <type> [clave=valor ...]
    # ej: python3 scripts/activity.py stage:start stage=SAST agent=sast-analyst

Ruta de salida: $VULN_ACTIVITY o .vuln-hunter/activity.jsonl
"""
import json
import os
import sys
from datetime import datetime

EVENT_TYPES = {
    "run:start", "run:done",
    "stage:start", "stage:end",
    "finding:new", "deploy:blocked",
}


def parse_fields(args):
    """Convierte ['k=v', 'k2=v2'] en {'k':'v','k2':'v2'}. Ignora tokens sin '='."""
    fields = {}
    for a in args:
        if "=" not in a:
            continue
        k, v = a.split("=", 1)
        fields[k] = v
    return fields


def append_event(event_type, fields, path):
    """Append de un evento como linea JSON. Devuelve 0 ok, 2 si el tipo es invalido."""
    if event_type not in EVENT_TYPES:
        print(f"vuln-hunter activity: tipo desconocido '{event_type}'", file=sys.stderr)
        return 2
    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "type": event_type}
    rec.update(fields)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return 0


def main(argv):
    if len(argv) < 2:
        print("uso: activity.py <type> [clave=valor ...]", file=sys.stderr)
        return 2
    event_type = argv[1]
    path = os.environ.get("VULN_ACTIVITY", ".vuln-hunter/activity.jsonl")
    return append_event(event_type, parse_fields(argv[2:]), path)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 tests/test_activity.py -v`
Expected: PASS — 6 tests OK.

- [ ] **Step 5: Manual smoke check**

Run:
```bash
VULN_ACTIVITY=/tmp/act.jsonl python3 scripts/activity.py stage:start stage=SAST agent=sast-analyst
VULN_ACTIVITY=/tmp/act.jsonl python3 scripts/activity.py finding:new id=VULN-101 title="SQL injection" source=sast
cat /tmp/act.jsonl
```
Expected: two JSON lines, each with `ts`, `type`, and the given fields.

- [ ] **Step 6: Commit** *(only on explicit user authorization — see CLAUDE.md; do not commit autonomously)*

```bash
git add scripts/activity.py tests/test_activity.py
git commit -m "feat(panel): add append-only activity event logger"
```

---

### Task 2: Verification fixtures (`tests/fixtures/`)

**Files:**
- Create: `tests/fixtures/ledger.sample.json`
- Create: `tests/fixtures/activity.sample.jsonl`

- [ ] **Step 1: Create the sample ledger**

Create `tests/fixtures/ledger.sample.json` (a mid-audit state: one closed, one fixed-pending, one confirmed P0 KEV dep):

```json
{
  "schema_version": "1.0",
  "run": {
    "started_at": "2026-06-09T10:00:00",
    "scope": "apps/epos",
    "owasp_version": "2025",
    "branch": "vuln-hunter/audit-epos",
    "stacks": ["python-django", "next-react-ts"]
  },
  "attack_surface": {
    "entrypoints": ["apps/epos/views.py", "apps/epos/api/"],
    "trust_boundaries": ["HTTP request -> ORM", "user input -> template"],
    "high_risk_zones": ["raw SQL in reports", "dangerouslySetInnerHTML in dashboard"]
  },
  "findings": [
    {
      "id": "VULN-101",
      "source": "sast",
      "title": "SQL injection (raw query)",
      "location": "apps/epos/views.py:11",
      "cwe": "CWE-89",
      "owasp_2025": "A03:2025-Injection",
      "sast": {
        "tool": "semgrep",
        "rule": "python.django.sql.raw-query",
        "flow": "SRC request.GET['q'] -> SINK cursor.execute(f\"... {q}\")",
        "confidence": 9,
        "hypothesis": "User-controlled q reaches a raw SQL string"
      },
      "exploitability": {
        "verdict": "EXPLOITABLE",
        "reachable": true,
        "controllable": true,
        "conditions": "Authenticated user with report access",
        "conceptual_chain": [
          "Attacker sends q=1' OR '1'='1",
          "String interpolated into SQL with no parameterization",
          "Query returns all rows -> data exfiltration"
        ],
        "confidence_adjusted": 9
      },
      "triage": {
        "cvss": 8.6,
        "cvss_version": "4.0",
        "priority": "P0",
        "rationale": "Reachable, controllable, high impact on confidentiality"
      },
      "fix": {
        "root_cause": "String interpolation into raw SQL",
        "files_touched": ["apps/epos/views.py"],
        "asvs": "V5.3.4",
        "summary": "Use parameterized query with placeholder",
        "applied": true
      },
      "verification": {
        "rescan_clear": true,
        "tests_pass": true,
        "no_new_findings": true,
        "verdict": "CLOSED",
        "evidence": "semgrep re-scan clean; test_report_injection passes"
      },
      "status": "closed"
    },
    {
      "id": "VULN-102",
      "source": "sast",
      "title": "XSS via dangerouslySetInnerHTML",
      "location": "apps/epos/dashboard/page.jsx:4",
      "cwe": "CWE-79",
      "owasp_2025": "A03:2025-Injection",
      "sast": {
        "tool": "eslint-security",
        "rule": "react/no-danger",
        "flow": "SRC props.note -> SINK dangerouslySetInnerHTML",
        "confidence": 7,
        "hypothesis": "Unsanitized note rendered as HTML"
      },
      "exploitability": {
        "verdict": "CONDITIONAL",
        "reachable": true,
        "controllable": true,
        "conditions": "Requires stored note with script payload",
        "conceptual_chain": [
          "Attacker stores a note with <img onerror>",
          "Dashboard renders it via dangerouslySetInnerHTML",
          "Script executes in victim session"
        ],
        "confidence_adjusted": 7
      },
      "triage": {
        "cvss": 6.1,
        "cvss_version": "4.0",
        "priority": "P2",
        "rationale": "Stored XSS but limited to authenticated dashboard"
      },
      "fix": {
        "root_cause": "Rendering untrusted HTML",
        "files_touched": ["apps/epos/dashboard/page.jsx"],
        "asvs": "V5.3.3",
        "summary": "Render as text or sanitize with DOMPurify",
        "applied": true
      },
      "status": "fixed"
    },
    {
      "id": "VULN-201",
      "source": "sca",
      "title": "Django 3.2.4 — CVE in CISA KEV",
      "location": "Django@3.2.4",
      "cwe": "CWE-1395",
      "owasp_2025": "A06:2025-Vulnerable and Outdated Components",
      "intel": {
        "package": "Django",
        "installed_version": "3.2.4",
        "ecosystem": "PyPI",
        "is_production_dep": true,
        "cve_ids": ["CVE-2022-28346"],
        "ghsa_ids": ["GHSA-2gwj-7jmv-h26r"],
        "in_cisa_kev": true,
        "known_ransomware_use": false,
        "epss": 0.71,
        "fixed_version": "3.2.13",
        "sources_consulted": ["OSV.dev", "NVD", "CISA KEV", "FIRST EPSS"]
      },
      "triage": {
        "cvss": 9.8,
        "cvss_version": "3.1",
        "priority": "P0",
        "rationale": "Production dep, in CISA KEV, high EPSS -> deploy blocker"
      },
      "status": "triaged"
    }
  ],
  "plan_ref": ".vuln-hunter/plan.md"
}
```

- [ ] **Step 2: Create the matching activity timeline**

Create `tests/fixtures/activity.sample.jsonl`:

```jsonl
{"ts": "2026-06-09T10:00:00", "type": "run:start", "scope": "apps/epos"}
{"ts": "2026-06-09T10:00:05", "type": "stage:start", "stage": "RECON", "agent": "recon-cartographer"}
{"ts": "2026-06-09T10:01:10", "type": "stage:end", "stage": "RECON", "agent": "recon-cartographer", "summary": "3 high-risk zones"}
{"ts": "2026-06-09T10:01:12", "type": "stage:start", "stage": "SAST", "agent": "sast-analyst"}
{"ts": "2026-06-09T10:03:40", "type": "finding:new", "id": "VULN-101", "title": "SQL injection (raw query)", "source": "sast"}
{"ts": "2026-06-09T10:03:55", "type": "finding:new", "id": "VULN-102", "title": "XSS via dangerouslySetInnerHTML", "source": "sast"}
{"ts": "2026-06-09T10:04:00", "type": "stage:end", "stage": "SAST", "agent": "sast-analyst", "summary": "2 findings"}
{"ts": "2026-06-09T10:04:02", "type": "stage:start", "stage": "INTEL", "agent": "threat-intel-scout"}
{"ts": "2026-06-09T10:05:30", "type": "finding:new", "id": "VULN-201", "title": "Django 3.2.4 — CVE in CISA KEV", "source": "sca"}
{"ts": "2026-06-09T10:05:35", "type": "deploy:blocked", "reason": "Django@3.2.4 CVE-2022-28346 in CISA KEV"}
{"ts": "2026-06-09T10:05:40", "type": "stage:end", "stage": "INTEL", "agent": "threat-intel-scout", "summary": "1 KEV dependency"}
{"ts": "2026-06-09T10:05:45", "type": "stage:start", "stage": "RED-TEAM", "agent": "redteam-whitehat"}
{"ts": "2026-06-09T10:07:00", "type": "stage:end", "stage": "RED-TEAM", "agent": "redteam-whitehat", "summary": "2 exploitable, 1 conditional"}
{"ts": "2026-06-09T10:07:05", "type": "stage:start", "stage": "TRIAGE", "agent": "triage-judge"}
{"ts": "2026-06-09T10:07:50", "type": "stage:end", "stage": "TRIAGE", "agent": "triage-judge", "summary": "2 P0, 1 P2"}
{"ts": "2026-06-09T10:08:00", "type": "stage:start", "stage": "FIX", "agent": "appsec-fixer"}
```

This fixture deliberately stops mid-`FIX` (a `stage:start` with no `stage:end`) so the panel shows `appsec-fixer` as **running**.

- [ ] **Step 3: Commit** *(only on explicit user authorization)*

```bash
git add tests/fixtures/ledger.sample.json tests/fixtures/activity.sample.jsonl
git commit -m "test(panel): add sample ledger and activity fixtures"
```

---

### Task 3: The panel (`panel/index.html`)

**Files:**
- Create: `panel/index.html`
- Test: `tests/test_panel_contract.py`

- [ ] **Step 1: Write the failing contract test**

Create `tests/test_panel_contract.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 tests/test_panel_contract.py -v`
Expected: FAIL — `FileNotFoundError` for `panel/index.html` (the fixture tests pass; the panel-reference tests error because the file is missing).

- [ ] **Step 3: Write the panel**

Create `panel/index.html` with this exact content:

```html
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>vuln-hunter — Panel vivo</title>
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<style>
  :root{
    --paper:#f4f1ea;--card:#fff;--ink:#1a1915;--mute:#8a847a;--rule:#ddd8cc;
    --p0:#b4532f;--p1:#c0772f;--p2:#c89a3c;--p3:#6b7d5c;--filt:#8a847a;
    --run:#c0772f;--done:#6b7d5c;--idle:#bdb7a9;
  }
  *{box-sizing:border-box}
  body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:var(--paper);color:var(--ink);margin:0;line-height:1.5}
  .wrap{max-width:1180px;margin:0 auto;padding:28px 24px 80px}
  h1{font-size:1.7rem;margin:0 0 4px}
  .sub{color:var(--mute);font-family:ui-monospace,Menlo,monospace;font-size:12.5px;margin-bottom:22px}
  .live{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--run);margin-right:6px;animation:pulse 1.4s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
  .grid{display:grid;grid-template-columns:1fr 320px;gap:22px;align-items:start}
  .cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
  .card{background:var(--card);border:1px solid var(--rule);border-radius:12px;padding:14px 20px;min-width:84px;text-align:center}
  .card .num{font-size:1.6rem;font-weight:700}
  .card .lbl{font-family:ui-monospace,monospace;font-size:11px;color:var(--mute);text-transform:uppercase;letter-spacing:.04em}
  .kev{background:#fdf0ec;border-left:4px solid var(--p0);border-radius:8px;padding:12px 16px;margin-bottom:18px;font-size:14px}
  .panelbox{background:var(--card);border:1px solid var(--rule);border-radius:12px;padding:16px 18px;margin-bottom:18px}
  .panelbox h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mute);margin:0 0 12px}
  .roster{display:flex;gap:10px;flex-wrap:wrap}
  .agent{display:flex;align-items:center;gap:8px;border:1px solid var(--rule);border-radius:999px;padding:6px 12px;font-size:13px}
  .agent .dot{width:9px;height:9px;border-radius:50%}
  .agent.running{border-color:var(--run);background:#fbf2e9}
  .agent.running .dot{background:var(--run);animation:pulse 1.4s infinite}
  .agent.done .dot{background:var(--done)}
  .agent.idle{color:var(--mute)}
  .agent.idle .dot{background:var(--idle)}
  .pipe{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-family:ui-monospace,monospace;font-size:12.5px}
  .pipe .step{padding:3px 9px;border-radius:6px;border:1px solid var(--rule)}
  .pipe .step.done{background:#eef1e9;border-color:#cfd8c2}
  .pipe .step.running{background:#fbf2e9;border-color:var(--run);font-weight:700}
  .pipe .arrow{color:var(--mute)}
  table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--rule);border-radius:12px;overflow:hidden;font-size:13.5px}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #eee7d8;vertical-align:top}
  th{background:#faf8f2;font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;color:var(--mute)}
  tr.frow{cursor:pointer}
  tr.frow:hover{background:#faf8f2}
  code{background:rgba(107,125,92,.12);padding:1px 5px;border-radius:4px;font-size:.85em}
  .badge{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;font-weight:700;color:#fff}
  .pill{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;border:1px solid var(--rule);color:var(--mute)}
  .detail{background:#fbf9f3}
  .detail dl{margin:0;display:grid;grid-template-columns:140px 1fr;gap:6px 14px;font-size:13px}
  .detail dt{color:var(--mute);font-family:ui-monospace,monospace;font-size:11.5px;text-transform:uppercase}
  .detail dd{margin:0}
  .detail ol{margin:4px 0 0;padding-left:20px}
  .timeline{max-height:70vh;overflow:auto}
  .ev{display:flex;gap:8px;font-size:12.5px;padding:6px 0;border-bottom:1px solid #eee7d8}
  .ev .t{color:var(--mute);font-family:ui-monospace,monospace;font-size:11px;white-space:nowrap}
  .empty{color:var(--mute);text-align:center;padding:40px;font-size:14px}
  footer{margin-top:24px;color:var(--mute);font-size:11.5px;font-family:ui-monospace,monospace}
  @media(max-width:880px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div id="root"></div>
<script type="text/babel">
const {useState,useEffect,useCallback,Fragment} = React;

// Etapas canonicas (la clave 'key' DEBE coincidir con activity.py y la presentacion)
const STAGES = [
  {key:"detect",   label:"detect",   icon:"🧭", agent:null,                  done:(L)=> (L.run&&L.run.stacks||[]).length>0},
  {key:"RECON",    label:"RECON",    icon:"🛰", agent:"recon-cartographer",  done:(L)=> !!L.attack_surface},
  {key:"SAST",     label:"SAST",     icon:"🔬", agent:"sast-analyst",        done:(L)=> L.findings.some(f=>f.sast)},
  {key:"INTEL",    label:"INTEL",    icon:"📡", agent:"threat-intel-scout",  done:(L)=> L.findings.some(f=>f.intel)},
  {key:"RED-TEAM", label:"RED-TEAM", icon:"🎯", agent:"redteam-whitehat",    done:(L)=> L.findings.some(f=>f.exploitability)},
  {key:"TRIAGE",   label:"TRIAGE",   icon:"⚖️", agent:"triage-judge",        done:(L)=> L.findings.some(f=>f.triage)},
  {key:"plan",     label:"plan",     icon:"🗺", agent:null,                  done:(L)=> !!L.plan_ref},
  {key:"FIX",      label:"FIX",      icon:"🔧", agent:"appsec-fixer",        done:(L)=> L.findings.some(f=>f.fix)},
  {key:"VERIFY",   label:"VERIFY",   icon:"✅", agent:"verify-engineer",     done:(L)=> L.findings.some(f=>f.verification)},
];

const PRIO = {P0:"#b4532f",P1:"#c0772f",P2:"#c89a3c",P3:"#6b7d5c",FILTERED:"#8a847a"};
const PRIO_ORDER = {P0:0,P1:1,P2:2,P3:3,FILTERED:9};
const STATUS_LABEL = {hypothesis:"Hipotesis",confirmed:"Confirmada",triaged:"Triada",planned:"Planificada",fixed:"Corregida",closed:"Cerrada",filtered:"Filtrada"};

async function fetchJSON(url){
  const r = await fetch(url + "?t=" + Date.now());
  if(!r.ok) throw new Error(r.status);
  return r.json();
}
async function fetchJSONL(url){
  const r = await fetch(url + "?t=" + Date.now());
  if(!r.ok) return [];
  const txt = await r.text();
  return txt.split("\n").filter(l=>l.trim()).map(l=>{ try{return JSON.parse(l)}catch(e){return null} }).filter(Boolean);
}

// Estado de un agente: running si su ultimo stage:* es start; si no, done por evento o por ledger.
function agentState(stageKey, activity, ledger, doneFn){
  const evs = activity.filter(e=>(e.type==="stage:start"||e.type==="stage:end") && e.stage===stageKey);
  const last = evs[evs.length-1];
  if(last && last.type==="stage:start") return "running";
  if(last && last.type==="stage:end") return "done";
  return doneFn(ledger) ? "done" : "idle";
}

function SummaryCards({findings}){
  const counts = {}; let kev=0;
  findings.forEach(f=>{
    const p = (f.triage||{}).priority || "—";
    counts[p] = (counts[p]||0)+1;
    if((f.intel||{}).in_cisa_kev) kev++;
  });
  const order = Object.keys(counts).sort((a,b)=>(PRIO_ORDER[a]??5)-(PRIO_ORDER[b]??5));
  return (
    <div className="cards">
      <div className="card"><div className="num">{findings.length}</div><div className="lbl">Hallazgos</div></div>
      {order.map(p=>(
        <div className="card" key={p}><div className="num" style={{color:PRIO[p]||"#1a1915"}}>{counts[p]}</div><div className="lbl">{p}</div></div>
      ))}
      <div className="card"><div className="num" style={{color:"#b4532f"}}>{kev}</div><div className="lbl">CISA KEV</div></div>
    </div>
  );
}

function AgentRoster({activity,ledger}){
  return (
    <div className="panelbox">
      <h2>Agentes</h2>
      <div className="roster">
        {STAGES.filter(s=>s.agent).map(s=>{
          const st = agentState(s.key, activity, ledger, s.done);
          return (
            <div className={"agent "+st} key={s.key} title={s.agent}>
              <span className="dot"></span>{s.icon} {s.label}
              <span style={{fontSize:11,color:"var(--mute)"}}>· {st}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function PipelineBar({activity,ledger}){
  return (
    <div className="panelbox">
      <h2>Flujo</h2>
      <div className="pipe">
        {STAGES.map((s,i)=>{
          const st = s.agent ? agentState(s.key,activity,ledger,s.done) : (s.done(ledger)?"done":"idle");
          const cls = st==="running"?"running":(st==="done"?"done":"");
          return (
            <Fragment key={s.key}>
              {i>0 && <span className="arrow">→</span>}
              <span className={"step "+cls}>{s.label} {st==="done"?"✓":st==="running"?"●":"○"}</span>
            </Fragment>
          );
        })}
      </div>
    </div>
  );
}

function FindingDetail({f}){
  const sast=f.sast||{}, ex=f.exploitability||{}, intel=f.intel||{}, tri=f.triage||{}, fix=f.fix||{}, ver=f.verification||{};
  return (
    <td colSpan="6" className="detail">
      <dl>
        <dt>Ubicacion</dt><dd><code>{f.location||"—"}</code> · {f.cwe||""} · {f.owasp_2025||f.owasp_2021||""}</dd>
        {sast.flow && (<Fragment><dt>Flujo SAST</dt><dd><code>{sast.flow}</code> (confianza {sast.confidence??"—"})</dd></Fragment>)}
        {sast.hypothesis && (<Fragment><dt>Hipotesis</dt><dd>{sast.hypothesis}</dd></Fragment>)}
        {ex.verdict && (<Fragment><dt>Explotable</dt><dd>{ex.verdict} — {ex.conditions||""}</dd></Fragment>)}
        {(ex.conceptual_chain||[]).length>0 && (<Fragment><dt>Cadena (PoC conceptual)</dt><dd><ol>{ex.conceptual_chain.map((c,i)=><li key={i}>{c}</li>)}</ol></dd></Fragment>)}
        {intel.package && (<Fragment><dt>Dependencia</dt><dd><code>{intel.package}@{intel.installed_version}</code> → fix {intel.fixed_version||"?"} · {(intel.cve_ids||[]).join(", ")} {intel.in_cisa_kev?"· KEV":""} {intel.epss!=null?("· EPSS "+intel.epss):""}</dd></Fragment>)}
        {tri.rationale && (<Fragment><dt>Triage</dt><dd>{tri.priority} · CVSS {tri.cvss??"—"} (v{tri.cvss_version||"?"}) — {tri.rationale}</dd></Fragment>)}
        {fix.root_cause && (<Fragment><dt>Fix (causa raiz)</dt><dd>{fix.root_cause} → {fix.summary||""} {fix.applied?"· aplicado al working tree":"· sin aplicar"} {fix.asvs?("· ASVS "+fix.asvs):""}</dd></Fragment>)}
        {ver.verdict && (<Fragment><dt>Verificacion</dt><dd>{ver.verdict} — {ver.evidence||""}</dd></Fragment>)}
      </dl>
    </td>
  );
}

function FindingsTable({findings}){
  const [open,setOpen] = useState({});
  const sorted = [...findings].sort((a,b)=>(PRIO_ORDER[(a.triage||{}).priority]??5)-(PRIO_ORDER[(b.triage||{}).priority]??5));
  if(findings.length===0) return <div className="empty">Sin hallazgos en el ledger todavia. Corre <code>/vuln-hunter:hunt</code>.</div>;
  return (
    <table>
      <thead><tr><th>ID</th><th>Sev</th><th>Titulo</th><th>OWASP / CWE</th><th>Explotable</th><th>Estado</th></tr></thead>
      <tbody>
        {sorted.map(f=>{
          const p = (f.triage||{}).priority || "—";
          const intel = f.intel||{};
          const isOpen = !!open[f.id];
          return (
            <Fragment key={f.id}>
              <tr className="frow" onClick={()=>setOpen(o=>({...o,[f.id]:!o[f.id]}))}>
                <td><code>{f.id}</code></td>
                <td>{p!=="—" ? <span className="badge" style={{background:PRIO[p]||"#8a847a"}}>{p}</span> : "—"}</td>
                <td>{f.title} {intel.in_cisa_kev && <span className="badge" style={{background:"#b4532f"}}>KEV</span>} {intel.known_ransomware_use && <span className="badge" style={{background:"#7a1f1f"}}>RANSOMWARE</span>}</td>
                <td>{f.owasp_2025||f.owasp_2021||"—"}<br/><span style={{color:"var(--mute)",fontSize:12}}>{f.cwe||""}</span></td>
                <td>{(f.exploitability||{}).verdict||"—"}</td>
                <td><span className="pill">{STATUS_LABEL[f.status]||f.status||"—"}</span></td>
              </tr>
              {isOpen && <tr><FindingDetail f={f}/></tr>}
            </Fragment>
          );
        })}
      </tbody>
    </table>
  );
}

function ActivityTimeline({activity}){
  const evs = [...activity].reverse();
  return (
    <div className="panelbox timeline">
      <h2>Actividad</h2>
      {evs.length===0 && <div className="empty">Sin eventos.</div>}
      {evs.map((e,i)=>{
        let txt;
        if(e.type==="run:start") txt=`▶ Auditoria iniciada (${e.scope||"repo"})`;
        else if(e.type==="run:done") txt="■ Auditoria finalizada";
        else if(e.type==="stage:start") txt=`● Empieza ${e.stage}${e.agent?" ("+e.agent+")":""}`;
        else if(e.type==="stage:end") txt=`✓ Termina ${e.stage}${e.summary?" — "+e.summary:""}`;
        else if(e.type==="finding:new") txt=`＋ ${e.id} ${e.title||""}`;
        else if(e.type==="deploy:blocked") txt=`⛔ Deploy bloqueado — ${e.reason||""}`;
        else txt=e.type;
        return <div className="ev" key={i}><span className="t">{(e.ts||"").replace("T"," ").slice(5,16)}</span><span>{txt}</span></div>;
      })}
    </div>
  );
}

function App(){
  const [ledger,setLedger] = useState(null);
  const [activity,setActivity] = useState([]);
  const [err,setErr] = useState(null);
  const [updated,setUpdated] = useState(null);

  const poll = useCallback(async ()=>{
    try{
      const L = await fetchJSON("ledger.json");
      const A = await fetchJSONL("activity.jsonl");
      setLedger(L); setActivity(A); setErr(null);
      setUpdated(new Date().toLocaleTimeString());
    }catch(e){ setErr(String(e)); }
  },[]);

  useEffect(()=>{ poll(); const id=setInterval(poll,2000); return ()=>clearInterval(id); },[poll]);

  if(err && !ledger) return <div className="wrap"><h1>vuln-hunter</h1><div className="empty">No se pudo leer <code>ledger.json</code> ({err}). Corre <code>/vuln-hunter:detect</code> o <code>/vuln-hunter:hunt</code> primero.</div></div>;
  if(!ledger) return <div className="wrap"><div className="empty">Cargando…</div></div>;

  const run = ledger.run||{};
  const findings = ledger.findings||[];
  const runDone = activity.some(e=>e.type==="run:done");
  const kev = findings.filter(f=>(f.intel||{}).in_cisa_kev).length;

  return (
    <div className="wrap">
      <h1>{runDone ? "" : <span className="live"></span>}vuln-hunter — Panel vivo</h1>
      <div className="sub">scope: {run.scope||"repo completo"} · branch: {run.branch||"—"} · OWASP {run.owasp_version||"2025"} · stacks: {(run.stacks||[]).join(", ")||"—"} · {runDone?"finalizada":"en curso"} · actualizado {updated||"—"}</div>

      {kev>0 && <div className="kev"><b>⚠ Atencion:</b> {kev} dependencia(s) de produccion con CVE en CISA KEV — el deploy queda bloqueado hasta parchear (vector tipico de ransomware, MITRE T1190).</div>}

      <SummaryCards findings={findings}/>
      <PipelineBar activity={activity} ledger={ledger}/>
      <AgentRoster activity={activity} ledger={ledger}/>

      <div className="grid">
        <div>
          <div className="panelbox" style={{padding:0,overflow:"hidden"}}>
            <FindingsTable findings={findings}/>
          </div>
        </div>
        <ActivityTimeline activity={activity}/>
      </div>

      <footer>Datos: .vuln-hunter/ledger.json + activity.jsonl · panel estatico (React CDN) · polling 2s · vuln-hunter no sustituye auditoria humana.</footer>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App/>);
</script>
</body>
</html>
```

- [ ] **Step 4: Run the contract test to verify it passes**

Run: `python3 tests/test_panel_contract.py -v`
Expected: PASS — all tests OK (fixture + panel-reference assertions).

- [ ] **Step 5: Visual verification against the fixtures**

Run:
```bash
mkdir -p /tmp/vh-panel && cp panel/index.html /tmp/vh-panel/index.html \
  && cp tests/fixtures/ledger.sample.json /tmp/vh-panel/ledger.json \
  && cp tests/fixtures/activity.sample.jsonl /tmp/vh-panel/activity.jsonl \
  && (python3 -m http.server 8765 --directory /tmp/vh-panel &) \
  && sleep 1 && open http://localhost:8765/index.html
```
Expected observations (manual):
- Header shows scope `apps/epos`, branch `vuln-hunter/audit-epos`, "en curso", a pulsing live dot.
- KEV banner is visible (1 KEV dep).
- Summary cards: 3 hallazgos, P0 ×2, P2 ×1, CISA KEV 1.
- Pipeline: detect/RECON/SAST/INTEL/RED-TEAM/TRIAGE/plan = ✓ done, **FIX = ● running**, VERIFY = ○.
- Agent roster: `appsec-fixer` shows **running** (pulsing), the rest **done** except `verify-engineer` **idle**.
- Findings table sorted P0 first. Clicking VULN-101 expands a detail row with flow, conceptual chain, fix, and verification.
- Timeline (right) newest-first, ending with "● Empieza FIX (appsec-fixer)" at top.

Stop the server when done: `pkill -f "http.server 8765"`.

- [ ] **Step 6: Commit** *(only on explicit user authorization)*

```bash
git add panel/index.html tests/test_panel_contract.py
git commit -m "feat(panel): add static React live panel"
```

---

### Task 4: Panel launcher command (`commands/panel.md`)

**Files:**
- Create: `commands/panel.md`

- [ ] **Step 1: Write the command**

Create `commands/panel.md`:

```markdown
---
description: Levanta el panel administrativo vivo (React+CDN, estatico) que lee el ledger y activity.jsonl y se actualiza por polling
argument-hint: [puerto]
allowed-tools: Bash(python3:*), Bash(cp:*), Bash(mkdir:*), Bash(open:*), Read
model: haiku
---

# Panel vivo de vuln-hunter

Sirve el panel estatico desde `.vuln-hunter/` y lo abre en el navegador. El panel
hace polling de `ledger.json` y `activity.jsonl` cada 2s, asi que se actualiza
solo mientras corre la auditoria.

## Pasos
1. Asegura la carpeta de estado:
   ```
   mkdir -p .vuln-hunter
   ```
2. Copia el panel (asset del plugin) junto a los datos para que los `fetch()` sean
   hermanos:
   ```
   cp ${CLAUDE_PLUGIN_ROOT}/panel/index.html .vuln-hunter/index.html
   ```
3. Lanza el servidor estatico EN SEGUNDO PLANO (puerto $ARGUMENTS o 8765 por
   defecto) y abre el navegador:
   ```
   (python3 -m http.server ${ARGUMENTS:-8765} --directory .vuln-hunter >/dev/null 2>&1 &) ; sleep 1 ; open "http://localhost:${ARGUMENTS:-8765}/index.html"
   ```
4. Dile al usuario:
   - URL: `http://localhost:<puerto>/index.html`
   - El panel se refresca solo cada 2s; deja esta terminal y corre la auditoria en
     otra (o sigue con `/vuln-hunter:hunt`).
   - Para detenerlo: `pkill -f "http.server <puerto>"`.

## Nota
Si aun no existe `.vuln-hunter/ledger.json`, el panel muestra un estado vacio que
invita a correr `/vuln-hunter:detect` o `/vuln-hunter:hunt`. No es un error.
```

- [ ] **Step 2: Verify the command file parses (frontmatter + body present)**

Run: `python3 -c "import sys; t=open('commands/panel.md').read(); assert t.startswith('---'); assert 'http.server' in t; assert 'index.html' in t; print('panel.md OK')"`
Expected: `panel.md OK`

- [ ] **Step 3: Commit** *(only on explicit user authorization)*

```bash
git add commands/panel.md
git commit -m "feat(panel): add /vuln-hunter:panel launcher command"
```

---

### Task 5: Instrument the orchestrator (`commands/hunt.md` + `commands/detect.md`)

**Files:**
- Modify: `commands/hunt.md` (add an activity-emission section; extend `allowed-tools`)
- Modify: `commands/detect.md` (emit `run:start` + detect stage)

- [ ] **Step 1: Extend `hunt.md` allowed-tools**

In `commands/hunt.md`, line 4, replace:

```
allowed-tools: Task, Read, Grep, Glob, Bash(git:*), Bash(mkdir:*), Write, TodoWrite, WebSearch, WebFetch
```

with (adds `Bash(python3:*)`):

```
allowed-tools: Task, Read, Grep, Glob, Bash(git:*), Bash(mkdir:*), Bash(python3:*), Write, TodoWrite, WebSearch, WebFetch
```

- [ ] **Step 2: Add the activity-emission section to `hunt.md`**

In `commands/hunt.md`, immediately after the `## Visualizacion entre pasos (importante para la UX)` section (after the closing of that block, end of file), append:

````markdown
## Eventos de actividad (alimentan el panel vivo)
Ademas del dashboard de texto, emite eventos al timeline del panel con el helper
`scripts/activity.py`. Hazlo en los BORDES de cada etapa (no dentro del agente):

- Al iniciar TODO el flujo, una vez:
  ```
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py run:start scope="<scope o repo>"
  ```
- Antes de lanzar cada subagente: `stage:start`; al volver: `stage:end`. Usa estas
  claves de etapa EXACTAS y su agente:
  | stage | agent |
  |---|---|
  | RECON | recon-cartographer |
  | SAST | sast-analyst |
  | INTEL | threat-intel-scout |
  | RED-TEAM | redteam-whitehat |
  | TRIAGE | triage-judge |
  | FIX | appsec-fixer |
  | VERIFY | verify-engineer |

  Ejemplo:
  ```
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=SAST agent=sast-analyst
  # ... corre el subagente ...
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=SAST agent=sast-analyst summary="<N findings>"
  ```
- Por cada finding NUEVO que un agente agregue al ledger:
  ```
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py finding:new id=VULN-101 title="<titulo>" source=sast
  ```
- Si el triage escribe `.vuln-hunter/deploy-blocked`:
  ```
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py deploy:blocked reason="<paquete@version CVE en KEV>"
  ```
- Las etapas `detect` y `plan` no tienen subagente; emite igual `stage:start`/
  `stage:end` con `stage=detect` y `stage=plan`.
- Al terminar TODO el flujo, una vez:
  ```
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py run:done
  ```

Sugiere al usuario abrir el panel con `/vuln-hunter:panel` para verlo en vivo.
````

- [ ] **Step 3: Instrument `detect.md`**

First read the current file to find its frontmatter and end:

Run: `cat commands/detect.md`

Then (a) ensure `Bash(python3:*)` is in its `allowed-tools` (add it if missing, preserving the rest), and (b) append at the end of the file:

````markdown
## Eventos de actividad (panel)
Al empezar la deteccion (es el inicio del flujo), emite:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py run:start scope="<scope o repo completo>"
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=detect
```
Al terminar, tras escribir `.vuln-hunter/stacks.json`:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=detect summary="<stacks detectados>"
```
````

- [ ] **Step 4: Verify both files still start with frontmatter and mention the helper**

Run:
```bash
python3 -c "
for fp in ['commands/hunt.md','commands/detect.md']:
    t=open(fp).read()
    assert t.startswith('---'), fp
    assert 'activity.py' in t, fp
    assert 'Bash(python3:*)' in t, fp
print('hunt.md + detect.md instrumented OK')
"
```
Expected: `hunt.md + detect.md instrumented OK`

- [ ] **Step 5: Commit** *(only on explicit user authorization)*

```bash
git add commands/hunt.md commands/detect.md
git commit -m "feat(panel): emit activity events from hunt + detect"
```

---

### Task 6: Instrument the solo stage commands

So the timeline also works when stages are run individually (not via `/hunt`).

**Files (modify):** `commands/scan.md`, `commands/watch.md`, `commands/redteam.md`, `commands/triage.md`, `commands/plan.md`, `commands/fix.md`, `commands/verify.md`

Per-file values:

| File | stage key | agent | extra events |
|---|---|---|---|
| `scan.md` | `SAST` | `sast-analyst` | `finding:new` per new finding |
| `watch.md` | `INTEL` | `threat-intel-scout` | `finding:new` per new finding |
| `redteam.md` | `RED-TEAM` | `redteam-whitehat` | — |
| `triage.md` | `TRIAGE` | `triage-judge` | `deploy:blocked` if it writes `.vuln-hunter/deploy-blocked` |
| `plan.md` | `plan` | *(none)* | — |
| `fix.md` | `FIX` | `appsec-fixer` | — |
| `verify.md` | `VERIFY` | `verify-engineer` | — |

- [ ] **Step 1: For EACH file above, add `Bash(python3:*)` to its `allowed-tools`**

Read each file's frontmatter first (`cat commands/<file>`). Append `, Bash(python3:*)` to the existing `allowed-tools:` line if not already present. Do not remove any existing tool.

- [ ] **Step 2: For EACH file above, append this activity section at the end**

Use this exact template, substituting `<STAGE>` and `<AGENT>` from the table (for `plan.md`, drop the `agent=` token and the `finding:new` line; include `finding:new` only for `scan.md`/`watch.md`; include `deploy:blocked` only for `triage.md`):

````markdown
## Eventos de actividad (panel)
Emite eventos al timeline del panel en los bordes de esta etapa:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=<STAGE> agent=<AGENT>
# ... corre el subagente / la etapa ...
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=<STAGE> agent=<AGENT> summary="<resumen corto>"
```
Por cada finding NUEVO agregado al ledger (solo scan/watch):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py finding:new id=<VULN-id> title="<titulo>" source=<sast|sca>
```
Si escribes `.vuln-hunter/deploy-blocked` (solo triage):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py deploy:blocked reason="<motivo>"
```
````

Concrete example — `commands/scan.md` gets exactly:

````markdown
## Eventos de actividad (panel)
Emite eventos al timeline del panel en los bordes de esta etapa:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=SAST agent=sast-analyst
# ... corre el subagente sast-analyst ...
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=SAST agent=sast-analyst summary="<N findings>"
```
Por cada finding NUEVO agregado al ledger:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py finding:new id=<VULN-1xx> title="<titulo>" source=sast
```
````

- [ ] **Step 3: Verify every stage command is instrumented**

Run:
```bash
python3 -c "
import re
files={'scan.md':'SAST','watch.md':'INTEL','redteam.md':'RED-TEAM','triage.md':'TRIAGE','plan.md':'plan','fix.md':'FIX','verify.md':'VERIFY'}
for f,stage in files.items():
    t=open('commands/'+f).read()
    assert t.startswith('---'), f
    assert 'Bash(python3:*)' in t, f+' missing python3 tool'
    assert ('stage='+stage) in t, f+' missing stage='+stage
print('all stage commands instrumented OK')
"
```
Expected: `all stage commands instrumented OK`

- [ ] **Step 4: Commit** *(only on explicit user authorization)*

```bash
git add commands/scan.md commands/watch.md commands/redteam.md commands/triage.md commands/plan.md commands/fix.md commands/verify.md
git commit -m "feat(panel): emit activity events from solo stage commands"
```

---

### Task 7: Document the panel (`README.md`)

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Read the commands section of the README**

Run: `grep -n "vuln-hunter:" README.md | head -30`
Identify where the command list / usage lives.

- [ ] **Step 2: Add a panel entry**

In the command list, add a row/line for the panel (match the surrounding format). Example line to insert alongside the other `/vuln-hunter:*` entries:

```markdown
- `/vuln-hunter:panel [puerto]` — Levanta el panel administrativo vivo (React+CDN, estatico). Lee `.vuln-hunter/ledger.json` + `activity.jsonl` y se actualiza por polling cada 2s para ver hallazgos y su mitigacion en tiempo real.
```

If the README has a "How it works" / architecture section, add one sentence:

```markdown
El panel vivo es un frontend estatico (sin build, sin instalar nada) servido con `python3 -m http.server`. La verdad de estado es el ledger; `activity.jsonl` (append-only, escrito por `scripts/activity.py`) es el timeline. Ver `docs/adr/0001-panel-liveness-architecture.md`.
```

- [ ] **Step 3: Verify the edit**

Run: `grep -n "vuln-hunter:panel" README.md`
Expected: at least one match.

- [ ] **Step 4: Commit** *(only on explicit user authorization)*

```bash
git add README.md
git commit -m "docs: document the live panel command"
```

---

### Task 8: End-to-end verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full test suite**

Run:
```bash
python3 tests/test_activity.py -v && python3 tests/test_panel_contract.py -v
```
Expected: all tests PASS.

- [ ] **Step 2: Simulate a live audit feeding the panel**

Run (writes a real ledger + activity stream into a temp working dir and serves the panel):
```bash
WORK=$(mktemp -d) && cd "$WORK" && mkdir -p .vuln-hunter
cp "$OLDPWD/panel/index.html" .vuln-hunter/index.html
cp "$OLDPWD/tests/fixtures/ledger.sample.json" .vuln-hunter/ledger.json
(python3 -m http.server 8766 --directory .vuln-hunter >/dev/null 2>&1 &)
sleep 1 && open http://localhost:8766/index.html
# Now append events with the real helper and watch the panel update within ~2s:
VULN_ACTIVITY=.vuln-hunter/activity.jsonl python3 "$OLDPWD/scripts/activity.py" run:start scope="apps/epos"
VULN_ACTIVITY=.vuln-hunter/activity.jsonl python3 "$OLDPWD/scripts/activity.py" stage:start stage=FIX agent=appsec-fixer
```
Expected: panel loads from the real `activity.py` output; after the second command, within ~2s the FIX step turns ● running and `appsec-fixer` shows running, and the timeline gains the two events — **without reloading the page**.

- [ ] **Step 3: Empty-state check**

Run:
```bash
EMPTY=$(mktemp -d) && cp panel/index.html "$EMPTY/index.html"
(python3 -m http.server 8767 --directory "$EMPTY" >/dev/null 2>&1 &)
sleep 1 && open http://localhost:8767/index.html
```
Expected: panel shows the "No se pudo leer ledger.json … corre /vuln-hunter:detect o /vuln-hunter:hunt" empty state, not a crash.

- [ ] **Step 4: Clean up servers**

Run: `pkill -f "http.server 876" || true`
Expected: temp servers stopped.

- [ ] **Step 5: Final commit (if anything outstanding)** *(only on explicit user authorization)*

```bash
git status
# commit only what the user authorizes
```

---

## Self-Review

**Spec coverage** (against the resolved design table):
- Single project / scope-based → panel reads the one repo's ledger; "por proyecto" = scope/stacks shown in header. ✔ (Task 3)
- Live agent activity → AgentRoster + activity.jsonl + orchestrator emission. ✔ (Tasks 1, 5, 6, Task 3 roster)
- Orchestrator → activity.jsonl (append-only) → `scripts/activity.py` + command instrumentation. ✔ (Tasks 1, 5, 6)
- http.server + polling → `commands/panel.md` + 2s `setInterval`. ✔ (Tasks 3, 4)
- Complementary to report.py → report.py untouched; panel is a separate asset. ✔
- Data-driven (no settings file) → single `index.html`, all content from ledger/activity. ✔ (Task 3)
- Event taxonomy (5+ types) → `EVENT_TYPES` set + emission docs. ✔ (Tasks 1, 5, 6)
- State vs events split → ledger=truth, activity=timeline; statuses read from ledger. ✔ (Task 3 derivation)
- Single-page expandable rows → FindingsTable with toggle detail. ✔ (Task 3)
- Shared helper across all commands → Tasks 5 + 6 instrument detect/hunt + 7 solo commands. ✔

**Placeholder scan:** All code blocks are complete (activity.py, index.html, tests, command bodies). The per-command instrumentation in Task 6 uses an explicit template + a concrete worked example for `scan.md` and a substitution table — no "TBD"/"similar to".

**Type/key consistency:** Stage keys (`detect`, `RECON`, `SAST`, `INTEL`, `RED-TEAM`, `TRIAGE`, `plan`, `FIX`, `VERIFY`) are identical in `STAGES` (index.html), the emission tables (hunt.md), and the verification scripts. Event types match between `activity.py`'s `EVENT_TYPES` and the panel's switch in `ActivityTimeline`. Ledger field access in `FindingDetail` matches `schemas/ledger.schema.json` (sast.flow, exploitability.conceptual_chain, intel.in_cisa_kev, triage.priority, fix.root_cause, verification.verdict).

**Note on git:** Every commit step is gated on explicit user authorization per the project/global CLAUDE.md. No autonomous commits; no `Co-Authored-By` trailer.
