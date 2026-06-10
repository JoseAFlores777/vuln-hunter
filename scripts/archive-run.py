#!/usr/bin/env python3
"""
vuln-hunter :: archive-run.py
Archiva una corrida de auditoria al historial LOCAL del repo, bajo
.vuln-hunter/history/. Determinista (sin LLM). Lo consume el panel para cargar
corridas pasadas en modo solo-lectura.

NOTA: .vuln-hunter/ esta en .gitignore, asi que el historial es LOCAL (no se
commitea). Los snapshots contienen detalles de hallazgos: no los publiques en git
salvo decision explicita.

Que hace:
  - Calcula un id de corrida estable a partir de run.started_at + scope.
  - Copia ledger.json + activity.jsonl (+ audit-report.* si existen) a
    .vuln-hunter/history/<id>/ (snapshot inmutable; re-archivar la misma corrida
    la sobreescribe -> idempotente).
  - Actualiza .vuln-hunter/history/index.json con un resumen de la corrida (para
    el selector del panel). Reemplaza la entrada del mismo id si ya existia.

Uso:
    python3 scripts/archive-run.py [ledger.json] [activity.jsonl]
"""
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime

# Reutiliza los helpers del informe para que el resumen sea consistente con el.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report  # noqa: E402


def slug(text):
    s = re.sub(r"[^a-zA-Z0-9]+", "-", str(text or "")).strip("-").lower()
    return s or "repo"


def run_id(ledger):
    run = ledger.get("run", {}) if isinstance(ledger.get("run"), dict) else {}
    started = run.get("started_at") or datetime.now().isoformat(timespec="seconds")
    started_fs = re.sub(r"[:.]", "-", str(started))
    return f"{started_fs}_{slug(run.get('scope') or 'repo')}"


def _atomic_write_json(path, data):
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".idx.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def summarize(ledger, rid):
    run = ledger.get("run", {}) if isinstance(ledger.get("run"), dict) else {}
    C = report.compute(ledger)
    lvl, _txt, _color = report.risk_verdict(ledger)
    findings = [f for f in ledger.get("findings", []) if isinstance(f, dict)]
    return {
        "id": rid,
        "started_at": run.get("started_at"),
        "archived_at": datetime.now().isoformat(timespec="seconds"),
        "scope": run.get("scope") or "repo completo",
        "branch": run.get("branch"),
        "stacks": run.get("stacks", []),
        "owasp_version": run.get("owasp_version", "2025"),
        "total": len(findings),
        "by_prio": C["by_prio"],
        "kev": C["kev"],
        "fixed": C["fixed"],
        "closed": C["closed"],
        "verdict": lvl,
    }


def update_index(history_dir, entry):
    idx_path = os.path.join(history_dir, "index.json")
    runs = []
    if os.path.exists(idx_path):
        try:
            with open(idx_path) as fh:
                loaded = json.load(fh)
            if isinstance(loaded, list):
                runs = [r for r in loaded if isinstance(r, dict)]
        except Exception:
            runs = []
    runs = [r for r in runs if r.get("id") != entry["id"]]  # reemplaza el mismo id
    runs.append(entry)
    runs.sort(key=lambda r: (r.get("started_at") or "", r.get("archived_at") or ""))
    _atomic_write_json(idx_path, runs)
    return len(runs)


def main(argv):
    ledger_path = argv[1] if len(argv) > 1 else ".vuln-hunter/ledger.json"
    activity_path = argv[2] if len(argv) > 2 else os.path.join(
        os.path.dirname(ledger_path) or ".", "activity.jsonl")

    try:
        with open(ledger_path) as fh:
            ledger = json.load(fh)
    except Exception as e:
        print(f"vuln-hunter archive: no se pudo leer el ledger ({e})", file=sys.stderr)
        return 1
    if not isinstance(ledger, dict):
        print("vuln-hunter archive: el ledger no es un objeto valido", file=sys.stderr)
        return 1

    state_dir = os.path.dirname(os.path.abspath(ledger_path)) or "."
    history_dir = os.path.join(state_dir, "history")
    rid = run_id(ledger)
    run_dir = os.path.join(history_dir, rid)
    os.makedirs(run_dir, exist_ok=True)

    # snapshot inmutable de la corrida
    shutil.copy2(ledger_path, os.path.join(run_dir, "ledger.json"))
    if os.path.exists(activity_path):
        shutil.copy2(activity_path, os.path.join(run_dir, "activity.jsonl"))
    # informes asociados, si existen junto al ledger
    for name in ("audit-report.md", "audit-report.html", "audit-report.pdf"):
        src = os.path.join(state_dir, name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(run_dir, name))

    n = update_index(history_dir, summarize(ledger, rid))
    print(f"vuln-hunter archive: corrida '{rid}' archivada ({n} en el historial)")
    print(f"  {run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
