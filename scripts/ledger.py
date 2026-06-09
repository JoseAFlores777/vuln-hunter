#!/usr/bin/env python3
"""
vuln-hunter :: ledger.py
Continuidad entre runs/versiones del ledger (.vuln-hunter/ledger.json).

Tres responsabilidades, todas DETERMINISTAS (sin LLM), para que un run nuevo sea
retrocompatible con el ledger de una version anterior y reanude donde quedo:

1) migrate(ledger): sube cualquier schema viejo al actual, rellena campos
   faltantes con defaults y preserva findings + su estado. Idempotente.
2) resume_point(ledger): a partir de los findings y sus sub-objetos, calcula que
   etapas ya estan hechas y cual es el siguiente comando de la cadena.
3) findings_under(ledger, path): lista los findings cuyo `location` cae dentro de
   un subarbol (para /vuln-hunter:rescan <path>).

Uso CLI:
    python3 scripts/ledger.py migrate <ledger.json>   # migra EN SITIO (escribe)
    python3 scripts/ledger.py resume  <ledger.json>    # imprime punto de reanudacion
    python3 scripts/ledger.py under   <ledger.json> <path>
"""
import json
import os
import sys

CURRENT_SCHEMA = "1.2"
DEFAULT_STATUS = "hypothesis"
# Abiertos = aun requieren accion. 'fixing' = el fixer empezo pero no termino.
OPEN_STATUSES = {None, "hypothesis", "confirmed", "triaged", "planned", "fixing"}

# Orden canonico de etapas (coincide con activity.py y el panel).
STAGE_DONE = [
    ("detect",   lambda L: bool(L.get("run", {}).get("stacks"))),
    ("RECON",    lambda L: bool(L.get("attack_surface"))),
    ("SAST",     lambda L: any("sast" in f for f in L.get("findings", []))),
    ("INTEL",    lambda L: any("intel" in f for f in L.get("findings", []))),
    ("RED-TEAM", lambda L: any("exploitability" in f for f in L.get("findings", []))),
    ("TRIAGE",   lambda L: any("triage" in f for f in L.get("findings", []))),
    ("plan",     lambda L: bool(L.get("plan_ref"))),
    ("FIX",      lambda L: any("fix" in f for f in L.get("findings", []))),
    ("VERIFY",   lambda L: any("verification" in f for f in L.get("findings", []))),
]


def migrate(ledger):
    """Sube el ledger al schema actual sin perder datos. Idempotente."""
    if not isinstance(ledger, dict):
        ledger = {}
    if not isinstance(ledger.get("run"), dict):
        ledger["run"] = {}
    if not isinstance(ledger.get("findings"), list):
        ledger["findings"] = []
    for f in ledger["findings"]:
        if isinstance(f, dict):
            f.setdefault("status", DEFAULT_STATUS)
    ledger["schema_version"] = CURRENT_SCHEMA
    return ledger


def resume_point(ledger):
    """Devuelve etapas completas y el siguiente comando de la cadena."""
    findings = ledger.get("findings", [])
    completed = [name for name, done in STAGE_DONE if done(ledger)]

    def is_open(f):
        return f.get("status") not in ("closed", "filtered")

    if not findings:
        nxt = "/vuln-hunter:scan"
    elif any(f.get("source") == "sast" and "exploitability" not in f and is_open(f) for f in findings):
        nxt = "/vuln-hunter:redteam all"
    elif any("exploitability" in f and "triage" not in f for f in findings):
        nxt = "/vuln-hunter:triage"
    elif any(f.get("status") in OPEN_STATUSES for f in findings):
        nxt = "/vuln-hunter:fix all"
    elif any(f.get("status") == "fixed" for f in findings):
        nxt = "/vuln-hunter:verify all"
    else:
        nxt = "/vuln-hunter:report"

    open_n = sum(1 for f in findings if is_open(f))
    return {
        "schema_version": ledger.get("schema_version"),
        "completed": completed,
        "next_command": nxt,
        "open": open_n,
        "total": len(findings),
    }


def findings_under(ledger, path):
    """Findings cuyo `location` (sin :linea) cae dentro del subarbol `path`."""
    p = (path or "").rstrip("/")
    out = []
    for f in ledger.get("findings", []):
        loc = (f.get("location") or "")
        locpath = loc.split(":", 1)[0]
        if locpath == p or locpath.startswith(p + "/"):
            out.append({"id": f.get("id"), "location": loc, "status": f.get("status")})
    return out


def _load(path):
    with open(path) as fh:
        return json.load(fh)


def main(argv):
    if len(argv) < 3:
        print("uso: ledger.py <migrate|resume|under> <ledger.json> [path]", file=sys.stderr)
        return 2
    cmd, path = argv[1], argv[2]
    if not os.path.exists(path):
        print(f"vuln-hunter ledger: no existe {path}", file=sys.stderr)
        return 1
    ledger = migrate(_load(path))

    if cmd == "migrate":
        with open(path, "w") as fh:
            json.dump(ledger, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"vuln-hunter ledger: migrado a schema {CURRENT_SCHEMA} ({len(ledger['findings'])} findings)")
        return 0
    if cmd == "resume":
        print(json.dumps(resume_point(ledger), ensure_ascii=False, indent=2))
        return 0
    if cmd == "under":
        if len(argv) < 4:
            print("uso: ledger.py under <ledger.json> <path>", file=sys.stderr)
            return 2
        print(json.dumps(findings_under(ledger, argv[3]), ensure_ascii=False, indent=2))
        return 0
    print(f"vuln-hunter ledger: comando desconocido '{cmd}'", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
