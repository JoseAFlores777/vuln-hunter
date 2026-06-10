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
import tempfile


def atomic_write_json(path, data):
    """Escribe JSON de forma atomica (tmp + os.replace) en el mismo directorio.
    Rompe cualquier symlink en el destino y evita ledgers corruptos a medias si
    varios agentes reescriben. Nombre temporal unico para no pisar a otro escritor."""
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".ledger.", suffix=".tmp")
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

CURRENT_SCHEMA = "1.2"
DEFAULT_STATUS = "hypothesis"
# Abiertos = aun requieren accion. 'fixing' = el fixer empezo pero no termino.
# 'candidate-resolved' = desaparecio en rescan pero sin verificar: sigue abierto.
OPEN_STATUSES = {None, "hypothesis", "confirmed", "triaged", "planned", "fixing", "candidate-resolved"}


def _is_open(f):
    return isinstance(f, dict) and f.get("status") not in ("closed", "filtered")


def _core_next(findings):
    """Router COMPARTIDO de la etapa de findings (tras detect+scan). Fuente unica
    para resume_point y status.py: asi no pueden discrepar en este tramo. Las
    superficies anaden por su cuenta los gates previos (detect/scan/plan)."""
    findings = [f for f in findings if isinstance(f, dict)]
    if any(f.get("source") == "sast" and "exploitability" not in f and _is_open(f) for f in findings):
        return "/vuln-hunter:redteam all"
    # candidate-resolved -> verify ANTES que fix/patch: no hay diff que aprobar.
    if any(f.get("status") == "candidate-resolved" for f in findings):
        return "/vuln-hunter:verify all"
    if any(_is_open(f) and "triage" not in f for f in findings):
        return "/vuln-hunter:triage"
    if any(f.get("status") in OPEN_STATUSES for f in findings):
        return "/vuln-hunter:fix all"
    if any(f.get("status") == "fixed" for f in findings):
        return "/vuln-hunter:verify all"
    return "/vuln-hunter:report"

# Orden canonico de etapas (coincide con activity.py y el panel).
def _has(L, key):
    return any(isinstance(f, dict) and key in f for f in L.get("findings", []))


STAGE_DONE = [
    ("detect",   lambda L: bool(L.get("run", {}).get("stacks"))),
    ("RECON",    lambda L: bool(L.get("attack_surface"))),
    ("SAST",     lambda L: _has(L, "sast")),
    ("INTEL",    lambda L: _has(L, "intel")),
    ("RED-TEAM", lambda L: _has(L, "exploitability")),
    ("TRIAGE",   lambda L: _has(L, "triage")),
    ("plan",     lambda L: bool(L.get("plan_ref"))),
    ("FIX",      lambda L: _has(L, "fix")),
    ("VERIFY",   lambda L: _has(L, "verification")),
]


def migrate(ledger):
    """Sube el ledger al schema actual sin perder datos. Idempotente.
    PURGA entradas de findings que no sean objetos (un ledger envenenado con
    strings/numeros en `findings` haria crashear a todos los consumidores)."""
    if not isinstance(ledger, dict):
        ledger = {}
    if not isinstance(ledger.get("run"), dict):
        ledger["run"] = {}
    findings = ledger.get("findings")
    if not isinstance(findings, list):
        findings = []
    clean = [f for f in findings if isinstance(f, dict)]
    for f in clean:
        f.setdefault("status", DEFAULT_STATUS)
    ledger["findings"] = clean
    ledger["schema_version"] = CURRENT_SCHEMA
    return ledger


def resume_point(ledger):
    """Devuelve etapas completas y el siguiente comando de la cadena."""
    findings = [f for f in ledger.get("findings", []) if isinstance(f, dict)]
    completed = [name for name, done in STAGE_DONE if done(ledger)]

    nxt = "/vuln-hunter:scan" if not findings else _core_next(findings)
    open_n = sum(1 for f in findings if _is_open(f))
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
        if not isinstance(f, dict):
            continue
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
        atomic_write_json(path, ledger)
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
