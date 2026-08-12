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
4) renumber(ledger): canonicaliza los ids de recoleccion (VULN-1xx SAST / VULN-2xx
   SCA / VULN-9xx recon — necesarios para que sast-analyst y threat-intel-scout
   escriban en paralelo sin chocar de id, ver skill ledger-contract) a
   VULN-001, VULN-002... crecientes, en el orden en que se descubrieron. El id
   de recoleccion NO se pierde: queda en `origin_id`. Pensado para que el
   triage-judge lo corra al consolidar (el humano nunca deberia leer "VULN-209"
   en el informe).

Uso CLI:
    python3 scripts/ledger.py migrate  <ledger.json>   # migra EN SITIO (escribe)
    python3 scripts/ledger.py resume   <ledger.json>    # imprime punto de reanudacion
    python3 scripts/ledger.py under    <ledger.json> <path>
    python3 scripts/ledger.py renumber <ledger.json>   # canonicaliza ids EN SITIO
"""
import json
import os
import re
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
    strings/numeros en `findings` haria crashear a todos los consumidores).

    Tambien CANONICALIZA los ids (VULN-101/VULN-209 -> VULN-001/VULN-002...,
    ver renumber()). Esto es lo que hace que la version con ids crecientes sea
    retrocompatible: `migrate` ya se corria en cada comando que toca un ledger
    existente (hunt/resume/rescan, y el propio CLI de este script para
    migrate/resume/under), asi que un repo que actualiza el plugin y ya tenia
    una auditoria corrida en un schema anterior queda con ids canonicos en
    cuanto se vuelve a tocar el ledger — sin que el usuario tenga que saber que
    `renumber` existe ni correrlo a mano."""
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
    ledger = renumber(ledger)
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


_CANON_ID_RE = re.compile(r"^VULN-\d+$")
_TRAILING_NUM_RE = re.compile(r"(\d+)$")


def renumber(ledger):
    """Reasigna `id` a VULN-001, VULN-002... crecientes (sin saltos tipo 101/209
    que confunden al leer el informe). Determinista, sin LLM: el orden es el
    numero del id de RECOLECCION (VULN-1xx/2xx/9xx = orden real de descubrimiento
    dentro del run, ver skill ledger-contract), no la prioridad de triage (que
    puede variar entre corridas). Idempotente e incremental:
    - Un finding con `origin_id` ya es canonico -> se deja tal cual, y su numero
      cuenta para no repetirse.
    - Un finding SIN `origin_id` es nuevo (recien creado por sast-analyst,
      threat-intel-scout, o al vuelo por appsec-fixer) -> se le asigna el
      siguiente numero libre, seguido de continuar la secuencia.
    El id original queda en `origin_id` (nunca se pierde, para trazabilidad con
    activity.jsonl: las lineas de log ya escritas con el id de recoleccion no se
    reescriben — es un log append-only — asi que conservan el id que tenian en
    ese instante). Si `triage.dedup_of` apuntaba al id viejo de un finding que se
    esta renumerando, se actualiza al nuevo id."""
    findings = [f for f in ledger.get("findings", []) if isinstance(f, dict)]

    max_n = 0
    for f in findings:
        if f.get("origin_id") and _CANON_ID_RE.match(f.get("id") or ""):
            max_n = max(max_n, int(f["id"].split("-", 1)[1]))

    pending = [f for f in findings if not f.get("origin_id")]

    def _discovery_key(f):
        m = _TRAILING_NUM_RE.search(f.get("id") or "")
        return (int(m.group(1)) if m else 0, f.get("id") or "")

    pending.sort(key=_discovery_key)

    remap = {}
    for f in pending:
        max_n += 1
        old_id = f.get("id")
        new_id = f"VULN-{max_n:03d}"
        remap[old_id] = new_id
        f["origin_id"] = old_id
        f["id"] = new_id

    if remap:
        for f in findings:
            tri = f.get("triage")
            if isinstance(tri, dict) and tri.get("dedup_of") in remap:
                tri["dedup_of"] = remap[tri["dedup_of"]]

    return ledger


def _load(path):
    with open(path) as fh:
        return json.load(fh)


def main(argv):
    if len(argv) < 3:
        print("uso: ledger.py <migrate|resume|under|renumber> <ledger.json> [path]", file=sys.stderr)
        return 2
    cmd, path = argv[1], argv[2]
    if not os.path.exists(path):
        print(f"vuln-hunter ledger: no existe {path}", file=sys.stderr)
        return 1
    raw = _load(path)
    before_ids = {f.get("id") for f in raw.get("findings", []) if isinstance(f, dict)}
    ledger = migrate(raw)  # migrate() ya canonicaliza ids (renumber) — ver su docstring

    # 'renumber' es un alias explicito de 'migrate' para cuando lo que se quiere
    # comunicar es "canonicaliza los ids" (p.ej. desde commands/triage.md tras
    # consolidar): ambos hacen exactamente lo mismo, solo cambia el mensaje.
    if cmd in ("migrate", "renumber"):
        atomic_write_json(path, ledger)
        after_ids = [f.get("id") for f in ledger["findings"] if isinstance(f, dict)]
        renumbered = len(before_ids - set(after_ids))
        if cmd == "renumber" or renumbered:
            highest = max(after_ids, key=lambda i: int(i.split("-", 1)[1]) if _CANON_ID_RE.match(i or "") else -1, default="—")
            print(f"vuln-hunter ledger: {renumbered} id(s) canonicalizados ({len(after_ids)} findings, "
                  f"el ultimo es {highest})")
        else:
            print(f"vuln-hunter ledger: migrado a schema {CURRENT_SCHEMA} ({len(after_ids)} findings)")
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
