#!/usr/bin/env python3
"""
vuln-hunter :: deploy-gate.py
Productor DETERMINISTA del gate de despliegue (.vuln-hunter/deploy-blocked).

Antes, ningun script escribia ese archivo: dependia de que el LLM lo creara, asi
que el "bloqueo de deploy por KEV" (CLAUDE.md regla 7) no estaba realmente
forzado y era manipulable por inyeccion. Este script DERIVA el archivo del ledger
de forma reproducible:

  - Bloquea si hay algun hallazgo ABIERTO de dependencia de PRODUCCION con CVE en
    CISA KEV, o con EPSS >= umbral (def 0.5).
  - Estampa los VULN-ids bloqueantes en el archivo, para que el informe pueda
    comprobar que siguen existiendo (anti-drift).
  - Si no hay bloqueantes, ELIMINA el archivo (idempotente).

El hook guard-commit-and-exec.py solo LEE el archivo; la fuente de verdad es el
ledger, y este script la materializa.

Uso:
    python3 scripts/deploy-gate.py [ledger.json] [--epss UMBRAL] [--check]
      --check : no escribe; exit 0 si APTO, 2 si BLOQUEADO (para CI/gate).
"""
import json
import os
import sys

DEFAULT_EPSS_THRESHOLD = 0.5


def is_open(f):
    if not isinstance(f, dict):
        return False
    if f.get("status") == "filtered":
        return False
    if f.get("status") == "closed" and (f.get("verification") or {}).get("verdict") == "CLOSED":
        return False
    return True


def blocking_findings(ledger, epss_threshold):
    out = []
    for f in ledger.get("findings", []):
        if not is_open(f):
            continue
        intel = f.get("intel") or {}
        # Solo dependencias de produccion (is_production_dep no-False; las SCA
        # marcan True; si falta el campo, no asumimos prod salvo que haya KEV).
        prod = intel.get("is_production_dep")
        kev = bool(intel.get("in_cisa_kev"))
        epss = intel.get("epss")
        high_epss = isinstance(epss, (int, float)) and epss >= epss_threshold
        if (kev or high_epss) and prod is not False:
            reason = "KEV" if kev else f"EPSS {epss}"
            out.append((f.get("id", "?"), intel.get("package", "?"),
                        intel.get("installed_version", "?"), reason))
    return out


def main(argv):
    args = list(argv[1:])
    check = "--check" in args
    if check:
        args.remove("--check")
    epss_threshold = DEFAULT_EPSS_THRESHOLD
    if "--epss" in args:
        i = args.index("--epss")
        try:
            epss_threshold = float(args[i + 1])
            del args[i:i + 2]
        except (IndexError, ValueError):
            print("uso: deploy-gate.py [ledger] [--epss UMBRAL] [--check]", file=sys.stderr)
            return 2

    ledger_path = args[0] if args else ".vuln-hunter/ledger.json"
    gate_file = os.path.join(os.path.dirname(os.path.abspath(ledger_path)), "deploy-blocked")

    try:
        with open(ledger_path) as fh:
            ledger = json.load(fh)
    except Exception as e:
        print(f"vuln-hunter deploy-gate: no se pudo leer el ledger ({e})", file=sys.stderr)
        return 1
    if not isinstance(ledger, dict):
        ledger = {}

    blockers = blocking_findings(ledger, epss_threshold)

    if check:
        if blockers:
            print("DESPLIEGUE_BLOQUEADO:")
            for vid, pkg, ver, reason in blockers:
                print(f"  {vid}  {pkg}@{ver}  ({reason})")
            return 2
        print("APTO_PARA_DESPLIEGUE")
        return 0

    if blockers:
        lines = ["vuln-hunter: deploy BLOQUEADO. Dependencias de produccion con riesgo activo:"]
        for vid, pkg, ver, reason in blockers:
            lines.append(f"  - {vid}  {pkg}@{ver}  ({reason})")
        lines.append("Parchea a la version corregida y vuelve a correr este gate.")
        content = "\n".join(lines) + "\n"
        os.makedirs(os.path.dirname(gate_file) or ".", exist_ok=True)
        # Escritura simple (el archivo es interno al repo, no atacable por symlink
        # desde el arbol auditado porque vive en .vuln-hunter/).
        with open(gate_file, "w") as fh:
            fh.write(content)
        print(f"deploy-gate: BLOQUEADO ({len(blockers)} dependencia(s)). Escrito {gate_file}")
        return 2
    else:
        if os.path.exists(gate_file):
            os.remove(gate_file)
            print(f"deploy-gate: sin bloqueantes; eliminado {gate_file}. APTO_PARA_DESPLIEGUE")
        else:
            print("deploy-gate: sin bloqueantes. APTO_PARA_DESPLIEGUE")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
