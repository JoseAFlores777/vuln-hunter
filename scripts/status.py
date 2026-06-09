#!/usr/bin/env python3
"""
vuln-hunter :: status.py
Dashboard DETERMINISTA del estado de la auditoria, leido de .vuln-hunter/ledger.json.
Lo invoca el comando /vuln-hunter:status. No depende del LLM: siempre muestra el
mismo estado real, con los hallazgos y el SIGUIENTE COMANDO recomendado.

Uso:
    python3 scripts/status.py [ruta_ledger]
"""
import json
import sys

SEV = {"P0": "🔴 P0", "P1": "🟠 P1", "P2": "🟡 P2", "P3": "🟢 P3", "FILTERED": "⚪ filt"}
# Etapas del pipeline y como se detecta que cada una se hizo (campo en el finding)
STAGES = [
    ("detect", "detect"),
    ("SAST", "sast"),
    ("INTEL", "intel"),
    ("red-team", "exploitability"),
    ("triage", "triage"),
    ("plan", None),       # se detecta por plan_ref
    ("fix", "fix"),
    ("verify", "verification"),
]


def load(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


def stage_done(L, key):
    if key is None:
        return bool(L.get("plan_ref"))
    if key == "detect":
        return bool(L.get("run", {}).get("stacks"))
    return any(key in f for f in L.get("findings", []))


def next_command(L):
    """Recomienda el siguiente comando segun el estado del ledger."""
    findings = L.get("findings", [])
    has_sast = any("sast" in f for f in findings)
    has_intel = any("intel" in f for f in findings)
    has_expl = any("exploitability" in f for f in findings)
    has_triage = any("triage" in f for f in findings)
    has_plan = bool(L.get("plan_ref"))
    has_fix = any("fix" in f for f in findings)
    has_verify = any("verification" in f for f in findings)
    kev = any((f.get("intel") or {}).get("in_cisa_kev") for f in findings)

    if not L.get("run", {}).get("stacks"):
        return "/vuln-hunter:detect", "Detectar stacks del proyecto/monorepo (scoping)"
    if not has_sast and not has_intel:
        return "/vuln-hunter:scan  +  /vuln-hunter:watch", "Escanear codigo (SAST) y dependencias (SCA) — pueden ir en paralelo"
    if not has_expl and (has_sast or has_intel):
        return "/vuln-hunter:redteam all", "Confirmar explotabilidad de las hipotesis"
    if not has_triage and has_expl:
        return "/vuln-hunter:triage", "Priorizar lo confirmado (CVSS + EPSS + KEV)"
    if not has_plan and has_triage:
        return "/vuln-hunter:plan", "Generar el plan de remediacion"
    if not has_fix and has_plan:
        return "/vuln-hunter:fix all", "Aplicar fixes de causa raiz (sin commit)"
    if has_fix and not has_verify:
        return "/vuln-hunter:patch  → luego  /vuln-hunter:verify", "Aprobar diffs (por hash) y verificar el cierre"
    if has_verify:
        return "/vuln-hunter:report", "Generar el informe final de auditoria"
    if kev:
        return "/vuln-hunter:triage", "Hay CVE en KEV: priorizar y bloquear deploy"
    return "/vuln-hunter:report", "Revisar el estado actual"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else ".vuln-hunter/ledger.json"
    L = load(path)
    W = 64
    print("┌" + "─" * W + "┐")
    print("│  🛡  vuln-hunter · estado de la auditoria".ljust(W + 1) + "│")
    print("└" + "─" * W + "┘")

    if not L:
        print("\nAun no hay ledger (.vuln-hunter/ledger.json).")
        print("\n▶ Siguiente paso")
        print("  ★ /vuln-hunter:detect      Detectar stacks y empezar")
        return 0

    run = L.get("run", {})
    findings = L.get("findings", [])
    print(f"\nScope    {run.get('scope') or 'repo completo'}   ·   OWASP {run.get('owasp_version','2025')}")
    print(f"Branch   {run.get('branch','—')}   ·   stacks: {', '.join(run.get('stacks', [])) or '—'}")

    # Barra de progreso del flujo
    parts = []
    for label, key in STAGES:
        mark = "✓" if stage_done(L, key) else "○"
        parts.append(f"[{label} {mark}]" if mark == "✓" else f"{label} {mark}")
    print("\nFlujo    " + " → ".join(parts))
    print("         (✓ hecho · ○ pendiente)")

    # Conteo por severidad
    counts = {}
    kev = 0
    for f in findings:
        p = (f.get("triage") or {}).get("priority", "—")
        counts[p] = counts.get(p, 0) + 1
        if (f.get("intel") or {}).get("in_cisa_kev"):
            kev += 1
    if findings:
        resumen = "  ".join(f"{SEV.get(p, p)}×{n}" for p, n in sorted(counts.items()))
        print(f"\nHallazgos {len(findings)} total   {resumen}" + (f"   ·  {kev} en CISA KEV" if kev else ""))
        if kev:
            print("⚠  Hay dependencias de produccion con CVE en CISA KEV → el deploy quedara BLOQUEADO hasta parchear.")
        print()
        order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "FILTERED": 9, "—": 5}
        print(f"  {'ID':<10}{'Sev':<8}{'Titulo':<34}{'Estado'}")
        print("  " + "─" * 60)
        for f in sorted(findings, key=lambda x: order.get((x.get("triage") or {}).get("priority", "—"), 5)):
            sev = SEV.get((f.get("triage") or {}).get("priority", "—"), "  —  ")
            title = (f.get("title") or "")[:32]
            print(f"  {f.get('id',''):<10}{sev:<8}{title:<34}{f.get('status','')}")
    else:
        print("\nSin hallazgos en el ledger todavia.")

    cmd, desc = next_command(L)
    print("\n▶ Siguiente paso")
    print(f"  ★ {cmd}")
    print(f"    {desc}")
    print("\n  ¿Continuo con el paso recomendado? (responde \"si\" o elige otro comando)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
