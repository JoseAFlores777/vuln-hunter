#!/usr/bin/env python3
"""
vuln-hunter :: report.py
Genera un informe HTML de auditoria a partir de .vuln-hunter/ledger.json.
Determinista y reproducible (no depende del LLM). Salida por defecto:
.vuln-hunter/report.html

Uso:
    python3 scripts/report.py [ruta_ledger] [ruta_salida]
"""
import html
import json
import sys
from datetime import datetime

PRIO_COLOR = {"P0": "#b4532f", "P1": "#c0772f", "P2": "#c89a3c", "P3": "#6b7d5c", "FILTERED": "#8a847a"}
STATUS_LABEL = {
    "hypothesis": "Hipotesis", "confirmed": "Confirmada", "triaged": "Triada",
    "planned": "Planificada", "fixed": "Corregida", "closed": "Cerrada", "filtered": "Filtrada",
}


def esc(x):
    return html.escape(str(x if x is not None else ""))


def main():
    ledger_path = sys.argv[1] if len(sys.argv) > 1 else ".vuln-hunter/ledger.json"
    out_path = sys.argv[2] if len(sys.argv) > 2 else ".vuln-hunter/report.html"

    try:
        with open(ledger_path) as fh:
            L = json.load(fh)
    except Exception as e:
        print(f"vuln-hunter: no se pudo leer el ledger ({e})", file=sys.stderr)
        return 1

    run = L.get("run", {})
    findings = L.get("findings", [])

    # Conteos
    by_prio = {}
    kev = 0
    for f in findings:
        p = (f.get("triage") or {}).get("priority", "—")
        by_prio[p] = by_prio.get(p, 0) + 1
        if (f.get("intel") or {}).get("in_cisa_kev"):
            kev += 1

    rows = []
    # Orden por prioridad
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "FILTERED": 9, "—": 5}
    for f in sorted(findings, key=lambda x: order.get((x.get("triage") or {}).get("priority", "—"), 5)):
        tri = f.get("triage") or {}
        intel = f.get("intel") or {}
        expl = f.get("exploitability") or {}
        ver = f.get("verification") or {}
        prio = tri.get("priority", "—")
        color = PRIO_COLOR.get(prio, "#8a847a")
        kev_badge = ' <span style="background:#b4532f;color:#fff;padding:1px 6px;border-radius:4px;font-size:11px">KEV</span>' if intel.get("in_cisa_kev") else ""
        ransom_badge = ' <span style="background:#7a1f1f;color:#fff;padding:1px 6px;border-radius:4px;font-size:11px">RANSOMWARE</span>' if intel.get("known_ransomware_use") else ""
        rows.append(f"""
        <tr>
          <td><code>{esc(f.get('id'))}</code></td>
          <td><span style="color:{color};font-weight:700">{esc(prio)}</span></td>
          <td>{esc(f.get('title'))}{kev_badge}{ransom_badge}</td>
          <td><code>{esc(f.get('location'))}</code></td>
          <td>{esc(f.get('owasp_2025') or f.get('owasp_2021'))}<br><span style="color:#8a847a;font-size:12px">{esc(f.get('cwe'))}</span></td>
          <td>{esc(expl.get('verdict','—'))}</td>
          <td>{esc((intel.get('epss')) if intel.get('epss') is not None else '—')}</td>
          <td>{esc(STATUS_LABEL.get(f.get('status'), f.get('status','—')))} / {esc(ver.get('verdict','—'))}</td>
        </tr>""")

    cards = "".join(
        f'<div class="card"><div class="num" style="color:{PRIO_COLOR.get(p,"#1a1915")}">{n}</div><div class="lbl">{esc(p)}</div></div>'
        for p, n in sorted(by_prio.items(), key=lambda kv: order.get(kv[0], 5))
    )

    doc = f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vuln-hunter — Informe de auditoria</title>
<style>
  body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#f4f1ea;color:#1a1915;margin:0;padding:0;line-height:1.55}}
  .wrap{{max-width:1000px;margin:0 auto;padding:40px 28px}}
  h1{{font-size:2rem;margin:0 0 6px}} .sub{{color:#8a847a;font-family:monospace;font-size:13px;margin-bottom:28px}}
  .cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}}
  .card{{background:#fff;border:1px solid #ddd8cc;border-radius:12px;padding:16px 22px;min-width:90px;text-align:center}}
  .card .num{{font-size:1.8rem;font-weight:700}} .card .lbl{{font-family:monospace;font-size:12px;color:#8a847a}}
  .kev-alert{{background:#fdf0ec;border-left:4px solid #b4532f;border-radius:8px;padding:14px 18px;margin-bottom:24px}}
  table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #ddd8cc;border-radius:12px;overflow:hidden;font-size:14px}}
  th,td{{text-align:left;padding:11px 13px;border-bottom:1px solid #eee7d8;vertical-align:top}}
  th{{background:#faf8f2;font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:#8a847a}}
  code{{background:rgba(107,125,92,.12);padding:1px 5px;border-radius:4px;font-size:.85em}}
  footer{{margin-top:28px;color:#8a847a;font-size:12px;font-family:monospace}}
</style></head><body><div class="wrap">
<h1>Informe de auditoria — vuln-hunter</h1>
<div class="sub">scope: {esc(run.get('scope') or 'repo completo')} · OWASP {esc(run.get('owasp_version','2025'))} · branch: {esc(run.get('branch','—'))} · generado: {datetime.now().isoformat(timespec='seconds')}</div>
<div class="cards">{cards}<div class="card"><div class="num" style="color:#b4532f">{kev}</div><div class="lbl">EN CISA KEV</div></div></div>
{'<div class="kev-alert"><b>Atencion:</b> hay ' + str(kev) + ' dependencia(s) de produccion con CVE en CISA KEV (explotacion confirmada in-the-wild). Son el vector tipico de ransomware (T1190): parchea antes de desplegar.</div>' if kev else ''}
<table><thead><tr><th>ID</th><th>Prioridad</th><th>Titulo</th><th>Ubicacion</th><th>OWASP / CWE</th><th>Explotable</th><th>EPSS</th><th>Estado</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan="8" style="text-align:center;color:#8a847a;padding:30px">Sin hallazgos en el ledger.</td></tr>'}</tbody></table>
<footer>Generado de forma determinista desde {esc(ledger_path)} · vuln-hunter no sustituye auditoria humana ni SAST/DAST dedicados.</footer>
</div></body></html>"""

    with open(out_path, "w") as fh:
        fh.write(doc)
    print(f"vuln-hunter: informe escrito en {out_path} ({len(findings)} hallazgos)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
