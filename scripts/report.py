#!/usr/bin/env python3
"""
vuln-hunter :: report.py
Genera el informe FORMAL de auditoria a partir de .vuln-hunter/ledger.json.

Determinista y reproducible (no depende del LLM). Produce tres artefactos con el
mismo contenido en tres formatos, listos para descargar desde el panel:

    <base>.md     informe en Markdown (3 secciones: auditoria, plan, resultados)
    <base>.html   informe imprimible (boton "Descargar PDF" -> imprimir a PDF)
    <base>.pdf    solo si hay un convertidor disponible (weasyprint / wkhtmltopdf
                  / Chrome|Chromium|Edge headless). Si no, se omite y se usa el
                  boton del HTML.

Estructura del informe:
    1. Auditoria y diagnostico  (superficie, hallazgos, diagnostico por hallazgo)
    2. Estrategia y plan de remediacion  (plan, enfoque por hallazgo, action plan)
    3. Resultados  (fixes aplicados, verificacion, "que esta seguro", estado)

Uso:
    python3 scripts/report.py [ruta_ledger] [base_o_salida]

`base_o_salida` puede ser una base sin extension (.vuln-hunter/audit-report) o una
ruta .html/.md (por retrocompat); en ambos casos se generan los tres formatos.
"""
import html
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

PRIO_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "FILTERED": 9, "—": 5}
PRIO_COLOR = {"P0": "#b4532f", "P1": "#c0772f", "P2": "#c89a3c", "P3": "#6b7d5c", "FILTERED": "#8a847a", "—": "#8a847a"}
STATUS_LABEL = {
    "hypothesis": "Hipotesis", "confirmed": "Confirmada", "triaged": "Triada",
    "planned": "Planificada", "fixed": "Corregida", "closed": "Cerrada", "filtered": "Filtrada",
}


# ----------------------------- helpers --------------------------------------
def esc(x):
    return html.escape(str(x if x is not None else ""))


def mdc(x):
    """Escapa una celda para tablas markdown."""
    s = str(x if x is not None else "—")
    return s.replace("|", "\\|").replace("\n", " ").strip() or "—"


def joinlist(v, sep=", "):
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return sep.join(str(i) for i in v if i not in (None, ""))
    return str(v)


def prio_of(f):
    return (f.get("triage") or {}).get("priority", "—")


def sorted_findings(findings):
    return sorted(findings, key=lambda x: PRIO_ORDER.get(prio_of(x), 5))


def compute(L):
    findings = L.get("findings", [])
    by_prio, kev, ransom = {}, 0, 0
    fixed = verified = 0
    for f in findings:
        by_prio[prio_of(f)] = by_prio.get(prio_of(f), 0) + 1
        intel = f.get("intel") or {}
        if intel.get("in_cisa_kev"):
            kev += 1
        if intel.get("known_ransomware_use"):
            ransom += 1
        if (f.get("fix") or {}).get("applied"):
            fixed += 1
        if (f.get("verification") or {}).get("verdict") in ("pass", "passed", "ok", "verified"):
            verified += 1
    return {"by_prio": by_prio, "kev": kev, "ransom": ransom, "fixed": fixed, "verified": verified}


def action_buckets(findings):
    inmediato, semana, mes = [], [], []
    for f in findings:
        p = prio_of(f)
        in_kev = (f.get("intel") or {}).get("in_cisa_kev")
        if f.get("status") == "filtered":
            continue
        if p == "P0" or in_kev:
            inmediato.append(f)
        elif p == "P1":
            semana.append(f)
        elif p in ("P2", "P3"):
            mes.append(f)
    return inmediato, semana, mes


# ----------------------------- markdown -------------------------------------
def build_md(L, ledger_path):
    run = L.get("run", {})
    findings = L.get("findings", [])
    C = compute(L)
    asf = L.get("attack_surface") or {}
    now = datetime.now().isoformat(timespec="seconds")
    prio_line = " · ".join(f"{p} {n}" for p, n in sorted(C["by_prio"].items(), key=lambda kv: PRIO_ORDER.get(kv[0], 5))) or "sin hallazgos"

    o = []
    o.append("# Informe de auditoría de seguridad — vuln-hunter\n")
    o.append(f"> **Scope:** {mdc(run.get('scope') or 'repo completo')} · **OWASP** {mdc(run.get('owasp_version','2025'))} · "
             f"**Branch:** {mdc(run.get('branch','—'))} · **Generado:** {now}  ")
    o.append("> Defensivo y autorizado. No sustituye una auditoría humana ni SAST/DAST dedicados.\n")

    # Resumen ejecutivo
    o.append("## Resumen ejecutivo\n")
    o.append(f"- **Hallazgos totales:** {len(findings)}")
    o.append(f"- **Por prioridad:** {prio_line}")
    o.append(f"- **En CISA KEV:** {C['kev']}" + ("  ⚠️ vector típico de ransomware (ATT&CK T1190)" if C["kev"] else ""))
    o.append(f"- **Remediación:** {C['fixed']} corregidos · {C['verified']} verificados\n")
    if C["kev"]:
        o.append(f"> ⚠️ **Atención:** {C['kev']} dependencia(s) de producción con CVE en **CISA KEV** "
                 "(explotación confirmada in-the-wild). Parchea **antes de desplegar**.\n")

    # 1. Auditoria y diagnostico
    o.append("---\n\n## 1. Auditoría y diagnóstico\n")
    o.append("### 1.1 Superficie de ataque\n")
    if asf:
        o.append(f"- **Entrypoints:** {mdc(joinlist(asf.get('entrypoints')) or '—')}")
        o.append(f"- **Trust boundaries:** {mdc(joinlist(asf.get('trust_boundaries')) or '—')}")
        o.append(f"- **Zonas de alto riesgo:** {mdc(joinlist(asf.get('high_risk_zones')) or '—')}\n")
    else:
        o.append("- (sin superficie de ataque registrada por recon)\n")

    o.append("### 1.2 Hallazgos\n")
    if findings:
        o.append("| ID | Prio | Título | Ubicación | OWASP / CWE | Explotable | EPSS | Estado |")
        o.append("|---|---|---|---|---|---|---|---|")
        for f in sorted_findings(findings):
            intel = f.get("intel") or {}
            expl = f.get("exploitability") or {}
            ver = f.get("verification") or {}
            badges = ("KEV " if intel.get("in_cisa_kev") else "") + ("RANSOMWARE" if intel.get("known_ransomware_use") else "")
            owc = f"{f.get('owasp_2025') or f.get('owasp_2021') or '—'} / {f.get('cwe') or '—'}"
            est = f"{STATUS_LABEL.get(f.get('status'), f.get('status','—'))} / {ver.get('verdict','—')}"
            epss = intel.get("epss") if intel.get("epss") is not None else "—"
            o.append(f"| `{mdc(f.get('id'))}` | {mdc(prio_of(f))} | {mdc((f.get('title') or '—') + (' ['+badges.strip()+']' if badges.strip() else ''))} "
                     f"| `{mdc(f.get('location'))}` | {mdc(owc)} | {mdc(expl.get('verdict','—'))} | {mdc(epss)} | {mdc(est)} |")
        o.append("")
    else:
        o.append("_Sin hallazgos en el ledger._\n")

    o.append("### 1.3 Diagnóstico por hallazgo\n")
    if not findings:
        o.append("_Sin hallazgos._\n")
    for f in sorted_findings(findings):
        sast = f.get("sast") or {}
        intel = f.get("intel") or {}
        expl = f.get("exploitability") or {}
        tri = f.get("triage") or {}
        tag = []
        if intel.get("in_cisa_kev"):
            tag.append("KEV")
        if intel.get("known_ransomware_use"):
            tag.append("RANSOMWARE")
        head = f"#### {f.get('id','?')} — {f.get('title','(sin título)')}  [{prio_of(f)}]" + (f" [{' '.join(tag)}]" if tag else "")
        o.append(head + "\n")
        o.append(f"- **Ubicación:** `{mdc(f.get('location'))}`")
        o.append(f"- **OWASP:** {mdc(f.get('owasp_2025') or f.get('owasp_2021') or '—')} · **CWE:** {mdc(f.get('cwe') or '—')} · **Fuente:** {mdc(f.get('source') or '—')}")
        if sast:
            o.append(f"- **SAST:** {mdc(sast.get('tool','—'))} · regla `{mdc(sast.get('rule','—'))}` · confianza {mdc(sast.get('confidence','—'))}")
            if sast.get("hypothesis"):
                o.append(f"  - Hipótesis: {mdc(sast.get('hypothesis'))}")
            if sast.get("flow"):
                o.append(f"  - Data-flow: {mdc(joinlist(sast.get('flow'), ' → '))}")
        if intel:
            o.append(f"- **Dependencia:** {mdc(intel.get('package','—'))}@{mdc(intel.get('installed_version','—'))} "
                     f"({mdc(intel.get('ecosystem','—'))}, prod={mdc(intel.get('is_production_dep'))})")
            if intel.get("cve_ids") or intel.get("ghsa_ids"):
                o.append(f"  - CVE/GHSA: {mdc(joinlist(intel.get('cve_ids')) + ('  ' + joinlist(intel.get('ghsa_ids')) if intel.get('ghsa_ids') else ''))}")
            o.append(f"  - EPSS: {mdc(intel.get('epss','—'))} · fix: {mdc(intel.get('fixed_version','—'))}")
        if expl:
            o.append(f"- **Explotabilidad:** {mdc(expl.get('verdict','—'))} "
                     f"(reachable={mdc(expl.get('reachable'))}, controllable={mdc(expl.get('controllable'))})")
            if expl.get("conceptual_chain"):
                o.append(f"  - Cadena conceptual: {mdc(joinlist(expl.get('conceptual_chain'), ' → '))}")
        if tri:
            o.append(f"- **Triage:** CVSS {mdc(tri.get('cvss','—'))} ({mdc(tri.get('cvss_version','—'))}) · prioridad {mdc(tri.get('priority','—'))}")
            if tri.get("rationale"):
                o.append(f"  - {mdc(tri.get('rationale'))}")
        o.append("")

    # 2. Estrategia y plan
    o.append("---\n\n## 2. Estrategia y plan de remediación\n")
    o.append("### 2.1 Plan\n")
    plan_ref = L.get("plan_ref")
    o.append(f"- Referencia del plan: `{mdc(plan_ref)}`\n" if plan_ref else "- (sin plan registrado; usa `/vuln-hunter:plan`)\n")

    o.append("### 2.2 Enfoque de fix por hallazgo\n")
    any_fix = False
    for f in sorted_findings(findings):
        fix = f.get("fix") or {}
        if not fix:
            continue
        any_fix = True
        o.append(f"#### {f.get('id','?')} — {f.get('title','')}")
        o.append(f"- **Causa raíz:** {mdc(fix.get('root_cause','—'))}")
        o.append(f"- **ASVS:** {mdc(joinlist(fix.get('asvs')) or '—')}")
        o.append(f"- **Estrategia:** {mdc(fix.get('summary','—'))}")
        if fix.get("files_touched"):
            o.append(f"- **Archivos:** {mdc(joinlist(fix.get('files_touched')))}")
        o.append("")
    if not any_fix:
        o.append("_Aún no hay enfoque de fix registrado (dry-run o etapa pendiente)._\n")

    o.append("### 2.3 Action Plan priorizado\n")
    inmediato, semana, mes = action_buckets(findings)

    def _bucket(title, items):
        o.append(f"**{title}**")
        if items:
            for f in items:
                o.append(f"- `{f.get('id','?')}` {f.get('title','')} — `{f.get('location','—')}`")
        else:
            o.append("- (nada)")
        o.append("")
    _bucket("Inmediato (P0 / KEV)", inmediato)
    _bucket("Esta semana (P1)", semana)
    _bucket("Este mes (P2 / P3)", mes)

    # 3. Resultados
    o.append("---\n\n## 3. Resultados\n")
    o.append("### 3.1 Fixes aplicados\n")
    applied = [f for f in findings if (f.get("fix") or {}).get("applied")]
    if applied:
        o.append("| ID | Aplicado | Archivos | Causa raíz |")
        o.append("|---|---|---|---|")
        for f in applied:
            fix = f.get("fix") or {}
            o.append(f"| `{mdc(f.get('id'))}` | sí | {mdc(joinlist(fix.get('files_touched')))} | {mdc(fix.get('root_cause','—'))} |")
        o.append("")
    else:
        o.append("_Sin fixes aplicados (dry-run o pendiente de `/vuln-hunter:fix` + `/vuln-hunter:patch`)._\n")

    o.append("### 3.2 Verificación\n")
    vers = [f for f in findings if f.get("verification")]
    if vers:
        o.append("| ID | Re-scan | Tests | Sin nuevos | Veredicto | Evidencia |")
        o.append("|---|---|---|---|---|---|")
        for f in vers:
            v = f.get("verification") or {}
            o.append(f"| `{mdc(f.get('id'))}` | {mdc(v.get('rescan_clear'))} | {mdc(v.get('tests_pass'))} | "
                     f"{mdc(v.get('no_new_findings'))} | {mdc(v.get('verdict','—'))} | {mdc(v.get('evidence','—'))} |")
        o.append("")
    else:
        o.append("_Sin verificación registrada (pendiente de `/vuln-hunter:verify`)._\n")

    o.append("### 3.3 Qué está seguro\n")
    safe = [f for f in findings if f.get("status") in ("closed", "filtered")]
    if safe:
        for f in safe:
            why = (f.get("triage") or {}).get("rationale") or (f.get("verification") or {}).get("verdict") or STATUS_LABEL.get(f.get("status"), f.get("status"))
            o.append(f"- `{f.get('id','?')}` {f.get('title','')} — {mdc(why)}")
    else:
        o.append("- (sin elementos cerrados/filtrados todavía)")
    o.append("")

    o.append("### 3.4 Estado final\n")
    pend = len(findings) - C["fixed"]
    o.append(f"- Corregidos: **{C['fixed']}/{len(findings)}** · Verificados: **{C['verified']}**")
    o.append(f"- Pendientes: **{max(pend,0)}**")
    if C["kev"]:
        o.append(f"- **Deploy:** bloqueado por {C['kev']} CVE en KEV hasta parchear.")
    o.append("")

    o.append(f"---\n\n_Generado de forma determinista desde `{esc(ledger_path)}` el {now}. "
             "vuln-hunter es un primer pase disciplinado; no reemplaza auditoría humana._\n")
    return "\n".join(o)


# ----------------------------- html -----------------------------------------
def md_to_html_blocks(md_text):
    """Render mínimo de un subconjunto de Markdown (headings, tablas, listas,
    blockquotes, código inline) — suficiente para el informe que generamos."""
    out = []
    lines = md_text.split("\n")
    i = 0
    n = len(lines)

    def inline(s):
        s = esc(s)
        # negrita **x**
        import re
        s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        return s

    while i < n:
        ln = lines[i]
        if not ln.strip():
            i += 1
            continue
        if ln.startswith("#### "):
            out.append(f"<h4>{inline(ln[5:])}</h4>"); i += 1; continue
        if ln.startswith("### "):
            out.append(f"<h3>{inline(ln[4:])}</h3>"); i += 1; continue
        if ln.startswith("## "):
            out.append(f"<h2>{inline(ln[3:])}</h2>"); i += 1; continue
        if ln.startswith("# "):
            out.append(f"<h1>{inline(ln[2:])}</h1>"); i += 1; continue
        if ln.startswith("---"):
            out.append("<hr>"); i += 1; continue
        if ln.startswith(">"):
            buf = []
            while i < n and lines[i].startswith(">"):
                buf.append(inline(lines[i].lstrip("> ").rstrip()))
                i += 1
            out.append("<blockquote>" + "<br>".join(buf) + "</blockquote>"); continue
        if ln.lstrip().startswith("|") and i + 1 < n and set(lines[i + 1].replace("|", "").replace(":", "").strip()) <= {"-", " "}:
            header = [c.strip() for c in ln.strip().strip("|").split("|")]
            i += 2
            body = []
            while i < n and lines[i].lstrip().startswith("|"):
                body.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            th = "".join(f"<th>{inline(h)}</th>" for h in header)
            trs = "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in row) + "</tr>" for row in body)
            out.append(f"<table><thead><tr>{th}</tr></thead><tbody>{trs}</tbody></table>"); continue
        if ln.lstrip().startswith("- "):
            items = []
            base_indent = len(ln) - len(ln.lstrip())
            while i < n and lines[i].lstrip().startswith("- "):
                indent = len(lines[i]) - len(lines[i].lstrip())
                items.append((indent, inline(lines[i].lstrip()[2:])))
                i += 1
            html_items = "".join(f'<li style="margin-left:{(ind-base_indent)}px">{txt}</li>' for ind, txt in items)
            out.append(f"<ul>{html_items}</ul>"); continue
        out.append(f"<p>{inline(ln)}</p>"); i += 1
    return "\n".join(out)


def build_html(md_text, has_pdf, md_name, pdf_name):
    body = md_to_html_blocks(md_text)
    pdf_link = f'<a class="dl" href="{esc(pdf_name)}" download>PDF</a>' if has_pdf else ""
    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vuln-hunter — Informe de auditoría</title>
<style>
  :root{{--paper:#f4f1ea;--ink:#1a1915;--ink-soft:#3a3833;--ink-mute:#8a847a;--rule:#ddd8cc;--accent:#b4532f;--card:#fff}}
  *{{box-sizing:border-box}}
  body{{font-family:'Tinos',Georgia,'Times New Roman',serif;background:var(--paper);color:var(--ink);margin:0;line-height:1.6}}
  .toolbar{{position:sticky;top:0;z-index:5;display:flex;gap:10px;justify-content:flex-end;align-items:center;
    padding:10px 18px;background:rgba(244,241,234,.92);backdrop-filter:blur(6px);border-bottom:1px solid var(--rule)}}
  .toolbar .lbl{{margin-right:auto;font-family:ui-monospace,monospace;font-size:12px;color:var(--ink-mute);letter-spacing:1px}}
  .dl,.print{{font-family:ui-monospace,monospace;font-size:13px;font-weight:700;text-decoration:none;cursor:pointer;
    border:1px solid var(--accent);color:#fff;background:var(--accent);border-radius:8px;padding:8px 14px}}
  .dl{{background:transparent;color:var(--accent)}}
  .wrap{{max-width:900px;margin:0 auto;padding:48px 32px 80px}}
  h1{{font-size:2.1rem;margin:.2em 0 .3em;line-height:1.15}}
  h2{{font-size:1.5rem;margin:1.6em 0 .5em;padding-bottom:.2em;border-bottom:1px solid var(--rule)}}
  h3{{font-size:1.18rem;margin:1.3em 0 .4em;color:var(--ink-soft)}}
  h4{{font-size:1.02rem;margin:1.1em 0 .3em;font-family:ui-monospace,monospace}}
  p,li{{font-size:1.02rem}}
  blockquote{{margin:1em 0;padding:12px 18px;background:#fbf6ec;border-left:4px solid var(--accent);border-radius:6px;color:var(--ink-soft)}}
  ul{{margin:.4em 0 .8em;padding-left:1.3em}} li{{margin:.18em 0}}
  hr{{border:0;border-top:1px solid var(--rule);margin:2em 0}}
  code{{font-family:ui-monospace,SFMono-Regular,monospace;background:rgba(107,125,92,.12);padding:1px 5px;border-radius:4px;font-size:.86em}}
  table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--rule);border-radius:10px;overflow:hidden;font-size:.92rem;margin:.6em 0 1.1em}}
  th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid #eee7d8;vertical-align:top}}
  th{{background:#faf8f2;font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--ink-mute)}}
  @media print{{
    .toolbar{{display:none}}
    body{{background:#fff}}
    .wrap{{max-width:none;padding:0}}
    h2{{break-after:avoid}} table,blockquote,h3,h4{{break-inside:avoid}}
    @page{{margin:18mm 16mm}}
  }}
  @media (max-width:640px){{.wrap{{padding:28px 18px}}}}
</style></head><body>
<div class="toolbar">
  <span class="lbl">vuln-hunter // informe de auditoría</span>
  {pdf_link}
  <a class="dl" href="{esc(md_name)}" download>Markdown</a>
  <button class="print" onclick="window.print()">Descargar PDF</button>
</div>
<div class="wrap">{body}</div>
</body></html>"""


# ----------------------------- pdf ------------------------------------------
def _find_chrome():
    cands = [
        "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "microsoft-edge",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ]
    for c in cands:
        if os.sep in c:
            if os.path.exists(c):
                return c
        else:
            w = shutil.which(c)
            if w:
                return w
    return None


def try_pdf(html_path, pdf_path):
    """Intenta generar el PDF con el primer convertidor disponible. Devuelve el
    nombre de la herramienta usada, o None si ninguno esta disponible."""
    apath = os.path.abspath(html_path)
    ppath = os.path.abspath(pdf_path)

    def _run(cmd):
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=180)
            return os.path.exists(ppath) and os.path.getsize(ppath) > 0
        except Exception:
            return False

    if shutil.which("weasyprint") and _run(["weasyprint", apath, ppath]):
        return "weasyprint"
    if shutil.which("wkhtmltopdf") and _run(["wkhtmltopdf", "--quiet", "--enable-local-file-access", apath, ppath]):
        return "wkhtmltopdf"
    chrome = _find_chrome()
    if chrome:
        url = "file://" + apath
        if _run([chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={ppath}", url]):
            return os.path.basename(chrome)
        if _run([chrome, "--headless", "--disable-gpu", f"--print-to-pdf={ppath}", url]):
            return os.path.basename(chrome)
    return None


# ----------------------------- main -----------------------------------------
def main():
    ledger_path = sys.argv[1] if len(sys.argv) > 1 else ".vuln-hunter/ledger.json"
    out_arg = sys.argv[2] if len(sys.argv) > 2 else ".vuln-hunter/audit-report"

    # base sin extension (acepta .html/.md por retrocompat)
    if out_arg.endswith(".html"):
        base = out_arg[:-5]
    elif out_arg.endswith(".md"):
        base = out_arg[:-3]
    else:
        base = out_arg

    try:
        with open(ledger_path) as fh:
            L = json.load(fh)
    except Exception as e:
        print(f"vuln-hunter: no se pudo leer el ledger ({e})", file=sys.stderr)
        return 1

    md_path = base + ".md"
    html_path = base + ".html"
    pdf_path = base + ".pdf"
    md_name = os.path.basename(md_path)
    pdf_name = os.path.basename(pdf_path)

    os.makedirs(os.path.dirname(os.path.abspath(base)), exist_ok=True)

    md_text = build_md(L, ledger_path)
    with open(md_path, "w") as fh:
        fh.write(md_text)

    # PDF primero (necesita el HTML); generamos un HTML temporal de contenido,
    # luego el HTML final ya sabe si el PDF existe para mostrar el enlace.
    with open(html_path, "w") as fh:
        fh.write(build_html(md_text, False, md_name, pdf_name))
    tool = try_pdf(html_path, pdf_path)
    if tool:
        with open(html_path, "w") as fh:
            fh.write(build_html(md_text, True, md_name, pdf_name))

    n = len(L.get("findings", []))
    print(f"vuln-hunter: informe escrito ({n} hallazgos)")
    print(f"  markdown: {md_path}")
    print(f"  html:     {html_path}  (boton 'Descargar PDF' = imprimir a PDF)")
    if tool:
        print(f"  pdf:      {pdf_path}  (via {tool})")
    else:
        print("  pdf:      no se generó (sin weasyprint/wkhtmltopdf/Chrome). "
              "Abre el HTML y usa 'Descargar PDF' (Cmd/Ctrl+P → Guardar como PDF).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
