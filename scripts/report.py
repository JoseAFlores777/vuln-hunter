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
    "planned": "Planificada", "fixing": "En proceso",
    "candidate-resolved": "Candidato a resuelto", "fixed": "Corregida",
    "closed": "Cerrada", "filtered": "Filtrada",
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


# --- invariantes de honestidad (CLAUDE.md regla 9) -------------------------
# Nada se reporta como "cerrado/seguro" por la mera cadena de status: exige
# evidencia real (verdict CLOSED del verify-engineer) o un triage que lo filtre.
# Asi un status:"closed" puesto a mano / por inyeccion sin verificacion NO infla
# los KPIs ni la lista "Que esta seguro".
def is_truly_closed(f):
    return (f.get("status") == "closed"
            and (f.get("verification") or {}).get("verdict") == "CLOSED")


def is_filtered(f):
    tri = f.get("triage") or {}
    return (f.get("status") == "filtered"
            and bool(tri.get("rationale") or tri.get("priority") == "FILTERED"))


def is_open(f):
    return not (is_truly_closed(f) or is_filtered(f))


def fix_applied_real(f):
    """Fix aplicado de verdad: applied==true y NO un auto-'fixed' de rescan
    (desaparecer del escaner no es evidencia de correccion — CLAUDE.md regla 9)."""
    fix = f.get("fix") or {}
    return bool(fix.get("applied")) and fix.get("source") != "rescan"


def sorted_findings(findings):
    return sorted(findings, key=lambda x: PRIO_ORDER.get(prio_of(x), 5))


def compute(L):
    findings = L.get("findings", [])
    by_prio, kev, ransom = {}, 0, 0
    fixed = verified = closed = closed_unverified = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        by_prio[prio_of(f)] = by_prio.get(prio_of(f), 0) + 1
        intel = f.get("intel") or {}
        if intel.get("in_cisa_kev"):
            kev += 1
        if intel.get("known_ransomware_use"):
            ransom += 1
        if fix_applied_real(f):
            fixed += 1
        # 'verificado' = el verify-engineer dictamino CLOSED (vocabulario del schema,
        # enum CLOSED/NOT_CLOSED/REGRESSION). Antes se buscaba "pass"/"verified",
        # que NUNCA matcheaba -> el informe decia "ninguno cerrado" por error.
        if (f.get("verification") or {}).get("verdict") == "CLOSED":
            verified += 1
        # 'cerrado' = cerrado DE VERDAD: status closed + verdict CLOSED. Un status
        # closed sin verificacion no cuenta (no se finge seguridad).
        if is_truly_closed(f):
            closed += 1
        if f.get("status") == "closed" and not is_truly_closed(f):
            closed_unverified += 1
    return {"by_prio": by_prio, "kev": kev, "ransom": ransom,
            "fixed": fixed, "verified": verified, "closed": closed,
            "closed_unverified": closed_unverified}


def risk_verdict(L):
    """Veredicto ejecutivo en una linea: (nivel, texto, color). Determinista."""
    findings = L.get("findings", [])
    C = compute(L)
    open_f = [f for f in findings if isinstance(f, dict) and is_open(f)]
    open_p0 = sum(1 for f in open_f if prio_of(f) == "P0")
    open_kev = sum(1 for f in open_f if (f.get("intel") or {}).get("in_cisa_kev"))
    open_p1 = sum(1 for f in open_f if prio_of(f) == "P1")
    bits = []
    if open_p0:
        bits.append(f"{open_p0} P0 sin cerrar")
    if open_p1:
        bits.append(f"{open_p1} P1 sin cerrar")
    if open_kev:
        bits.append(f"{open_kev} dependencia(s) en CISA KEV → deploy bloqueado")
    if not findings:
        return ("sin hallazgos", "Sin hallazgos en el ledger. Corre la auditoría para poblarlo.", "#6b7d5c")
    if not open_f:
        return ("controlado", f"Todos los hallazgos cerrados o filtrados ({C['closed']}/{len(findings)}). Riesgo bajo control.", "#6b7d5c")
    if open_p0 or open_kev:
        return ("alto", "Riesgo alto: " + " · ".join(bits) + ".", "#b4532f")
    if open_p1:
        return ("medio", "Riesgo medio: " + " · ".join(bits) + ".", "#c0772f")
    return ("moderado", f"{len(open_f)} hallazgo(s) abiertos de prioridad media/baja.", "#c89a3c")


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
    o.append(f"- **Remediación:** {C['fixed']} corregidos · {C['verified']} verificados · **{C['closed']} cerrados**\n")
    if C["kev"]:
        o.append(f"> ⚠️ **Atención:** {C['kev']} dependencia(s) de producción con CVE en **CISA KEV** "
                 "(explotación confirmada in-the-wild). Parchea **antes de desplegar**.\n")

    # Reconcilia el ledger con el gate REAL (.vuln-hunter/deploy-blocked). Si no
    # coinciden, alguien manipulo uno de los dos: se reporta el desfase en vez de
    # ocultarlo (el gate y el ledger son dos fuentes de verdad que deben concordar).
    open_kev = sum(1 for f in findings if isinstance(f, dict) and is_open(f)
                   and (f.get("intel") or {}).get("in_cisa_kev"))
    gate_exists = os.path.exists(os.path.join(os.path.dirname(os.path.abspath(ledger_path)), "deploy-blocked"))
    if open_kev and not gate_exists:
        o.append(f"> 🚩 **Inconsistencia:** el ledger tiene {open_kev} hallazgo(s) KEV abiertos pero NO existe "
                 "`.vuln-hunter/deploy-blocked`. El gate de deploy podria estar desactivado. "
                 "Corre `python3 scripts/deploy-gate.py` para regenerarlo.\n")
    elif gate_exists and not open_kev:
        o.append("> 🚩 **Inconsistencia:** existe `.vuln-hunter/deploy-blocked` pero el ledger no tiene KEV "
                 "abiertos. Revisa si el bloqueo sigue siendo válido (`python3 scripts/deploy-gate.py`).\n")

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
    # Solo lo cerrado CON evidencia (verdict CLOSED) o filtrado con justificacion.
    # Un status:closed sin verificacion NO se lista como seguro.
    safe = [f for f in findings if isinstance(f, dict) and (is_truly_closed(f) or is_filtered(f))]
    if safe:
        for f in safe:
            why = (f.get("triage") or {}).get("rationale") or (f.get("verification") or {}).get("verdict") or STATUS_LABEL.get(f.get("status"), f.get("status"))
            o.append(f"- `{f.get('id','?')}` {f.get('title','')} — {mdc(why)}")
    else:
        o.append("- (sin elementos verificados como cerrados/filtrados todavía)")
    if C.get("closed_unverified"):
        o.append(f"- ⚠️ {C['closed_unverified']} con `status: closed` pero **sin** veredicto "
                 "`CLOSED` del verify-engineer: NO se cuentan como cerrados (falta evidencia).")
    o.append("")

    o.append("### 3.4 Estado final\n")
    pend = len(findings) - C["closed"]
    o.append(f"- Cerrados: **{C['closed']}/{len(findings)}** · Corregidos: **{C['fixed']}** · Verificados: **{C['verified']}**")
    o.append(f"- Pendientes (no cerrados): **{max(pend,0)}**")
    if C["kev"]:
        o.append(f"- **Deploy:** bloqueado por {C['kev']} CVE en KEV hasta parchear.")
    o.append("")

    # Glosario didactico
    o.append("---\n\n## 4. Glosario\n")
    o.append("Términos para leer este informe sin ser especialista:\n")
    gloss = [
        ("Hallazgo", "Una vulnerabilidad candidata con un id (p.ej. VULN-101). Acumula el análisis de cada etapa."),
        ("Severidad (P0–P3)", "Prioridad de atención. **P0** = crítico/inmediato; **P3** = bajo. Se calcula con CVSS + EPSS + KEV."),
        ("CVSS", "Puntaje estándar de gravedad técnica de una vulnerabilidad (0–10)."),
        ("EPSS", "Probabilidad (0–1) de que una vulnerabilidad sea explotada en los próximos 30 días."),
        ("CISA KEV", "Catálogo de vulnerabilidades con explotación CONFIRMADA in-the-wild. Un CVE aquí es bloqueante de deploy (vector típico de ransomware, ATT&CK T1190)."),
        ("OWASP Top 10", "Lista de referencia de las 10 categorías de riesgo web más comunes."),
        ("CWE", "Catálogo de tipos de debilidad de software (p.ej. CWE-89 = inyección SQL)."),
        ("SAST", "Análisis estático del código propio para encontrar vulnerabilidades."),
        ("SCA", "Análisis de dependencias de terceros contra bases de CVEs."),
        ("Explotabilidad", "Si la vulnerabilidad es realmente alcanzable y aprovechable (PoC conceptual, sin exploit real)."),
        ("Causa raíz", "El origen real del problema, no el síntoma. El fix la ataca para que no reaparezca."),
        ("ASVS", "Estándar OWASP de requisitos de seguridad; cada fix se mapea a uno."),
        ("Estado del hallazgo", "Encontrado → En proceso → Corregido → **Cerrado** (verificado sin regresión) / Filtrado (descartado)."),
    ]
    for term, desc in gloss:
        o.append(f"- **{term}:** {desc}")
    o.append("")

    o.append(f"---\n\n_Generado de forma determinista desde `{esc(ledger_path)}` el {now}. "
             "vuln-hunter es un primer pase disciplinado; no reemplaza auditoría humana._\n")
    return "\n".join(o)


# ----------------------------- html: toc + charts ---------------------------
import re as _re

# Siglas -> definicion para tooltips <abbr> en el informe. Que un no-especialista
# entienda al pasar el cursor, sin salir del documento.
ACRONYMS = {
    "CVSS": "Common Vulnerability Scoring System: puntaje estándar de gravedad técnica (0–10).",
    "EPSS": "Exploit Prediction Scoring System: probabilidad (0–1) de explotación en 30 días.",
    "KEV": "CISA Known Exploited Vulnerabilities: catálogo de vulns con explotación confirmada in-the-wild.",
    "CISA": "Cybersecurity and Infrastructure Security Agency (gobierno de EE. UU.).",
    "SAST": "Static Application Security Testing: análisis estático del código propio.",
    "SCA": "Software Composition Analysis: análisis de dependencias de terceros.",
    "OWASP": "Open Worldwide Application Security Project: referencia de riesgos web.",
    "CWE": "Common Weakness Enumeration: catálogo de tipos de debilidad de software.",
    "CVE": "Common Vulnerabilities and Exposures: identificador único de una vulnerabilidad pública.",
    "GHSA": "GitHub Security Advisory: identificador de aviso de seguridad de GitHub.",
    "ASVS": "Application Security Verification Standard (OWASP): requisitos de seguridad.",
    "PoC": "Proof of Concept: prueba conceptual de explotabilidad (sin exploit real).",
    "IDOR": "Insecure Direct Object Reference: acceso a recursos por id sin verificar permiso.",
    "SSRF": "Server-Side Request Forgery: forzar al servidor a hacer peticiones no deseadas.",
    "XSS": "Cross-Site Scripting: inyección de scripts en la salida HTML.",
    "JWT": "JSON Web Token: token firmado para autenticación/autorización.",
    "T1190": "MITRE ATT&CK T1190: Explotación de aplicación pública (vector inicial típico).",
}
_ACRO_RE = _re.compile(r"\b(" + "|".join(_re.escape(k) for k in sorted(ACRONYMS, key=len, reverse=True)) + r")\b")


STATUS_COLOR = {
    "Cerrada": "#6b7d5c", "Corregida": "#c89a3c", "En proceso": "#3a86a8",
    "Triada": "#8a847a", "Planificada": "#8a847a", "Confirmada": "#8a847a",
    "Hipotesis": "#8a847a", "Filtrada": "#8a847a",
}
_SEV_RE = _re.compile(r"\b(P0|P1|P2|P3|FILTERED)\b")
_ST_RE = _re.compile(r"\b(En proceso|Cerrada|Corregida|Triada|Planificada|Confirmada|Hipotesis|Filtrada)\b")


def decorate_tokens(html_body):
    """Convierte severidades (P0–P3) y estados en chips de color, respetando tags
    y sin tocar el interior de <code>/<abbr>. Hace el informe escaneable de un vistazo."""
    parts = _re.split(r"(<[^>]+>)", html_body)
    skip = 0
    out = []
    for seg in parts:
        if seg.startswith("<"):
            tag = seg.lower()
            if tag.startswith("<code") or tag.startswith("<abbr"):
                skip += 1
            elif tag.startswith("</code") or tag.startswith("</abbr"):
                skip = max(skip - 1, 0)
            out.append(seg)
            continue
        if skip or not seg:
            out.append(seg)
            continue
        seg = _SEV_RE.sub(lambda m: f'<span class="sev-chip" style="background:{PRIO_COLOR.get(m.group(1),"#8a847a")}">{m.group(1)}</span>', seg)
        seg = _ST_RE.sub(lambda m: f'<span class="st-chip" style="color:{STATUS_COLOR.get(m.group(1),"#8a847a")}">{m.group(1)}</span>', seg)
        out.append(seg)
    return "".join(out)


def _svg_matrix(findings):
    """Matriz de riesgo: severidad (filas) x explotabilidad (columnas) con conteos."""
    rows = ["P0", "P1", "P2", "P3"]
    cols = [("EXPLOITABLE", "Explotable"), ("CONDITIONAL", "Condicional"), ("—", "Sin confirmar")]
    grid = {(r, c): 0 for r in rows for c, _ in cols}
    for f in findings:
        p = prio_of(f)
        if p not in rows:
            continue
        v = (f.get("exploitability") or {}).get("verdict") or "—"
        if v not in ("EXPLOITABLE", "CONDITIONAL"):
            v = "—"
        grid[(p, v)] += 1
    th = "".join(f'<th class="mx-c">{esc(lbl)}</th>' for _, lbl in cols)
    trs = []
    for r in rows:
        cells = []
        for c, _ in cols:
            n = grid[(r, c)]
            danger = (r in ("P0", "P1")) and c == "EXPLOITABLE"
            warn = (r in ("P0", "P1")) and c == "CONDITIONAL"
            cls = "mx hot" if (danger and n) else ("mx warn" if (warn and n) else ("mx on" if n else "mx"))
            cells.append(f'<td class="{cls}">{n or ""}</td>')
        trs.append(f'<tr><th class="mx-r" style="color:{PRIO_COLOR.get(r)}">{r}</th>{"".join(cells)}</tr>')
    return f'<table class="matrix"><thead><tr><th></th>{th}</tr></thead><tbody>{"".join(trs)}</tbody></table>'


def wrap_acronyms(html_body):
    """Envuelve siglas conocidas en <abbr title=...> sin tocar tags ni el interior
    de <code> (rutas/reglas no se anotan). Tooltip nativo: accesible y fiel en PDF."""
    parts = _re.split(r"(<[^>]+>)", html_body)
    skip = 0  # profundidad dentro de <code>/<abbr>
    out = []
    for seg in parts:
        if seg.startswith("<"):
            tag = seg.lower()
            if tag.startswith("<code") or tag.startswith("<abbr"):
                skip += 1
            elif tag.startswith("</code") or tag.startswith("</abbr"):
                skip = max(skip - 1, 0)
            out.append(seg)
            continue
        if skip or not seg:
            out.append(seg)
            continue
        out.append(_ACRO_RE.sub(lambda m: f'<abbr class="ac" title="{esc(ACRONYMS[m.group(1)])}">{m.group(1)}</abbr>', seg))
    return "".join(out)


def slugify(text):
    s = _re.sub(r"<[^>]+>", "", str(text))
    s = _re.sub(r"[*`]", "", s)
    s = s.strip().lower()
    s = _re.sub(r"[^a-z0-9áéíóúñ ]+", "", s)
    s = _re.sub(r"\s+", "-", s).strip("-")
    return s or "sec"


def build_toc(md_text):
    """Indice navegable a partir de los headings ## y ### del markdown."""
    rows = []
    for ln in md_text.split("\n"):
        if ln.startswith("### "):
            rows.append((3, ln[4:].strip()))
        elif ln.startswith("## "):
            rows.append((2, ln[3:].strip()))
    items = ['<a class="toc-x" href="#panorama">Panorama</a>']
    for lvl, t in rows:
        cls = "toc-2" if lvl == 2 else "toc-3"
        items.append(f'<a class="{cls}" href="#{slugify(t)}">{esc(_re.sub(r"[*`]","",t))}</a>')
    return '<nav class="toc"><div class="toc-h">Índice</div>' + "".join(items) + "</nav>"


def _svg_donut(by_prio):
    """Dona de distribucion por severidad (SVG inline, sin libs)."""
    order = ["P0", "P1", "P2", "P3", "FILTERED", "—"]
    data = [(p, by_prio.get(p, 0)) for p in order if by_prio.get(p, 0) > 0]
    total = sum(n for _, n in data) or 1
    cx = cy = 80
    r = 60
    stroke = 26
    import math
    circ = 2 * math.pi * r
    off = 0.0
    segs = []
    for p, n in data:
        frac = n / total
        seg_len = frac * circ
        segs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{PRIO_COLOR.get(p,"#8a847a")}" '
            f'stroke-width="{stroke}" stroke-dasharray="{seg_len:.2f} {circ-seg_len:.2f}" '
            f'stroke-dashoffset="{-off:.2f}" transform="rotate(-90 {cx} {cy})"><title>{esc(p)}: {n}</title></circle>'
        )
        off += seg_len
    legend = "".join(
        f'<span class="lg"><span class="sw" style="background:{PRIO_COLOR.get(p,"#8a847a")}"></span>{esc(p)} · {n}</span>'
        for p, n in data
    ) or '<span class="lg">sin hallazgos</span>'
    return (
        f'<svg viewBox="0 0 160 160" width="160" height="160" role="img" aria-label="Hallazgos por severidad">'
        f'{"".join(segs)}'
        f'<text x="{cx}" y="{cy-4}" text-anchor="middle" class="dn-n">{total}</text>'
        f'<text x="{cx}" y="{cy+14}" text-anchor="middle" class="dn-l">hallazgos</text></svg>'
        f'<div class="legend">{legend}</div>'
    )


def _svg_bars(pairs, color="#6b7d5c", label="—"):
    """Barras horizontales (categoria -> conteo)."""
    if not pairs:
        return '<p class="muted">— sin datos —</p>'
    mx = max(n for _, n in pairs) or 1
    rows = []
    bw = 220
    for name, n in pairs:
        w = max(3, int(bw * n / mx))
        rows.append(
            f'<div class="bar"><span class="bar-l" title="{esc(name)}">{esc(name)}</span>'
            f'<span class="bar-t"><span class="bar-f" style="width:{w}px;background:{color}"></span></span>'
            f'<span class="bar-n">{n}</span></div>'
        )
    return '<div class="bars">' + "".join(rows) + "</div>"


def _svg_progress(C, total):
    """Barra de progreso de remediacion: cerrados / corregidos / pendientes."""
    total = total or 1
    closed = C["closed"]
    fixed_only = max(C["fixed"] - closed, 0)
    pend = max(total - closed - fixed_only, 0)
    seg = []
    x = 0.0
    W = 280.0
    for n, col, lbl in [(closed, "#6b7d5c", "cerrados"), (fixed_only, "#c89a3c", "corregidos"), (pend, "#c0563a", "pendientes")]:
        if n <= 0:
            continue
        w = W * n / total
        seg.append(f'<rect x="{x:.1f}" y="0" width="{w:.1f}" height="20" fill="{col}"><title>{lbl}: {n}</title></rect>')
        x += w
    legend = (
        f'<span class="lg"><span class="sw" style="background:#6b7d5c"></span>Cerrados {closed}</span>'
        f'<span class="lg"><span class="sw" style="background:#c89a3c"></span>Corregidos {fixed_only}</span>'
        f'<span class="lg"><span class="sw" style="background:#c0563a"></span>Pendientes {pend}</span>'
    )
    return (f'<svg viewBox="0 0 280 20" width="100%" height="20" preserveAspectRatio="none" '
            f'role="img" aria-label="Progreso de remediación">{"".join(seg)}</svg>'
            f'<div class="legend">{legend}</div>')


def build_charts_html(L):
    findings = L.get("findings", [])
    C = compute(L)
    total = len(findings)
    # OWASP distribution
    owc = {}
    for f in findings:
        k = f.get("owasp_2025") or f.get("owasp_2021") or "—"
        owc[k] = owc.get(k, 0) + 1
    owpairs = sorted(owc.items(), key=lambda kv: -kv[1])[:8]
    kev = C["kev"]
    lvl, vtext, vcolor = risk_verdict(L)
    return f"""<section id="panorama" class="panorama">
  <h2 class="pan-h">Panorama de la auditoría</h2>
  <div class="verdict" style="border-color:{vcolor}">
    <span class="verdict-dot" style="background:{vcolor}"></span>
    <span class="verdict-lvl" style="color:{vcolor}">Riesgo {esc(lvl)}</span>
    <span class="verdict-txt">{esc(vtext)}</span>
  </div>
  <div class="kpis">
    <div class="kpi"><div class="kpi-n">{total}</div><div class="kpi-l">Hallazgos</div></div>
    <div class="kpi"><div class="kpi-n">{C['closed']}</div><div class="kpi-l">Cerrados</div></div>
    <div class="kpi"><div class="kpi-n">{C['fixed']}</div><div class="kpi-l">Corregidos</div></div>
    <div class="kpi"><div class="kpi-n" style="color:#b4532f">{kev}</div><div class="kpi-l">CISA KEV</div></div>
  </div>
  <div class="chart-grid">
    <div class="chart"><div class="chart-t">Por severidad</div><div class="donut">{_svg_donut(C['by_prio'])}</div></div>
    <div class="chart"><div class="chart-t">Por categoría OWASP</div>{_svg_bars(owpairs, "#6b7d5c")}</div>
    <div class="chart"><div class="chart-t">Matriz de riesgo · severidad × explotabilidad</div>{_svg_matrix(findings)}</div>
    <div class="chart"><div class="chart-t">Progreso de remediación</div>{_svg_progress(C, total)}</div>
  </div>
</section>"""


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
            t = ln[4:]; out.append(f'<h3 id="{slugify(t)}">{inline(t)}</h3>'); i += 1; continue
        if ln.startswith("## "):
            t = ln[3:]; out.append(f'<h2 id="{slugify(t)}">{inline(t)}</h2>'); i += 1; continue
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
            html_items = "".join(f'<li style="margin-left:{max(0, min(ind-base_indent, 64))}px">{txt}</li>' for ind, txt in items)
            out.append(f"<ul>{html_items}</ul>"); continue
        out.append(f"<p>{inline(ln)}</p>"); i += 1
    return "\n".join(out)


def build_html(md_text, has_pdf, md_name, pdf_name, L=None):
    body = decorate_tokens(wrap_acronyms(md_to_html_blocks(md_text)))
    toc = build_toc(md_text)
    charts = build_charts_html(L) if L is not None else ""
    pdf_link = f'<a class="dl" href="{esc(pdf_name)}" download>PDF</a>' if has_pdf else ""
    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vuln-hunter — Informe de auditoría</title>
<style>
  :root{{--paper:#f4f1ea;--ink:#1a1915;--ink-soft:#3a3833;--ink-mute:#8a847a;--rule:#ddd8cc;--accent:#b4532f;--card:#fff}}
  *{{box-sizing:border-box}}
  html{{scroll-behavior:smooth}}
  body{{font-family:'Tinos',Georgia,'Times New Roman',serif;background:var(--paper);color:var(--ink);margin:0;line-height:1.6}}
  .toolbar{{position:sticky;top:0;z-index:20;display:flex;gap:10px;justify-content:flex-end;align-items:center;
    padding:10px 18px;background:rgba(244,241,234,.92);backdrop-filter:blur(6px);border-bottom:1px solid var(--rule)}}
  .toolbar .lbl{{margin-right:auto;font-family:ui-monospace,monospace;font-size:12px;color:var(--ink-mute);letter-spacing:1px}}
  .dl,.print{{font-family:ui-monospace,monospace;font-size:13px;font-weight:700;text-decoration:none;cursor:pointer;
    border:1px solid var(--accent);color:#fff;background:var(--accent);border-radius:8px;padding:8px 14px}}
  .dl{{background:transparent;color:var(--accent)}}
  .layout{{max-width:1140px;margin:0 auto;padding:32px 28px 80px;display:grid;grid-template-columns:212px 1fr;gap:36px;align-items:start}}
  /* TOC */
  .toc{{position:sticky;top:64px;display:flex;flex-direction:column;gap:2px;font-family:ui-monospace,monospace;font-size:12.5px;max-height:calc(100vh - 90px);overflow:auto}}
  .toc-h{{text-transform:uppercase;letter-spacing:1.5px;font-size:10.5px;color:var(--ink-mute);margin-bottom:8px}}
  .toc a{{color:var(--ink-soft);text-decoration:none;padding:3px 10px;border-radius:6px;transition:background .15s,color .15s}}
  .toc a:hover{{color:var(--accent);background:#fbf6ec}}
  .toc .toc-3{{padding-left:22px;color:var(--ink-mute);font-size:11.5px}}
  .toc .toc-x{{color:var(--accent);font-weight:700}}
  .doc{{min-width:0}}
  h1{{font-size:2.1rem;margin:.2em 0 .3em;line-height:1.15}}
  h2{{font-size:1.5rem;margin:1.6em 0 .5em;padding-bottom:.2em;border-bottom:1px solid var(--rule);scroll-margin-top:64px}}
  h3{{font-size:1.18rem;margin:1.3em 0 .4em;color:var(--ink-soft);scroll-margin-top:64px}}
  h4{{font-size:1.02rem;margin:1.1em 0 .3em;font-family:ui-monospace,monospace}}
  p,li{{font-size:1.02rem}}
  blockquote{{margin:1em 0;padding:14px 18px;background:#fbf6ec;border:1px solid #e7dcc6;border-radius:8px;color:var(--ink-soft)}}
  abbr.ac{{text-decoration:underline dotted;text-decoration-color:var(--accent);text-underline-offset:3px;cursor:help;font-variant:inherit}}
  ul{{margin:.4em 0 .8em;padding-left:1.3em}} li{{margin:.18em 0}}
  hr{{border:0;border-top:1px solid var(--rule);margin:2em 0}}
  code{{font-family:ui-monospace,SFMono-Regular,monospace;background:rgba(107,125,92,.12);padding:1px 5px;border-radius:4px;font-size:.86em}}
  table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--rule);border-radius:10px;overflow:hidden;font-size:.92rem;margin:.6em 0 1.1em}}
  th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid #eee7d8;vertical-align:top}}
  th{{background:#faf8f2;font-family:ui-monospace,monospace;font-size:11px;letter-spacing:.04em;text-transform:uppercase;color:var(--ink-mute)}}
  /* Panorama / charts */
  .panorama{{background:var(--card);border:1px solid var(--rule);border-radius:14px;padding:22px 24px;margin:0 0 22px}}
  .pan-h{{margin:0 0 14px;font-size:1.25rem;border:0;padding:0}}
  .kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
  .kpi{{text-align:center;background:#faf8f2;border:1px solid var(--rule);border-radius:10px;padding:14px 8px}}
  .kpi-n{{font-size:1.8rem;font-weight:700;line-height:1;font-family:ui-monospace,monospace}}
  .kpi-l{{font-family:ui-monospace,monospace;font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;color:var(--ink-mute);margin-top:6px}}
  .chart-grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
  .chart{{background:#faf8f2;border:1px solid var(--rule);border-radius:10px;padding:14px 16px}}
  .chart-wide{{grid-column:1/-1}}
  .chart-t{{font-family:ui-monospace,monospace;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-mute);margin-bottom:10px}}
  .donut{{display:flex;align-items:center;gap:16px;flex-wrap:wrap}}
  .dn-n{{font-family:ui-monospace,monospace;font-size:26px;font-weight:700;fill:var(--ink)}}
  .dn-l{{font-family:ui-monospace,monospace;font-size:10px;fill:var(--ink-mute)}}
  .legend{{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:10px;font-family:ui-monospace,monospace;font-size:11.5px;color:var(--ink-soft)}}
  .legend .lg{{display:inline-flex;align-items:center;gap:6px}}
  .legend .sw{{width:10px;height:10px;border-radius:3px;display:inline-block}}
  .bars{{display:flex;flex-direction:column;gap:7px}}
  .bar{{display:grid;grid-template-columns:120px 1fr 28px;align-items:center;gap:8px;font-family:ui-monospace,monospace;font-size:11.5px}}
  .bar-l{{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--ink-soft)}}
  .bar-t{{background:#eee7d8;border-radius:5px;overflow:hidden;height:14px}}
  .bar-f{{display:block;height:14px;border-radius:5px}}
  .bar-n{{text-align:right;color:var(--ink-mute)}}
  .muted{{color:var(--ink-mute);font-style:italic}}
  /* verdict callout */
  .verdict{{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;border:1px solid var(--rule);border-radius:10px;
    padding:13px 16px;margin-bottom:18px;background:#faf8f2}}
  .verdict-dot{{width:10px;height:10px;border-radius:50%;align-self:center}}
  .verdict-lvl{{font-family:ui-monospace,monospace;font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.06em}}
  .verdict-txt{{font-size:.98rem;color:var(--ink-soft)}}
  /* severity + status chips (cuerpo) */
  .sev-chip{{display:inline-block;padding:0 7px;border-radius:5px;font-family:ui-monospace,monospace;font-weight:700;font-size:.78em;color:#fff;line-height:1.5;vertical-align:baseline}}
  .st-chip{{font-family:ui-monospace,monospace;font-weight:700;font-size:.82em}}
  /* risk matrix */
  .matrix{{border:1px solid var(--rule);border-radius:8px;overflow:hidden;font-family:ui-monospace,monospace;font-size:12px;width:100%}}
  .matrix th,.matrix td{{text-align:center;padding:8px 6px;border:1px solid #eee7d8}}
  .matrix .mx-c{{font-size:10px;text-transform:uppercase;letter-spacing:.03em;color:var(--ink-mute);background:#faf8f2}}
  .matrix .mx-r{{font-weight:700;background:#faf8f2}}
  .matrix td.mx{{color:var(--ink-mute);background:#fff}}
  .matrix td.mx.on{{color:var(--ink);font-weight:700;background:#f3efe5}}
  .matrix td.mx.warn{{color:#8a5a12;font-weight:700;background:#f7ecd2}}
  .matrix td.mx.hot{{color:#fff;font-weight:700;background:#b4532f}}
  @media print{{
    .toolbar,.toc{{display:none}}
    body{{background:#fff}}
    .layout{{display:block;max-width:none;padding:0}}
    .panorama,.chart,.kpi{{background:#fff}}
    h2{{break-after:avoid}} table,blockquote,h3,h4,.panorama,.chart{{break-inside:avoid}}
    @page{{margin:16mm 14mm}}
  }}
  @media (max-width:820px){{.layout{{grid-template-columns:1fr}}.toc{{position:static;max-height:none;flex-direction:row;flex-wrap:wrap}}.chart-grid{{grid-template-columns:1fr}}.kpis{{grid-template-columns:repeat(2,1fr)}}}}
</style></head><body>
<div class="toolbar">
  <span class="lbl">vuln-hunter // informe de auditoría</span>
  {pdf_link}
  <a class="dl" href="{esc(md_name)}" download>Markdown</a>
  <button class="print" onclick="window.print()">Descargar PDF</button>
</div>
<div class="layout">
  {toc}
  <main class="doc">{charts}{body}</main>
</div>
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
    # El informe es self-contained (SVG inline, sin recursos externos), asi que NO
    # se habilita --enable-local-file-access: contenido derivado del ledger no debe
    # poder cargar archivos locales al renderizar.
    if shutil.which("wkhtmltopdf") and _run(["wkhtmltopdf", "--quiet", apath, ppath]):
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
        fh.write(build_html(md_text, False, md_name, pdf_name, L))
    tool = try_pdf(html_path, pdf_path)
    if tool:
        with open(html_path, "w") as fh:
            fh.write(build_html(md_text, True, md_name, pdf_name, L))

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
