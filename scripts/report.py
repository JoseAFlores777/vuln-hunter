#!/usr/bin/env python3
"""
vuln-hunter :: report.py
Genera el informe FORMAL de auditoria a partir de .vuln-hunter/ledger.json.

Determinista y reproducible (no depende del LLM). Produce CINCO artefactos,
listos para descargar desde el panel:

    <base>.md               informe en Markdown (texto plano, fuente de verdad)
    <base>.html              dashboard TECNICO interactivo (tema oscuro, JS de
                             filtrado/orden, cards colapsables) — para navegar en pantalla
    <base>.pdf                documento FORMAL tecnico (portada, indice con paginas
                             reales, encabezado/pie, paleta clara) — para leer/archivar/
                             compartir; NO es un print-to-pdf del .html (ver
                             build_formal_document_html())
    <base>-executive.html/.pdf  version EJECUTIVA de ambos (condensada: veredicto,
                             KPIs, solo casos top con detalle, plan de accion)

El .pdf solo se genera si hay un convertidor disponible: se PREFIERE weasyprint
(motor de paginado real: soporta target-counter()/@page margin boxes, que el
documento formal usa para el indice y el encabezado/pie — confirmado que Chrome
headless NO los soporta), cae a wkhtmltopdf y por ultimo a Chrome|Chromium|Edge
headless (funciona, pero el indice queda sin numeros de pagina). Si no hay
ningun convertidor, se omite el .pdf y el boton "Descargar PDF" del dashboard
queda como alternativa manual (esa SI es un print-to-pdf, del dashboard oscuro).

Estructura del informe (comun a .md y a ambos .html):
    1. Auditoria y diagnostico  (superficie, hallazgos, diagnostico por hallazgo)
    2. Estrategia y plan de remediacion  (plan, enfoque por hallazgo, action plan)
    3. Resultados  (fixes aplicados, verificacion, "que esta seguro", estado)

Identidad visual: el mismo lenguaje HUD/dark del panel vivo (panel/index.html),
no un tema "paper" generico. Ver HUD (mas abajo) para los tokens de color, y el
comentario junto a --mono/--hud/--sans para la unica desviacion deliberada
(fuentes locales, el panel usa Google Fonts pero el informe debe seguir siendo
100% self-contained/offline).

Uso:
    python3 scripts/report.py [ruta_ledger] [base_o_salida]

`base_o_salida` puede ser una base sin extension (.vuln-hunter/audit-report) o una
ruta .html/.md (por retrocompat); en ambos casos se generan los cinco formatos.
"""
import html
import json
import os
import re as _re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger as _ledger  # noqa: E402 — retrocompat: canonicaliza ids de repos ya auditados (ver main())

PRIO_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "FILTERED": 9, "—": 5}

# Los agentes a veces ya numeran sus pasos ("1) ...", "2) ...") dentro del texto
# libre de conceptual_chain/flow; strip antes de renderizar para no duplicar la
# numeracion que aplican los renderers de kill-chain (dashboard e informe formal).
_LEADING_NUM_RE = _re.compile(r"^\s*\(?\d{1,2}[\.\)]\s*")

# Tokens de color HUD: copiados LITERALMENTE de panel/index.html (:root, linea
# ~19-31) — es la identidad visual ya en produccion del panel, no una paleta
# nueva. El informe NO inventa colores fuera de este set (regla dura del brief).
HUD = {
    "bg": "#070a0f", "bg2": "#0a0e16", "panel": "#0e1420", "panel2": "#111a28",
    "ink": "#e6edf6", "ink_soft": "#aebacb", "ink_mute": "#6b7889",
    "line": "rgba(120,160,200,.12)", "line2": "rgba(120,160,200,.22)",
    "green": "#22c55e", "green_soft": "#4ade80", "cyan": "#22d3ee", "cyan_soft": "#67e8f9",
    "amber": "#f59e0b", "orange": "#fb923c", "red": "#ef4444", "violet": "#a78bfa",
}

PRIO_COLOR = {"P0": HUD["red"], "P1": HUD["orange"], "P2": HUD["amber"],
              "P3": HUD["ink_mute"], "FILTERED": HUD["ink_mute"], "—": HUD["ink_mute"]}
STATUS_LABEL = {
    "hypothesis": "Hipotesis", "confirmed": "Confirmada", "triaged": "Triada",
    "planned": "Planificada", "fixing": "En proceso",
    "candidate-resolved": "Candidato a resuelto", "fixed": "Corregida",
    "closed": "Cerrada", "filtered": "Filtrada",
}

GLOSSARY = [
    ("Hallazgo", "Una vulnerabilidad candidata con un id creciente (p.ej. VULN-001). Acumula el análisis de cada etapa."),
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
    """Prioridad para mostrar y para agrupar en graficos. Normaliza valores NO
    canonicos (fuera de P0-P3/FILTERED) en vez de dejarlos pasar tal cual: un
    triage-judge real puede escribir "N/A" (u otro string) para lo filtrado en
    vez del literal "FILTERED" del schema — visto en una auditoria real, donde
    esto hacia desaparecer 13/17 hallazgos EN SILENCIO de la dona/matriz/barras
    OWASP (cada una itera sobre una lista fija de prioridades reconocidas: un
    valor no reconocido simplemente no aparecia en ningun lado, sin aviso).
    is_filtered() ya sabe reconocer un filtrado real por status+rationale, asi
    que lo reusamos en vez de negociar el string exacto de priority."""
    tri = f.get("triage") or {}
    p = tri.get("priority")
    if p in ("P0", "P1", "P2", "P3", "FILTERED"):
        return p
    return "FILTERED" if is_filtered(f) else "—"


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


def cvss_of(tri):
    """El schema declara el campo `cvss`, pero en produccion triage-judge a
    veces escribe `cvss_score` en su lugar (visto en una auditoria real: TODOS
    los hallazgos de esa corrida tenian cvss_score con dato real y cvss=None,
    asi que el CVSS real nunca se mostraba ni entraba al grafico CVSS×EPSS).
    Acepta ambos nombres sin mutar `tri`; prefiere el nombre del schema si por
    algun motivo ambos estan presentes."""
    v = tri.get("cvss")
    return v if v is not None else tri.get("cvss_score")


_VEREDICTO_MAP = {"confirmado": "EXPLOITABLE", "parcial": "CONDITIONAL",
                   "refutado": "NOT_EXPLOITABLE", "no explotable": "NOT_EXPLOITABLE"}


def normalize_exploitability(expl):
    """El schema de exploitability (lo escribe redteam-whitehat) declara claves
    en ingles: verdict/reachable/controllable/conditions/conceptual_chain/
    confidence_adjusted. En produccion se vio un redteam-whitehat escribiendo el
    equivalente en ESPAÑOL (veredicto/alcanzable/condiciones/cadena/
    confianza_ajustada) para TODOS los hallazgos de una auditoria real — sin
    este fallback, hallazgos que el red-team CONFIRMO como explotables se
    mostraban como "sin confirmar" en el informe: subestima el riesgo, la
    direccion de error mas costosa posible en un informe de seguridad (peor que
    sobre-reportar). No muta el dict original.

    `alcanzable`/`controllable` en español es texto libre no siempre
    boolean-izable ("amplificador (no explotable en aislado)") — NO se fuerza a
    boolean aqui; el renderer decide si mostrar el checkmark ingles o el texto
    crudo segun que campos esten presentes (ver build_finding_cards_section_html)."""
    if not expl:
        return expl
    out = dict(expl)
    if out.get("verdict") is None and out.get("veredicto") is not None:
        v_raw = str(out["veredicto"]).strip().lower()
        out["verdict"] = _VEREDICTO_MAP.get(v_raw, out["veredicto"])
    if out.get("conditions") is None and out.get("condiciones") is not None:
        out["conditions"] = out["condiciones"]
    if out.get("conceptual_chain") is None and out.get("cadena") is not None:
        out["conceptual_chain"] = _flow_steps(out["cadena"])
    if out.get("confidence_adjusted") is None and out.get("confianza_ajustada") is not None:
        out["confidence_adjusted"] = out["confianza_ajustada"]
    return out


def fix_applied_real(f):
    """Fix aplicado de verdad: applied==true y NO un auto-'fixed' de rescan
    (desaparecer del escaner no es evidencia de correccion — CLAUDE.md regla 9)."""
    fix = f.get("fix") or {}
    return bool(fix.get("applied")) and fix.get("source") != "rescan"


def sorted_findings(findings):
    # Blindado contra entradas no-dict (poison): compute() ya se defendia de esto,
    # ahora build_html()/build_md() tampoco truenan si el ledger viene corrupto.
    return sorted((f for f in findings if isinstance(f, dict)),
                  key=lambda x: PRIO_ORDER.get(prio_of(x), 5))


def compute(L):
    findings = L.get("findings", [])
    by_prio, kev, ransom = {}, 0, 0
    fixed = verified = closed = closed_unverified = filtered = 0
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
        if is_filtered(f):
            filtered += 1
    return {"by_prio": by_prio, "kev": kev, "ransom": ransom,
            "fixed": fixed, "verified": verified, "closed": closed,
            "closed_unverified": closed_unverified, "filtered": filtered}


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
    # Colores cambiados de hex "paper" a tokens HUD (paleta dark del panel). Ningun
    # test fija estos valores, solo el string de nivel (ver TestRiskVerdict).
    if not findings:
        return ("sin hallazgos", "Sin hallazgos en el ledger. Corre la auditoría para poblarlo.", HUD["green"])
    if not open_f:
        return ("controlado", f"Todos los hallazgos cerrados o filtrados ({C['closed']}/{len(findings)}). Riesgo bajo control.", HUD["green"])
    # vtext NUNCA repite "Riesgo {lvl}:" — los 4 consumidores (dashboard,
    # ejecutivo, portada impresa, parrafo del formal) ya anteponen ese badge
    # por su cuenta; con el prefijo aqui salia "Riesgo medio — Riesgo medio: ...".
    if open_p0 or open_kev:
        return ("alto", " · ".join(bits) + ".", HUD["red"])
    if open_p1:
        return ("medio", " · ".join(bits) + ".", HUD["orange"])
    return ("moderado", f"{len(open_f)} hallazgo(s) abiertos de prioridad media/baja.", HUD["amber"])


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
        o.append("| ID | Prio | CVSS | Título | Ubicación | OWASP / CWE | Explotable | EPSS | Estado |")
        o.append("|---|---|---|---|---|---|---|---|---|")
        for f in sorted_findings(findings):
            intel = f.get("intel") or {}
            expl = normalize_exploitability(f.get("exploitability") or {})
            tri = f.get("triage") or {}
            ver = f.get("verification") or {}
            badges = ("KEV " if intel.get("in_cisa_kev") else "") + ("RANSOMWARE" if intel.get("known_ransomware_use") else "")
            owc = f"{f.get('owasp_2025') or f.get('owasp_2021') or '—'} / {f.get('cwe') or '—'}"
            est = f"{STATUS_LABEL.get(f.get('status'), f.get('status','—'))} / {ver.get('verdict','—')}"
            epss = intel.get("epss") if intel.get("epss") is not None else "—"
            cvss_v = cvss_of(tri)
            cvss = f"{cvss_v} v{tri.get('cvss_version')}" if cvss_v is not None else "—"
            o.append(f"| `{mdc(f.get('id'))}` | {mdc(prio_of(f))} | {mdc(cvss)} | {mdc((f.get('title') or '—') + (' ['+badges.strip()+']' if badges.strip() else ''))} "
                     f"| `{mdc(f.get('location'))}` | {mdc(owc)} | {mdc(expl.get('verdict','—'))} | {mdc(epss)} | {mdc(est)} |")
        o.append("")
    else:
        o.append("_Sin hallazgos en el ledger._\n")

    # 1.3 se mantiene en formato de bullets (correcto para el .md, un artefacto de
    # texto plano). build_html() NO reparsea esto: separa (splice) esta seccion del
    # markdown y la re-renderiza como cards HUD — ver build_finding_cards_section_html().
    o.append("### 1.3 Diagnóstico por hallazgo\n")
    if not findings:
        o.append("_Sin hallazgos._\n")
    for f in sorted_findings(findings):
        sast = f.get("sast") or {}
        intel = f.get("intel") or {}
        expl = normalize_exploitability(f.get("exploitability") or {})
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
                o.append(f"  - Data-flow: {mdc(sast.get('flow'))}")
            if sast.get("sarif_ref"):
                o.append(f"  - Origen SARIF: `{mdc(sast.get('sarif_ref'))}` (trazabilidad exacta a la corrida del escáner)")
        if intel:
            o.append(f"- **Dependencia:** {mdc(intel.get('package','—'))}@{mdc(intel.get('installed_version','—'))} "
                     f"({mdc(intel.get('ecosystem','—'))}, prod={mdc(intel.get('is_production_dep'))})")
            if intel.get("cve_ids") or intel.get("ghsa_ids"):
                o.append(f"  - CVE/GHSA: {mdc(joinlist(intel.get('cve_ids')) + ('  ' + joinlist(intel.get('ghsa_ids')) if intel.get('ghsa_ids') else ''))}")
            o.append(f"  - EPSS: {mdc(intel.get('epss','—'))} · fix: {mdc(intel.get('fixed_version','—'))}")
            if intel.get("sources_consulted"):
                o.append(f"  - Fuentes consultadas: {mdc(joinlist(intel.get('sources_consulted')))}")
        if expl:
            reach_txt = (f"reachable={mdc(expl.get('reachable'))}, controllable={mdc(expl.get('controllable'))}"
                         if expl.get("reachable") is not None or expl.get("controllable") is not None
                         else mdc(expl.get("alcanzable", "—")))
            o.append(f"- **Explotabilidad:** {mdc(expl.get('verdict','—'))} ({reach_txt})")
            if expl.get("conditions"):
                o.append(f"  - Condiciones para explotar: {mdc(expl.get('conditions'))}")
            if expl.get("conceptual_chain"):
                o.append(f"  - Cadena conceptual: {mdc(joinlist(expl.get('conceptual_chain'), ' → '))}")
            if expl.get("confidence_adjusted") is not None:
                o.append(f"  - Confianza ajustada por red-team: {mdc(expl.get('confidence_adjusted'))} (vs. confianza SAST original {mdc(sast.get('confidence','—'))})")
        if tri:
            o.append(f"- **Triage:** CVSS {mdc(tri.get('cvss','—'))} ({mdc(tri.get('cvss_version','—'))}) · prioridad {mdc(tri.get('priority','—'))}")
            if tri.get("rationale"):
                o.append(f"  - {mdc(tri.get('rationale'))}")
            if tri.get("dedup_of"):
                o.append(f"  - Duplicado de: `{mdc(tri.get('dedup_of'))}` (no se cuenta dos veces en los totales)")
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
    for term, desc in GLOSSARY:
        o.append(f"- **{term}:** {desc}")
    o.append("")

    o.append(f"---\n\n_Generado de forma determinista desde `{esc(ledger_path)}` el {now}. "
             "vuln-hunter es un primer pase disciplinado; no reemplaza auditoría humana._\n")
    return "\n".join(o)


# ----------------------------- html: toc + charts ---------------------------

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


# Mapea los estados textuales (STATUS_LABEL) sobre los 4 BUCKETS de ciclo de vida
# que ya usa panel/index.html (.lbadge encontrados/mitigando/arreglados/filtrados)
# en vez de inventar tonos nuevos.
STATUS_COLOR = {
    "Hipotesis": HUD["amber"], "Confirmada": HUD["amber"], "Triada": HUD["amber"], "Planificada": HUD["amber"],
    "En proceso": HUD["cyan"],
    "Corregida": HUD["green_soft"],
    "Cerrada": HUD["green"],
    "Filtrada": HUD["ink_mute"],
}
_SEV_RE = _re.compile(r"\b(P0|P1|P2|P3|FILTERED)\b")
_ST_RE = _re.compile(r"\b(En proceso|Cerrada|Corregida|Triada|Planificada|Confirmada|Hipotesis|Filtrada)\b")

BUCKET_LABEL = {"encontrados": "Encontrado", "mitigando": "Mitigando", "arreglados": "Arreglado", "filtrados": "Filtrado"}


def bucket_of(f):
    """Bucket de 4 estados (igual vocabulario que panel/app.jsx lifecycleOf), pero
    honesto: 'closed' solo cae en 'arreglados' si is_truly_closed() (evidencia
    real), no por el mero status."""
    if is_filtered(f):
        return "filtrados"
    if is_truly_closed(f):
        return "arreglados"
    if f.get("status") in ("fixed", "fixing", "candidate-resolved", "closed"):
        return "mitigando"
    return "encontrados"


def stage_of(f):
    """Etapa (de 5) para el stepper por-card. Ver build_lifecycle_stepper_html:
    NUNCA infiere fecha, solo el status actual."""
    if is_truly_closed(f):
        return "cerrado"
    st = f.get("status")
    if st in ("fixed", "candidate-resolved", "closed"):
        return "corregido"
    if st == "fixing":
        return "mitigando"
    if st in ("triaged", "planned"):
        return "triado"
    return "encontrado"


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
        seg = _SEV_RE.sub(lambda m: f'<span class="sev-chip" style="background:{PRIO_COLOR.get(m.group(1), HUD["ink_mute"])}">{m.group(1)}</span>', seg)
        seg = _ST_RE.sub(lambda m: f'<span class="st-chip" style="color:{STATUS_COLOR.get(m.group(1), HUD["ink_mute"])}">{m.group(1)}</span>', seg)
        out.append(seg)
    return "".join(out)


def _svg_matrix(findings):
    """Matriz de riesgo: severidad (filas) x explotabilidad (columnas) con conteos."""
    rows = ["P0", "P1", "P2", "P3"]
    cols = [("EXPLOITABLE", "Explotable"), ("CONDITIONAL", "Condicional"), ("—", "Sin confirmar")]
    grid = {(r, c): 0 for r in rows for c, _ in cols}
    for f in findings:
        if not isinstance(f, dict):
            continue
        p = prio_of(f)
        if p not in rows:
            continue
        v = normalize_exploitability(f.get("exploitability") or {}).get("verdict") or "—"
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


def _prose(text):
    """Texto libre (hipotesis/rationale/condiciones/evidencia): escapa y envuelve
    siglas conocidas — es el unico tratamiento que aplicamos dentro de las cards
    (nunca decorate_tokens ahi, para no re-envolver severidades ya renderizadas
    como pills nativas)."""
    if not text:
        return ""
    return wrap_acronyms(esc(text))


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
    """Dona de distribucion por severidad (SVG inline, sin libs). Segmentos y
    leyenda disparan el filtro compartido (interactivity_spec): clic en 'P0'
    filtra tabla 1.2 y cards 1.3 a la vez."""
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
        clickable = ' class="scatter-pt"' if p in PRIO_ORDER and p not in ("FILTERED", "—") else ""
        onclick = f" onclick=\"vhFilterFromChart('sev','{esc(p)}')\"" if clickable else ""
        segs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{PRIO_COLOR.get(p, HUD["ink_mute"])}" '
            f'stroke-width="{stroke}" stroke-dasharray="{seg_len:.2f} {circ-seg_len:.2f}" '
            f'stroke-dashoffset="{-off:.2f}" transform="rotate(-90 {cx} {cy})"{clickable}{onclick}><title>{esc(p)}: {n}</title></circle>'
        )
        off += seg_len
    legend = "".join(
        f'<span class="lg" onclick="vhFilterFromChart(\'sev\',\'{esc(p)}\')"><span class="sw" style="background:{PRIO_COLOR.get(p, HUD["ink_mute"])}"></span>{esc(p)} · {n}</span>'
        for p, n in data
    ) or '<span class="lg">sin hallazgos</span>'
    return (
        f'<svg viewBox="0 0 160 160" width="160" height="160" role="img" aria-label="Hallazgos por severidad">'
        f'{"".join(segs)}'
        f'<text x="{cx}" y="{cy-4}" text-anchor="middle" class="dn-n">{total}</text>'
        f'<text x="{cx}" y="{cy+14}" text-anchor="middle" class="dn-l">hallazgos</text></svg>'
        f'<div class="legend">{legend}</div>'
    )


def _svg_bars_owasp(findings, top_n=8):
    """Barras horizontales por categoria OWASP, APILADAS por severidad — no solo
    'cuantos hay' sino 'cuantos de esos son P0/P1 urgentes vs backlog', que es lo
    que de verdad hace falta para priorizar de un vistazo. Cada fila filtra por
    texto (reusa la busqueda compartida, ver interactivity_spec)."""
    owc = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        k = f.get("owasp_2025") or f.get("owasp_2021") or "—"
        bucket = owc.setdefault(k, {"total": 0, "by_prio": {}})
        bucket["total"] += 1
        p = prio_of(f)
        bucket["by_prio"][p] = bucket["by_prio"].get(p, 0) + 1
    if not owc:
        return '<p class="muted">— sin datos —</p>'
    items = sorted(owc.items(), key=lambda kv: -kv[1]["total"])[:top_n]
    mx = max(v["total"] for _, v in items) or 1
    # "—" incluido a proposito (no solo P0-P3/FILTERED): prio_of() ya normaliza
    # cualquier valor no-canonico a FILTERED o "—" (nunca deja pasar un string
    # crudo), pero esta lista debe reconocer TODO lo que prio_of() puede
    # devolver o el segmento vuelve a desaparecer en silencio.
    order = ["P0", "P1", "P2", "P3", "FILTERED", "—"]
    bw = 220
    rows = []
    seen_prios = set()
    for name, data in items:
        segs = []
        for p in order:
            n = data["by_prio"].get(p, 0)
            if not n:
                continue
            seen_prios.add(p)
            w = max(2, bw * n / mx)
            segs.append(f'<span class="bar-seg" style="width:{w:.1f}px;background:{esc(PRIO_COLOR.get(p, HUD["ink_mute"]))}" title="{esc(p)}: {n}"></span>')
        rows.append(
            f'<div class="bar" onclick="vhFilterFromChart(\'q\',\'{esc(name)}\')" title="Filtrar por {esc(name)}">'
            f'<span class="bar-l" title="{esc(name)}">{esc(name)}</span>'
            f'<span class="bar-t">{"".join(segs)}</span>'
            f'<span class="bar-n">{data["total"]}</span></div>'
        )
    legend = "".join(
        f'<span class="lg"><span class="sw" style="background:{esc(PRIO_COLOR.get(p, HUD["ink_mute"]))}"></span>{esc(p)}</span>'
        for p in order if p in seen_prios
    )
    return '<div class="bars">' + "".join(rows) + '</div><div class="legend">' + legend + '</div>'


def _svg_progress(C, total):
    """Barra de progreso de remediacion: cerrados / corregidos / pendientes."""
    total = total or 1
    closed = C["closed"]
    fixed_only = max(C["fixed"] - closed, 0)
    pend = max(total - closed - fixed_only, 0)
    seg = []
    x = 0.0
    W = 280.0
    for n, col, lbl in [(closed, HUD["green"], "cerrados"), (fixed_only, HUD["amber"], "corregidos"), (pend, HUD["red"], "pendientes")]:
        if n <= 0:
            continue
        w = W * n / total
        seg.append(f'<rect x="{x:.1f}" y="0" width="{w:.1f}" height="20" fill="{col}"><title>{lbl}: {n}</title></rect>')
        x += w
    legend = (
        f'<span class="lg"><span class="sw" style="background:{HUD["green"]}"></span>Cerrados {closed}</span>'
        f'<span class="lg"><span class="sw" style="background:{HUD["amber"]}"></span>Corregidos {fixed_only}</span>'
        f'<span class="lg"><span class="sw" style="background:{HUD["red"]}"></span>Pendientes {pend}</span>'
    )
    return (f'<svg viewBox="0 0 280 20" width="100%" height="20" preserveAspectRatio="none" '
            f'role="img" aria-label="Progreso de remediación">{"".join(seg)}</svg>'
            f'<div class="legend">{legend}</div>')


def _svg_scatter(findings):
    """CVSS (x, 0-10) x EPSS (y, 0-1) por hallazgo abierto — unico grafico nuevo,
    visualiza en un vistazo la relacion que hoy solo se lee en la tabla. Clic en un
    punto salta a la card del hallazgo (hashchange handler en _interactivity_js)."""
    W, Hh, pad = 260, 160, 22
    pts = []
    for f in findings:
        if not isinstance(f, dict) or not is_open(f):
            continue
        tri = f.get("triage") or {}
        intel = f.get("intel") or {}
        cvss, epss = cvss_of(tri), intel.get("epss")
        if cvss is None or epss is None:
            continue
        try:
            cvss_f, epss_f = float(cvss), float(epss)
        except (TypeError, ValueError):
            continue
        x = pad + (W - 2 * pad) * max(0.0, min(10.0, cvss_f)) / 10.0
        y = (Hh - pad) - (Hh - 2 * pad) * max(0.0, min(1.0, epss_f))
        color = PRIO_COLOR.get(prio_of(f), HUD["ink_mute"])
        fid = f.get("id", "")
        pts.append(
            f'<circle class="scatter-pt" cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{color}" fill-opacity=".85" '
            f'stroke="{color}" stroke-width="1" onclick="location.hash=\'{esc(fid)}\'">'
            f'<title>{esc(fid)} — {esc(f.get("title",""))} (CVSS {cvss_f:g}, EPSS {epss_f:g})</title></circle>'
        )
    if not pts:
        return '<p class="muted">— sin hallazgos abiertos con CVSS y EPSS —</p>'
    axes = (
        f'<line x1="{pad}" y1="{Hh-pad}" x2="{W-pad}" y2="{Hh-pad}" stroke="{HUD["line2"]}" stroke-width="1"/>'
        f'<line x1="{pad}" y1="{pad}" x2="{pad}" y2="{Hh-pad}" stroke="{HUD["line2"]}" stroke-width="1"/>'
    )
    return (
        f'<svg viewBox="0 0 {W} {Hh}" width="100%" height="{Hh}" role="img" aria-label="CVSS versus EPSS">'
        f'{axes}{"".join(pts)}</svg>'
        '<div class="legend"><span class="lg">eje X: CVSS (0–10)</span><span class="lg">eje Y: EPSS (0–1)</span></div>'
    )


def build_charts_html(L, mode="technical", include_header=True):
    findings = L.get("findings", [])
    C = compute(L)
    total = len(findings)
    # denominador de "Progreso de remediacion": excluye lo FILTRADO (no es un
    # hallazgo real pendiente de remediar). Antes se pasaba `total` crudo, asi
    # que un ledger real con muchos filtrados/duplicados mostraba "Pendientes"
    # inflado (17 en vez de los 4 hallazgos reales) — contradecia a la propia
    # dona, que ya excluye lo filtrado.
    real_total = max(total - C["filtered"], 0)
    kev = C["kev"]
    lvl, vtext, vcolor = risk_verdict(L)
    verdict_html = (
        f'<div class="verdict" style="border-color:{esc(vcolor)}">'
        f'<span class="verdict-dot" style="background:{esc(vcolor)}"></span>'
        f'<span class="verdict-lvl" style="color:{esc(vcolor)}">Riesgo {esc(lvl)}</span>'
        f'<span class="verdict-txt">{esc(vtext)}</span></div>'
    )
    kpis_html = (
        '<div class="kpis">'
        f'<div class="kpi"><div class="kpi-n">{total}</div><div class="kpi-l">Hallazgos</div></div>'
        f'<div class="kpi"><div class="kpi-n" style="color:{HUD["green"]}">{C["closed"]}</div><div class="kpi-l">Cerrados</div></div>'
        f'<div class="kpi"><div class="kpi-n" style="color:{HUD["green_soft"]}">{C["fixed"]}</div><div class="kpi-l">Corregidos</div></div>'
        f'<div class="kpi"><div class="kpi-n" style="color:{HUD["red"]}">{kev}</div><div class="kpi-l">CISA KEV</div></div>'
        '</div>'
    )
    if mode == "executive":
        chart_grid = (
            '<div class="chart-grid">'
            f'<div class="chart"><div class="chart-t">Por severidad</div><div class="donut">{_svg_donut(C["by_prio"])}</div></div>'
            f'<div class="chart"><div class="chart-t">Progreso de remediación</div>{_svg_progress(C, real_total)}</div>'
            '</div>'
        )
    else:
        chart_grid = (
            '<div class="chart-grid">'
            f'<div class="chart"><div class="chart-t">Por severidad</div><div class="donut">{_svg_donut(C["by_prio"])}</div></div>'
            f'<div class="chart"><div class="chart-t">Por categoría OWASP · apilado por severidad</div>{_svg_bars_owasp(findings)}</div>'
            f'<div class="chart"><div class="chart-t">Matriz de riesgo · severidad × explotabilidad</div>{_svg_matrix(findings)}</div>'
            f'<div class="chart"><div class="chart-t">Progreso de remediación</div>{_svg_progress(C, real_total)}</div>'
            f'<div class="chart chart-wide"><div class="chart-t">CVSS × EPSS · hallazgos abiertos</div>{_svg_scatter(findings)}</div>'
            '</div>'
        )
    if not include_header:
        # El caller ya renderizó su propio hero (verdict + KPIs) — p.ej. el
        # ejecutivo, que usa un hero condensado propio en vez de repetir este.
        # Evita duplicar el mismo veredicto/KPIs dos veces en la misma página.
        return f'<section class="panorama panorama-charts">{chart_grid}</section>'
    return (
        '<section id="panorama" class="panorama"><h2 class="pan-h">Panorama de la auditoría</h2>'
        f'{verdict_html}{kpis_html}{chart_grid}</section>'
    )


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
        s = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
        s = _re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
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


def build_attack_surface_html(L):
    """1.1 como fila de facets en vez de 3 bullets — restyle liviano, mismo dato."""
    asf = L.get("attack_surface") or {}
    if not asf:
        return '<p class="muted">(sin superficie de ataque registrada por recon)</p>'

    def _facet(label, key):
        v = asf.get(key)
        if isinstance(v, (list, tuple)) and len(v) > 1:
            # Lista real (no un parrafo corrido separado por comas): con rutas
            # largas de un proyecto grande, unir todo con ", " en un solo <div>
            # se vuelve un parrafo illegible de una sola linea gigante.
            items = "".join(f"<li>{esc(i)}</li>" for i in v if i not in (None, ""))
            fval = f'<ul class="asf-list">{items}</ul>'
        else:
            fval = esc(joinlist(v) or "—")
        return f'<div class="facet"><div class="flabel">{esc(label)}</div><div class="fval">{fval}</div></div>'

    return ('<div class="facets">'
            + _facet("Entrypoints", "entrypoints")
            + _facet("Trust boundaries", "trust_boundaries")
            + _facet("Zonas de alto riesgo", "high_risk_zones")
            + '</div>')


def _search_blob(f):
    intel = f.get("intel") or {}
    owc = f.get("owasp_2025") or f.get("owasp_2021") or ""
    return f"{f.get('id','')} {f.get('title','')} {f.get('location','')} {intel.get('package','')} {owc}".lower()


EXPL_SHORT = {
    "EXPLOITABLE": ("EXPL", HUD["red"]),
    "CONDITIONAL": ("COND", HUD["amber"]),
    "NOT_EXPLOITABLE": ("NO", HUD["green_soft"]),
}


def _owasp_short(code):
    """'A03:2025-Injection' -> 'A03:2025': la tabla 1.2 es un indice de escaneo
    rapido, no el detalle (eso vive en la card 1.3) — el nombre largo de la
    categoria solo empujaba el ancho de columna sin agregar informacion nueva
    (ya esta implicito en el codigo A0N)."""
    if not code or code == "—":
        return "—"
    return code.split("-", 1)[0]


def build_findings_table_html(L):
    """1.2: tabla real con atributos data-* (sev/status/kev/search) para el filtro
    compartido, IDs de fila para el click-to-scroll, y <th> click-to-sort.
    Columnas deliberadamente compactas (codigos/badges cortos, no prosa): es un
    indice de escaneo rapido de TODOS los hallazgos, el detalle completo de cada
    uno vive en su card de 1.3 (nada se pierde, solo se prioriza aqui la vista
    general)."""
    findings = L.get("findings", [])
    if not findings:
        return '<p class="muted">Sin hallazgos en el ledger.</p>'
    heads = ["ID", "Prio", "CVSS", "Título", "Ubicación", "OWASP / CWE", "Explot.", "EPSS", "Estado"]
    # table-layout:fixed reparte el ancho segun estas columnas (ver _report_css);
    # sin esto, 9 columnas a ancho igual dejan Titulo/Ubicacion tan angostas que
    # el texto se envuelve palabra por palabra (una por linea) — inutilizable.
    widths = [10, 7, 7, 24, 16, 13, 7, 6, 10]
    cols = "".join(f'<col style="width:{w}%">' for w in widths)
    ths = "".join(f'<th data-sortcol="{i}">{esc(h)}</th>' for i, h in enumerate(heads))
    rows = []
    for f in sorted_findings(findings):
        intel = f.get("intel") or {}
        expl = normalize_exploitability(f.get("exploitability") or {})
        tri = f.get("triage") or {}
        ver = f.get("verification") or {}
        prio = prio_of(f)
        bucket = bucket_of(f)
        kev = bool(intel.get("in_cisa_kev"))
        badges = ("KEV " if kev else "") + ("RANSOMWARE" if intel.get("known_ransomware_use") else "")
        owc = f"{_owasp_short(f.get('owasp_2025') or f.get('owasp_2021'))} / {f.get('cwe') or '—'}"
        expl_verdict = expl.get("verdict")
        expl_short, expl_color = EXPL_SHORT.get(expl_verdict, (expl_verdict or "—", HUD["ink_mute"]))
        expl_html = f'<span class="sev" style="color:{esc(expl_color)}" title="{esc(expl_verdict or "—")}">{esc(expl_short)}</span>'
        est = STATUS_LABEL.get(f.get("status"), f.get("status", "—"))
        epss = intel.get("epss")
        cvss = cvss_of(tri)
        location = f.get("location") or "—"
        title_html = (f'<span class="tclamp" title="{esc(f.get("title") or "—")}">{esc(f.get("title") or "—")}</span>'
                      + (f' <span class="pill">{esc(badges.strip())}</span>' if badges.strip() else ""))
        rows.append(
            f'<tr class="frow" data-finding-id="{esc(f.get("id","?"))}" data-sev="{esc(prio)}" '
            f'data-status="{esc(bucket)}" data-kev="{1 if kev else 0}" data-search="{esc(_search_blob(f))}">'
            f'<td data-sort="{esc(f.get("id",""))}"><code>{esc(f.get("id","?"))}</code></td>'
            f'<td data-sort="{PRIO_ORDER.get(prio,5)}"><span class="sev" style="color:{esc(PRIO_COLOR.get(prio, HUD["ink_mute"]))}">{esc(prio)}</span></td>'
            f'<td data-sort="{cvss if cvss is not None else -1}">{esc(cvss) if cvss is not None else "—"}</td>'
            f'<td>{title_html}</td>'
            f'<td><code class="tclamp">{esc(location)}</code></td>'
            f'<td>{esc(owc)}</td>'
            f'<td data-sort="{esc(expl_verdict or "")}">{expl_html}</td>'
            f'<td data-sort="{epss if epss is not None else -1}">{esc(epss) if epss is not None else "—"}</td>'
            f'<td>{esc(est)}</td>'
            '</tr>'
        )
    return f'<div class="tablecard"><table id="findings-table"><colgroup>{cols}</colgroup><thead><tr>{ths}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def _flow_steps(flow):
    """sast.flow es un STRING 'SRC ... -> SINK ...' (ver ledger.schema.json);
    lo partimos en pasos para el killchain en vez de una linea corrida."""
    if not flow:
        return []
    if isinstance(flow, (list, tuple)):
        return [str(x).strip() for x in flow if x]
    return [p.strip() for p in _re.split(r"->|→", str(flow)) if p.strip()]


def _as_list(v):
    if not v:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if x not in (None, "")]
    return [str(v)]


def _killchain_html(items):
    items = [i for i in items if i]
    if not items:
        return ""
    cleaned = [_LEADING_NUM_RE.sub("", i, count=1) if isinstance(i, str) else i for i in items]
    lis = "".join(f'<li><span class="kn">{i+1}</span><span class="kt">{_prose(item)}</span></li>' for i, item in enumerate(cleaned))
    return f'<ol class="killchain">{lis}</ol>'


def build_lifecycle_stepper_html(f):
    """Stepper de 5 etapas. Refleja SOLO f['status'] via una tabla ordinal
    ESTATICA: el schema no registra timestamps por etapa (solo run.started_at),
    asi que esto NUNCA infiere ni muestra una fecha — no lo 'mejores' agregando
    una sin evidencia real, seria fabricar datos (CLAUDE.md regla 9)."""
    if is_filtered(f):
        return '<div class="ltrack filtered">Filtrado (no priorizado)</div>'
    steps = [("encontrado", "Encontrado"), ("triado", "Triado"), ("mitigando", "Mitigando"),
             ("corregido", "Corregido"), ("cerrado", "Cerrado")]
    cur = stage_of(f)
    idx = next((i for i, (k, _) in enumerate(steps) if k == cur), 0)
    parts = []
    for i, (k, label) in enumerate(steps):
        if i < idx:
            state = "past"
        elif i == idx:
            state = "done" if cur == "cerrado" else "cur"
        else:
            state = "future"
        if i > 0:
            parts.append(f'<span class="lbar{" on" if i <= idx else ""}"></span>')
        parts.append(f'<span class="lstep {state}"><span class="ld"></span>{esc(label)}</span>')
    return '<div class="ltrack">' + "".join(parts) + '</div>'


def build_finding_card_html(f, mode, tech_html_name=None):
    """Una card por hallazgo, espejo del `.detail` del panel (dhead/facets/
    killchain/ltrack), sin border-left como acento en ningun lado (regla del
    proyecto: test_no_sidestripe_border_left_accent)."""
    sast = f.get("sast") or {}
    intel = f.get("intel") or {}
    expl = normalize_exploitability(f.get("exploitability") or {})
    tri = f.get("triage") or {}
    ver = f.get("verification") or {}
    fid = f.get("id", "?")
    title = f.get("title") or "(sin título)"
    prio = prio_of(f)
    bucket = bucket_of(f)
    kev = bool(intel.get("in_cisa_kev"))
    ransom = bool(intel.get("known_ransomware_use"))
    location = f.get("location") or "—"
    owc = f.get("owasp_2025") or f.get("owasp_2021") or "—"
    cwe = f.get("cwe") or "—"
    open_attr = " open" if (prio in ("P0", "P1") or kev) else ""
    search = esc(_search_blob(f))

    # linea de preview: la respuesta a "por que me importa" ANTES de expandir.
    # nunca inventada, siempre uno de estos tres campos en orden de preferencia.
    preview = sast.get("hypothesis") or tri.get("rationale")
    if not preview:
        v = expl.get("verdict")
        preview = f"{v} — {location}" if v else "Sin diagnóstico adicional todavía."

    dchips = [f'<span class="sev" style="color:{esc(PRIO_COLOR.get(prio, HUD["ink_mute"]))}">{esc(prio)}</span>']
    if kev:
        dchips.append(f'<span class="tag" style="background:{HUD["red"]}">KEV</span>')
    if ransom:
        dchips.append(f'<span class="tag" style="background:{HUD["amber"]}">RANSOMWARE</span>')
    dchips.append(f'<span class="lbadge {bucket}">{esc(BUCKET_LABEL[bucket])}</span>')

    header = (
        '<summary class="dhead">'
        f'<span class="dleft"><span class="chip">{esc(fid)}</span> <strong class="dtitle">{esc(title)}</strong></span>'
        f'<span class="dchips">{"".join(dchips)}</span>'
        '</summary>'
        f'<p class="fpreview">{_prose(preview)} <code>{esc(location)}</code></p>'
    )

    if mode == "executive":
        impact = tri.get("rationale") or preview
        link_target = f"{esc(tech_html_name)}#{esc(fid)}" if tech_html_name else f"#{esc(fid)}"
        body = (
            '<div class="facets">'
            '<div class="facet wide"><div class="flabel">Impacto</div><div class="fval">'
            f'{_prose(impact)} · prioridad {esc(prio)}. '
            f'<a class="ext" href="{link_target}">Ver detalle técnico</a></div></div>'
            '</div>'
        )
        return (f'<details class="fcard" id="{esc(fid)}" data-sev="{esc(prio)}" data-status="{esc(bucket)}" '
                f'data-kev="{1 if kev else 0}" data-search="{search}"{open_attr}>{header}{body}</details>')

    # ---- variante tecnica: facets completos ----
    facets = [
        '<div class="facet"><div class="flabel">📍 Ubicación</div><div class="fval">'
        f'<code class="copychip" data-copy="{esc(location)}">{esc(location)}</code> '
        f'<span class="pill">{esc(owc)}</span> <span class="pill">{esc(cwe)}</span> '
        f'<span class="muted">{esc(f.get("source") or "—")}</span></div></div>'
    ]

    if sast:
        stat_row = (f'<div class="statrow"><span>{esc(sast.get("tool","—"))}</span>'
                    f'<span>regla <code>{esc(sast.get("rule","—"))}</code></span>'
                    f'<span>confianza {esc(sast.get("confidence","—"))}</span></div>')
        hyp = f'<p class="fprose">{_prose(sast.get("hypothesis"))}</p>' if sast.get("hypothesis") else ""
        flow_html = _killchain_html(_flow_steps(sast.get("flow")))
        sarif = (f'<div class="epssrow">SARIF <code class="copychip" data-copy="{esc(sast.get("sarif_ref"))}">{esc(sast.get("sarif_ref"))}</code></div>'
                 if sast.get("sarif_ref") else "")
        facets.append(f'<div class="facet"><div class="flabel">🔬 SAST</div><div class="fval">{stat_row}{hyp}{flow_html}{sarif}</div></div>')

    if intel:
        cve_chips = "".join(
            f'<a class="refchip" href="https://nvd.nist.gov/vuln/detail/{esc(cid)}" target="_blank" rel="noopener noreferrer"><span class="rk">CVE</span>{esc(cid)}</a>'
            for cid in (intel.get("cve_ids") or [])
        ) + "".join(
            f'<a class="refchip" href="https://github.com/advisories/{esc(gid)}" target="_blank" rel="noopener noreferrer"><span class="rk">GHSA</span>{esc(gid)}</a>'
            for gid in (intel.get("ghsa_ids") or [])
        )
        epss = intel.get("epss")
        epss_html = ""
        if epss is not None:
            try:
                pct = max(0.0, min(1.0, float(epss))) * 100
                epss_html = f'<div class="epssrow">EPSS <div class="meter"><div class="meter-f" style="width:{pct:.0f}%"></div></div><span class="pill">{esc(epss)}</span></div>'
            except (TypeError, ValueError):
                epss_html = f'<div class="epssrow">EPSS <span class="pill">{esc(epss)}</span></div>'
        fixed_v = intel.get("fixed_version")
        fixed_html = f' <span style="color:{HUD["green_soft"]}">→ {esc(fixed_v)}</span>' if fixed_v else ""
        facets.append(
            '<div class="facet"><div class="flabel">📡 Dependencia</div><div class="fval">'
            f'<span class="chip">{esc(intel.get("package","—"))}@{esc(intel.get("installed_version","—"))}</span>{fixed_html}'
            + (f'<div class="refs">{cve_chips}</div>' if cve_chips else "")
            + epss_html + '</div></div>'
        )

    if expl:
        v = expl.get("verdict", "—")
        vcolor = HUD["red"] if v == "EXPLOITABLE" else (HUD["amber"] if v == "CONDITIONAL" else HUD["ink_mute"])
        reachable, controllable = expl.get("reachable"), expl.get("controllable")
        if reachable is None and controllable is None and expl.get("alcanzable"):
            # El productor real puede escribir "alcanzable" (texto libre, no
            # siempre boolean-izable, p.ej. "amplificador (no explotable en
            # aislado)") en vez de los booleanos reachable/controllable del
            # schema -- se muestra tal cual en vez de forzar un ✓/✕ que
            # inventaria una precision que el dato no tiene.
            reach_ctrl_html = f'<span class="pill">{esc(expl.get("alcanzable"))}</span>'
        else:
            reach = "✓" if reachable else ("✕" if reachable is not None else "—")
            ctrl = "✓" if controllable else ("✕" if controllable is not None else "—")
            reach_c = HUD["green_soft"] if reachable else (HUD["red"] if reachable is not None else HUD["ink_mute"])
            ctrl_c = HUD["green_soft"] if controllable else (HUD["red"] if controllable is not None else HUD["ink_mute"])
            reach_ctrl_html = (f'<span style="color:{reach_c}">reachable {reach}</span> '
                               f'<span style="color:{ctrl_c}">controllable {ctrl}</span>')
        conf = ""
        if expl.get("confidence_adjusted") is not None:
            conf = (f'<p class="fprose">Confianza: SAST {esc(sast.get("confidence","—"))} → '
                    f'red-team {esc(expl.get("confidence_adjusted"))}</p>')
        cond = f'<p class="fprose">{_prose(expl.get("conditions"))}</p>' if expl.get("conditions") else ""
        chain_html = _killchain_html(_as_list(expl.get("conceptual_chain")))
        facets.append(
            '<div class="facet"><div class="flabel">🎯 Explotabilidad</div><div class="fval">'
            f'<span class="sev" style="color:{vcolor}">{esc(v)}</span> '
            f'{reach_ctrl_html}'
            f'{cond}{conf}{chain_html}</div></div>'
        )

    if tri:
        cvss = cvss_of(tri)
        cvss_html = (f'<span class="cvss-n">{esc(cvss)}</span> <span class="pill">v{esc(tri.get("cvss_version","—"))}</span> '
                     if cvss is not None else "")
        rationale = f'<p class="fprose">{_prose(tri.get("rationale"))}</p>' if tri.get("rationale") else ""
        dedup = (f'<div class="refs"><a class="refchip" href="#{esc(tri.get("dedup_of"))}"><span class="rk">DUP</span>{esc(tri.get("dedup_of"))}</a></div>'
                 if tri.get("dedup_of") else "")
        facets.append(
            '<div class="facet wide"><div class="flabel">⚖️ Triage</div><div class="fval">'
            f'{cvss_html}<span class="sev" style="color:{esc(PRIO_COLOR.get(prio, HUD["ink_mute"]))}">{esc(prio)}</span>'
            f'{rationale}{dedup}</div></div>'
        )

    # honestidad visible por-card (no solo en el agregado 3.3)
    if is_truly_closed(f):
        facets.append(
            '<div class="facet good"><div class="flabel">✅ Verificación</div><div class="fval">'
            f'<span class="ok">{esc(ver.get("verdict","CLOSED"))}</span>'
            + (f' · {_prose(ver.get("evidence"))}' if ver.get("evidence") else "")
            + '</div></div>'
        )
    elif f.get("status") == "closed":
        facets.append(
            '<div class="alert card-alert"><div class="aic">⚠</div><div class="atxt">'
            '<b>status: closed</b> pero sin veredicto <b>CLOSED</b> del verify-engineer — '
            'no cuenta como cerrado.</div></div>'
        )

    footer = ""
    if ver.get("verdict"):
        vcol = {"CLOSED": HUD["green"], "NOT_CLOSED": HUD["amber"], "REGRESSION": HUD["red"]}.get(ver.get("verdict"), HUD["ink_mute"])
        footer = (f'<div class="dfooter"><span class="sev" style="color:{vcol}">{esc(ver.get("verdict"))}</span>'
                  + (f' <span class="muted">{_prose(ver.get("evidence"))}</span>' if ver.get("evidence") else "")
                  + '</div>')

    body = f'<div class="facets">{"".join(facets)}</div><div class="stepper-row">{build_lifecycle_stepper_html(f)}</div>{footer}'
    return (f'<details class="fcard" id="{esc(fid)}" data-sev="{esc(prio)}" data-status="{esc(bucket)}" '
            f'data-kev="{1 if kev else 0}" data-search="{search}"{open_attr}>{header}{body}</details>')


def _cards_toolbar_html(sf):
    counts = {"encontrados": 0, "mitigando": 0, "arreglados": 0, "filtrados": 0}
    for f in sf:
        counts[bucket_of(f)] = counts.get(bucket_of(f), 0) + 1
    tabs = [f'<button class="tab on" onclick="vhSetStatus(this,\'\')">Todos<span class="tcount">{len(sf)}</span></button>']
    for key in ("encontrados", "mitigando", "arreglados", "filtrados"):
        tabs.append(
            f'<button class="tab" onclick="vhSetStatus(this,\'{key}\')">'
            f'<span class="tdot {key}"></span>{BUCKET_LABEL[key]}<span class="tcount">{counts.get(key,0)}</span></button>'
        )
    chips = "".join(f'<button class="chip" data-chip-sev="{p}" onclick="vhSetSev(this,\'{p}\')">{p}</button>' for p in ("P0", "P1", "P2", "P3"))
    chips += '<button class="chip" onclick="vhSetKev(this)">KEV</button>'
    return (
        '<div class="toolbar-cards">'
        f'<div class="tabs">{"".join(tabs)}</div>'
        f'<div class="chiprow">{chips}</div>'
        '<input id="fsearch" type="search" placeholder="Buscar id, título, ubicación, paquete…" oninput="vhSetQuery(this.value)">'
        '<div class="expandrow"><button class="dl" onclick="vhExpandAll(true)">Expandir todo</button>'
        '<button class="dl" onclick="vhExpandAll(false)">Colapsar todo</button></div>'
        '</div>'
    )


def build_finding_cards_section_html(L, mode, tech_html_name=None):
    findings = L.get("findings", [])
    sf = sorted_findings(findings)
    if mode == "technical":
        if not sf:
            return '<div class="cards-wrap"><p class="muted">Sin hallazgos.</p></div>'
        toolbar = _cards_toolbar_html(sf)
        cards = "".join(build_finding_card_html(f, "technical") for f in sf)
        return f'<div class="cards-wrap">{toolbar}<div id="cards">{cards}</div></div>'

    # ---- executive: solo P0/P1/KEV se renderizan como card completa; el resto
    # colapsa en una fila-resumen por bucket con link al informe tecnico ----
    full, rest = [], {}
    for f in sf:
        p = prio_of(f)
        kev = (f.get("intel") or {}).get("in_cisa_kev")
        if p in ("P0", "P1") or kev:
            full.append(f)
        else:
            rest.setdefault(p, []).append(f)
    cards = "".join(build_finding_card_html(f, "executive", tech_html_name=tech_html_name) for f in full)
    if not full:
        cards = '<p class="muted">Sin hallazgos de prioridad alta.</p>'
    rollup_rows = []
    for p in ("P2", "P3", "FILTERED", "—"):
        items = rest.get(p, [])
        if not items:
            continue
        rollup_rows.append(
            f'<tr><td><span class="sev" style="color:{esc(PRIO_COLOR.get(p, HUD["ink_mute"]))}">{esc(p)}</span></td>'
            f'<td>{len(items)} hallazgo(s)</td>'
            f'<td><a class="ext" href="{esc(tech_html_name or "#")}">Ver en informe técnico</a></td></tr>'
        )
    rollup = ""
    if rollup_rows:
        rollup = ('<table class="rollup"><thead><tr><th>Prio</th><th>Cantidad</th><th></th></tr></thead>'
                  f'<tbody>{"".join(rollup_rows)}</tbody></table>')
    return f'<div class="cards-wrap">{cards}{rollup}</div>'


def _report_css():
    """CSS compartido por B.html y B-executive.html. Tokens copiados literalmente
    de panel/index.html (mismo brand ya en produccion, no una paleta nueva).
    Sin border-left como acento en NINGUN selector (test_no_sidestripe_border_left_accent)."""
    return """
:root{
  --bg:#070a0f;--bg-2:#0a0e16;--panel:#0e1420;--panel-2:#111a28;
  --ink:#e6edf6;--ink-soft:#aebacb;--ink-mute:#6b7889;
  --line:rgba(120,160,200,.12);--line-2:rgba(120,160,200,.22);
  --green:#22c55e;--green-soft:#4ade80;--cyan:#22d3ee;--cyan-soft:#67e8f9;
  --amber:#f59e0b;--orange:#fb923c;--red:#ef4444;--violet:#a78bfa;
  --glow-cyan:0 0 0 1px rgba(34,211,238,.35),0 0 22px -4px rgba(34,211,238,.5);
  --glow-green:0 0 0 1px rgba(34,197,94,.35),0 0 22px -4px rgba(34,197,94,.5);
  /* Desviacion deliberada del panel: el panel carga Fira Code/JetBrains Mono/
     Inter/Share Tech Mono desde Google Fonts, pero report.py debe seguir siendo
     100% self-contained/offline -> solo stacks de fuente locales del sistema. */
  --mono:ui-monospace,'SFMono-Regular',Menlo,Consolas,monospace;
  --hud:ui-monospace,'SFMono-Regular',Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.6;-webkit-font-smoothing:antialiased}
.bg-grid{position:fixed;inset:0;z-index:0;pointer-events:none;background-image:linear-gradient(rgba(34,211,238,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(34,211,238,.035) 1px,transparent 1px);background-size:48px 48px;mask-image:radial-gradient(ellipse 85% 55% at 50% 0%,#000 30%,transparent 80%)}
.scanline{position:fixed;inset:0;z-index:1;pointer-events:none;opacity:.35;background:repeating-linear-gradient(transparent 0 2px,rgba(0,0,0,.18) 2px 3px);mix-blend-mode:overlay}
@media (prefers-reduced-motion:reduce){.scanline{display:none}}

.toolbar{position:sticky;top:0;z-index:20;display:flex;gap:10px;justify-content:flex-end;align-items:center;padding:10px 18px;background:rgba(7,10,15,.88);backdrop-filter:blur(6px);border-bottom:1px solid var(--line)}
.toolbar .lbl{margin-right:auto;font-family:var(--mono);font-size:12px;color:var(--ink-mute);letter-spacing:1px;text-transform:uppercase}
.dl,.print{font-family:var(--mono);font-size:12.5px;font-weight:600;text-decoration:none;cursor:pointer;border:1px solid var(--line-2);border-radius:9px;padding:7px 13px;color:var(--ink-soft);background:var(--bg-2);display:inline-flex;gap:7px;align-items:center;transition:border-color .2s,box-shadow .2s,color .2s}
.dl:hover,.print:hover{border-color:var(--cyan);color:var(--ink);box-shadow:var(--glow-cyan)}
.print{border-color:rgba(34,197,94,.4);color:var(--green-soft)}
.print:hover{border-color:var(--green);box-shadow:var(--glow-green)}
.dl-l{font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;color:var(--ink-mute);margin-right:2px}

.layout{max-width:1180px;margin:0 auto;padding:30px 24px 90px;display:grid;grid-template-columns:216px 1fr;gap:34px;align-items:start;position:relative;z-index:2}
.wrap{position:relative;z-index:2;max-width:980px;margin:0 auto;padding:30px 24px 90px}

.toc{position:sticky;top:64px;display:flex;flex-direction:column;gap:2px;font-family:var(--mono);font-size:12px;max-height:calc(100vh - 90px);overflow:auto}
.toc-h{text-transform:uppercase;letter-spacing:1.5px;font-size:10px;color:var(--ink-mute);margin-bottom:8px}
.toc a{color:var(--ink-soft);text-decoration:none;padding:3px 10px;border-radius:6px;transition:background .15s,color .15s}
.toc a:hover{color:var(--cyan);background:rgba(34,211,238,.06)}
.toc .toc-3{padding-left:20px;color:var(--ink-mute);font-size:11px}
.toc .toc-x{color:var(--cyan);font-weight:700}
.doc{min-width:0}

h1{font-family:var(--hud);letter-spacing:.02em;font-size:2rem;margin:.2em 0 .3em;line-height:1.2;color:var(--ink)}
h2{font-size:1.4rem;margin:1.6em 0 .5em;padding-bottom:.3em;border-bottom:1px solid var(--line);scroll-margin-top:64px;color:var(--ink)}
h3{font-size:1.1rem;margin:1.3em 0 .4em;color:var(--cyan-soft);scroll-margin-top:64px}
h4{font-size:.98rem;margin:1.1em 0 .3em;font-family:var(--mono);color:var(--ink-soft)}
p,li{font-size:1rem;color:var(--ink-soft)}
blockquote{margin:1em 0;padding:14px 18px;background:rgba(255,255,255,.02);border:1px solid var(--line-2);border-radius:10px;color:var(--ink-soft)}
abbr.ac{text-decoration:underline dotted;text-decoration-color:var(--cyan);text-underline-offset:3px;cursor:help}
ul{margin:.4em 0 .8em;padding-left:1.3em} li{margin:.18em 0}
hr{border:0;border-top:1px solid var(--line);margin:2em 0}
code{font-family:var(--mono);background:rgba(34,211,238,.08);color:var(--cyan-soft);padding:1px 5px;border-radius:4px;font-size:.86em;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;font-size:.9rem;margin:.6em 0 1.1em;table-layout:fixed}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:break-word}
th{background:rgba(255,255,255,.02);font-family:var(--mono);font-size:10px;letter-spacing:.05em;text-transform:uppercase;color:var(--ink-mute);cursor:pointer;overflow-wrap:break-word}
.tablecard{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
/* Clamp a 2 lineas con elipsis: evita que un titulo largo en una columna angosta
   se envuelva palabra-por-palabra e infle la tabla verticalmente. El texto
   completo sigue en la card de diagnostico (1.3) y en el atributo title=. Motores
   sin soporte de line-clamp (algunos conversores PDF) simplemente lo envuelven
   normal dentro de la columna ya ancha por <col> — degrada, no rompe. */
.tclamp{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
tr.frow{cursor:pointer}
tr.frow:hover{background:rgba(34,211,238,.05)}
.hide{display:none !important}

.panorama{border:1px solid var(--line);border-radius:16px;background:linear-gradient(180deg,var(--panel),var(--bg-2));padding:22px 24px;margin:0 0 22px}
.pan-h{margin:0 0 14px;font-size:1.15rem;border:0;padding:0;color:var(--ink)}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:14px;overflow:hidden;margin-bottom:20px}
.kpi{background:var(--bg-2);text-align:center;padding:18px 8px}
.kpi-n{font-family:var(--hud);font-size:1.7rem;line-height:1;color:var(--cyan)}
.kpi-l{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-mute);margin-top:8px}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.chart{background:rgba(255,255,255,.015);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.chart-wide{grid-column:1/-1}
.chart-t{font-family:var(--mono);font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-mute);margin-bottom:10px}
.donut{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.dn-n{font-family:var(--hud);font-size:24px;fill:var(--ink)}
.dn-l{font-family:var(--mono);font-size:9px;fill:var(--ink-mute)}
.legend{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:10px;font-family:var(--mono);font-size:11px;color:var(--ink-soft)}
.legend .lg{display:inline-flex;align-items:center;gap:6px;cursor:pointer}
.legend .sw{width:10px;height:10px;border-radius:3px;display:inline-block}
.bars{display:flex;flex-direction:column;gap:7px}
.bar{display:grid;grid-template-columns:120px 1fr 28px;align-items:center;gap:8px;font-family:var(--mono);font-size:11px;cursor:pointer}
.bar-l{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--ink-soft)}
.bar-t{display:flex;background:rgba(255,255,255,.05);border-radius:5px;overflow:hidden;height:14px}
.bar-f{display:block;height:14px;border-radius:5px}
.bar-seg{display:block;height:14px;flex:0 0 auto}
.bar-n{text-align:right;color:var(--ink-mute)}
.muted{color:var(--ink-mute);font-style:italic}

.verdict{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;border:1px solid var(--line);border-radius:12px;padding:13px 16px;margin-bottom:18px;background:rgba(255,255,255,.02)}
.verdict.hero{padding:22px 24px;font-size:1.05rem}
.verdict-dot{width:10px;height:10px;border-radius:50%;align-self:center;box-shadow:0 0 10px currentColor}
.verdict-lvl{font-family:var(--hud);font-weight:700;font-size:1.4rem;text-transform:uppercase;letter-spacing:.04em}
.verdict.hero .verdict-lvl{font-size:2.1rem}
.verdict-txt{font-size:.98rem;color:var(--ink-soft)}

.sev-chip{display:inline-block;padding:0 7px;border-radius:5px;font-family:var(--mono);font-weight:700;font-size:.78em;color:var(--bg);line-height:1.5;vertical-align:baseline}
.st-chip{font-family:var(--mono);font-weight:700;font-size:.82em}

.matrix{border:1px solid var(--line);border-radius:8px;overflow:hidden;font-family:var(--mono);font-size:11.5px;width:100%}
.matrix th,.matrix td{text-align:center;padding:8px 6px;border:1px solid var(--line)}
.matrix .mx-c{font-size:9.5px;text-transform:uppercase;letter-spacing:.03em;color:var(--ink-mute);background:rgba(255,255,255,.02)}
.matrix .mx-r{font-weight:700;background:rgba(255,255,255,.02)}
.matrix td.mx{color:var(--ink-mute);background:transparent}
.matrix td.mx.on{color:var(--ink);font-weight:700;background:rgba(255,255,255,.04)}
.matrix td.mx.warn{color:var(--amber);font-weight:700;background:rgba(245,158,11,.12)}
.matrix td.mx.hot{color:#fff;font-weight:700;background:var(--red)}

.chip{font-family:var(--mono);font-size:11.5px;padding:3px 10px;border-radius:999px;border:1px solid var(--line-2);color:var(--ink-mute);background:rgba(255,255,255,.02);display:inline-flex;align-items:center;gap:6px}
.pill{font-family:var(--mono);display:inline-block;padding:1px 8px;border-radius:5px;font-size:10.5px;border:1px solid var(--line-2);color:var(--ink-mute)}
.sev{font-family:var(--mono);font-size:10.5px;font-weight:700;letter-spacing:.4px;border-radius:5px;padding:1px 7px;border:1px solid currentColor;white-space:nowrap;display:inline-block}
.tag{font-family:var(--mono);font-size:9.5px;font-weight:700;letter-spacing:.4px;border-radius:5px;padding:1px 6px;color:var(--bg);margin-left:4px}
.cvss-n{font-family:var(--hud);font-size:1.3rem;color:var(--ink)}

.lbadge{font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.3px;padding:2px 9px;border-radius:6px;border:1px solid currentColor;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.lbadge::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.lbadge.encontrados{color:var(--amber)}
.lbadge.mitigando{color:var(--cyan-soft)}
.lbadge.arreglados{color:var(--green-soft)}
.lbadge.filtrados{color:var(--ink-mute)}

.tabs{display:flex;gap:4px;margin-bottom:12px;flex-wrap:wrap}
.tab{font-family:var(--mono);font-size:12.5px;color:var(--ink-mute);background:transparent;border:1px solid transparent;border-radius:9px;padding:7px 13px;cursor:pointer;display:inline-flex;align-items:center;gap:8px}
.tab:hover{color:var(--ink-soft)}
.tab.on{color:var(--ink);border-color:var(--line-2);background:rgba(255,255,255,.03)}
.tab .tdot{width:7px;height:7px;border-radius:50%}
.tab .tdot.encontrados{background:var(--amber)}
.tab .tdot.mitigando{background:var(--cyan)}
.tab .tdot.arreglados{background:var(--green)}
.tab .tdot.filtrados{background:var(--ink-mute)}
.tab .tcount{font-size:10.5px;color:var(--ink-mute);background:rgba(255,255,255,.05);border-radius:999px;padding:1px 8px;min-width:20px;text-align:center}
.tab.on .tcount{color:var(--ink);background:rgba(34,211,238,.12)}
.chip.on{border-color:var(--cyan);color:var(--cyan-soft);background:rgba(34,211,238,.08)}
.chiprow{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:12px}
.toolbar-cards{border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:0 0 16px;background:rgba(255,255,255,.015)}
#fsearch{font-family:var(--mono);font-size:12.5px;background:var(--bg-2);border:1px solid var(--line-2);color:var(--ink);border-radius:9px;padding:7px 11px;width:100%;max-width:360px;margin-bottom:10px}
.expandrow{display:flex;gap:8px}

.cards-wrap{display:flex;flex-direction:column;gap:12px}
.fcard{border:1px solid var(--line);border-radius:14px;background:linear-gradient(180deg,var(--panel),var(--bg-2));padding:16px 18px;scroll-margin-top:64px;transition:box-shadow .3s}
.fcard[open]{box-shadow:var(--glow-cyan)}
.fcard.flash{animation:vhflash 1.6s ease-out}
@keyframes vhflash{0%{box-shadow:0 0 0 2px var(--cyan),var(--glow-cyan)}100%{box-shadow:none}}
@media (prefers-reduced-motion:reduce){.fcard.flash{animation:none}}
.dhead{display:flex;flex-wrap:wrap;gap:12px 16px;align-items:center;justify-content:space-between;padding-bottom:12px;border-bottom:1px solid var(--line);cursor:pointer;list-style:none}
.dhead::-webkit-details-marker{display:none}
.dhead::after{content:"▸";color:var(--ink-mute);font-size:13px;transition:transform .15s;margin-left:auto}
details[open]>.dhead::after{transform:rotate(90deg)}
@media (prefers-reduced-motion:reduce){.dhead::after{transition:none}}
.dleft{display:flex;align-items:center;gap:10px;min-width:0;flex-wrap:wrap}
.dtitle{font-family:var(--sans);font-weight:700;color:var(--ink);overflow-wrap:anywhere}
.dchips{display:flex;gap:7px;flex-wrap:wrap;align-items:center}
.fpreview{margin:12px 0 0;font-size:.96rem;color:var(--ink-soft)}
.fpreview code{margin-left:8px}

.facets{display:grid;grid-template-columns:repeat(auto-fit,minmax(248px,1fr));gap:0 28px;margin-top:8px}
.facet{padding:12px 0;border-bottom:1px solid var(--line)}
.facet.wide{grid-column:1/-1}
.facet.good{background:linear-gradient(180deg,rgba(34,197,94,.07),transparent);border-radius:10px;padding:12px 14px;margin:4px 0;border-bottom:none}
.flabel{font-family:var(--mono);font-size:10.5px;letter-spacing:.5px;text-transform:uppercase;color:var(--cyan-soft);margin-bottom:6px;display:flex;align-items:center;gap:7px}
.facet.good .flabel{color:var(--green-soft)}
.fval{font-size:.92rem;color:var(--ink-soft);overflow-wrap:anywhere}
.asf-list{margin:0;padding-left:1.1em}
.asf-list li{margin:.2em 0;font-family:var(--mono);font-size:.88em}
.fval .ok{color:var(--green-soft);font-weight:700}
.fprose{margin:8px 0 0;font-family:var(--sans);font-size:.92rem;color:var(--ink-soft)}
.statrow{display:flex;gap:14px;flex-wrap:wrap;font-family:var(--mono);font-size:11.5px;color:var(--ink-mute)}
.meter{display:inline-block;width:80px;height:5px;background:rgba(255,255,255,.08);border-radius:3px;overflow:hidden;vertical-align:middle;margin:0 6px}
.meter-f{height:100%;background:var(--amber)}
.epssrow{margin-top:8px;font-family:var(--mono);font-size:11px;color:var(--ink-mute);display:flex;align-items:center}

.killchain{list-style:none;margin:10px 0 2px;padding:0}
.killchain li{display:flex;gap:12px;align-items:flex-start;padding:6px 0;position:relative}
.killchain li:not(:last-child)::before{content:"";position:absolute;left:11px;top:27px;bottom:-6px;width:1px;background:var(--line-2)}
.killchain .kn{flex:0 0 auto;width:22px;height:22px;border-radius:50%;background:rgba(34,211,238,.1);border:1px solid var(--line-2);color:var(--cyan-soft);font-family:var(--hud);font-size:11px;display:grid;place-items:center}
.killchain .kt{font-size:.88rem;color:var(--ink-soft);padding-top:2px;overflow-wrap:anywhere;font-family:var(--mono)}

.ltrack{display:inline-flex;align-items:center;flex-wrap:wrap;font-family:var(--mono);font-size:10.5px;gap:0}
.lstep{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;border:1px solid var(--line-2);color:var(--ink-mute);white-space:nowrap}
.lstep .ld{width:7px;height:7px;border-radius:50%;background:var(--ink-mute)}
.lstep.past{color:var(--green-soft);border-color:rgba(34,197,94,.4)}
.lstep.past .ld{background:var(--green)}
.lstep.done{color:var(--green-soft);border-color:var(--green);background:rgba(34,197,94,.1)}
.lstep.done .ld{background:var(--green)}
.lstep.cur{color:var(--cyan-soft);border-color:var(--cyan);background:rgba(34,211,238,.08);box-shadow:var(--glow-cyan)}
.lstep.cur .ld{background:var(--cyan)}
.lstep.future{opacity:.5}
.lbar{width:16px;height:1px;background:var(--line-2);flex:0 0 auto}
.lbar.on{background:rgba(34,197,94,.55)}
.ltrack.filtered{color:var(--ink-mute);font-style:italic;border:1px dashed var(--line-2);border-radius:999px;padding:4px 12px;display:inline-block}
.stepper-row{margin-top:12px}

.refs{display:flex;flex-wrap:wrap;gap:7px;margin-top:6px}
.refchip{font-family:var(--mono);font-size:10.5px;display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line-2);border-radius:7px;padding:3px 9px;color:var(--cyan-soft);text-decoration:none;background:rgba(34,211,238,.05)}
.refchip:hover{border-color:var(--cyan);color:var(--cyan);box-shadow:var(--glow-cyan)}
.refchip .rk{color:var(--ink-mute);font-size:9px;font-weight:700;letter-spacing:.4px;text-transform:uppercase}

.copychip{cursor:pointer}
.copychip.copied{color:var(--green-soft) !important;background:rgba(34,197,94,.12) !important}

.dfooter{margin-top:12px;padding-top:12px;border-top:1px solid var(--line);font-size:.88rem;color:var(--ink-soft)}

.alert{display:flex;gap:14px;align-items:flex-start;border:1px solid rgba(245,158,11,.32);border-radius:14px;background:linear-gradient(180deg,rgba(245,158,11,.08),transparent);padding:16px 18px;margin-bottom:20px}
.alert .aic{flex:0 0 auto;width:34px;height:34px;border-radius:9px;display:grid;place-items:center;background:rgba(245,158,11,.14);color:var(--amber);font-size:16px}
.alert .atxt{font-size:.9rem;color:var(--ink-soft)}
.alert .atxt b{color:var(--amber)}
.alert.card-alert{margin:10px 0 0}

.gloss{border-bottom:1px dotted var(--cyan-soft);cursor:help}
#glosstip{position:fixed;z-index:1000;max-width:280px;background:var(--panel-2);border:1px solid var(--line-2);border-radius:10px;padding:10px 12px;box-shadow:0 18px 44px -14px rgba(0,0,0,.85),var(--glow-cyan);font-family:var(--sans);font-size:12px;line-height:1.5;color:var(--ink-soft);pointer-events:none;opacity:0;transition:opacity .12s}
#glosstip.on{opacity:1}
@media (prefers-reduced-motion:reduce){#glosstip{transition:none}}

.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);border-radius:14px;overflow:hidden;margin-bottom:22px}
.stat{background:var(--bg-2);padding:20px 14px;text-align:center}
.stat .n{font-family:var(--hud);font-size:28px;line-height:1;color:var(--cyan)}
.stat .l{font-family:var(--mono);font-size:10.5px;color:var(--ink-mute);margin-top:8px;letter-spacing:.4px;text-transform:uppercase}

.block{margin-bottom:24px}
.eyebrow{font-family:var(--mono);font-size:11px;font-weight:600;letter-spacing:2.2px;text-transform:uppercase;color:var(--cyan);display:inline-flex;align-items:center;gap:10px;margin:0 0 14px}
.eyebrow::before{content:"";width:22px;height:1px;background:var(--cyan);box-shadow:0 0 8px var(--cyan)}
.actioncol{border:1px solid var(--line);border-radius:12px;padding:14px 16px;background:rgba(255,255,255,.015);display:flex;flex-direction:column;gap:8px}
.actionchip{width:100%;justify-content:flex-start;align-items:flex-start;text-align:left;white-space:normal}
.actionchip .idtag{flex:0 0 auto;white-space:nowrap}
.actionchip .actiontxt{flex:1 1 auto;min-width:0;color:var(--ink-soft);font-family:var(--sans)}
.rollup{width:100%;border-collapse:collapse;margin-top:10px}
.rollup td,.rollup th{border-bottom:1px solid var(--line);padding:8px 10px;font-size:.85rem}

.ext{color:var(--cyan-soft);text-decoration:none;border-bottom:1px solid rgba(34,211,238,.35);white-space:nowrap}
.ext:hover{color:var(--cyan);border-bottom-color:var(--cyan)}
.ext::after{content:"↗";font-size:.82em;margin-left:1px;opacity:.65}

.sub{color:var(--ink-mute);font-family:var(--mono);font-size:12px;margin-bottom:20px;overflow-wrap:anywhere}
.sub b{color:var(--ink-soft)}
footer{margin-top:30px;color:var(--ink-mute);font-family:var(--mono);font-size:11px;border-top:1px solid var(--line);padding-top:16px}
footer b{color:var(--cyan-soft)}
footer .ext{margin:0 4px}

@media print{
  html,body{background:var(--bg) !important}
  *{print-color-adjust:exact !important;-webkit-print-color-adjust:exact !important}
  .bg-grid,.scanline,.toolbar,.toc,.toolbar-cards,.copychip,input[type=search]{display:none !important}
  .layout{display:block;max-width:none;padding:0}
  .wrap{max-width:none;padding:0}
  /* Una sola columna en impresion para .chart-grid/.facets (en vez del
     repeat(auto-fit,minmax(...)) de pantalla): no todos los conversores a PDF
     soportan bien CSS Grid con funciones auto-fit/minmax (weasyprint, notablemente,
     puede recortar o superponer el contenido en vez de apilarlo). Un grid de 1
     columna es trivial de soportar en cualquier motor -> nunca se pierde ni se
     encima contenido, aunque ocupe mas paginas. Chrome/Chromium headless (el
     conversor preferido, ver try_pdf) SI soporta el grid completo y no necesita
     esto, pero el fallback debe verse bien tambien. */
  .chart-grid,.facets{display:block !important}
  .chart-grid>.chart,.facets>.facet{margin-bottom:12px}
  .fcard{break-inside:avoid}
  .fcard summary::after,.dhead::after{display:none}
  details:not([open]) > *:not(summary){display:block !important}
  .facet,.chart,.kpi,table,blockquote{break-inside:avoid}
  h2,h3{break-after:avoid}
  @page{margin:14mm 12mm}
}
@media (max-width:820px){
  .layout{grid-template-columns:1fr}
  .toc{position:static;max-height:none;flex-direction:row;flex-wrap:wrap}
  .chart-grid{grid-template-columns:1fr}
  .kpis{grid-template-columns:repeat(2,1fr)}
  .stats{grid-template-columns:repeat(2,1fr)}
}
"""


def _interactivity_js():
    """Un solo <script> vanilla, ES2017-safe, cero red/CDN — debe funcionar
    abriendo el archivo directo por file://. Ver interactivity_spec: filtro
    compartido tabla+cards, expand/collapse, copy-to-clipboard con fallback,
    deep-link por hash, glosario hover/focus, sort de tabla."""
    return """<script>
(function(){
  var state = {sev:null, status:null, kev:false, q:''};
  function apply(){
    var q = state.q.toLowerCase();
    function ok(el){
      if(state.sev && el.dataset.sev !== state.sev) return false;
      if(state.status && el.dataset.status !== state.status) return false;
      if(state.kev && el.dataset.kev !== '1') return false;
      if(q && el.dataset.search && el.dataset.search.indexOf(q) === -1) return false;
      return true;
    }
    document.querySelectorAll('.fcard').forEach(function(c){ c.classList.toggle('hide', !ok(c)); });
    document.querySelectorAll('#findings-table tbody tr[data-sev]').forEach(function(r){ r.classList.toggle('hide', !ok(r)); });
  }
  window.vhSetStatus = function(btn, v){
    state.status = v || null;
    document.querySelectorAll('.tab').forEach(function(b){ b.classList.remove('on'); });
    if(btn) btn.classList.add('on');
    apply();
  };
  window.vhSetSev = function(btn, v){
    var was = btn && btn.classList.contains('on');
    document.querySelectorAll('.chip[data-chip-sev]').forEach(function(b){ b.classList.remove('on'); });
    state.sev = was ? null : v;
    if(!was && btn) btn.classList.add('on');
    apply();
  };
  window.vhSetKev = function(btn){
    state.kev = !state.kev;
    if(btn) btn.classList.toggle('on', state.kev);
    apply();
  };
  window.vhSetQuery = function(v){ state.q = v || ''; apply(); };
  window.vhExpandAll = function(v){
    document.querySelectorAll('.fcard').forEach(function(c){ if(v){ c.setAttribute('open',''); } else { c.removeAttribute('open'); } });
  };
  window.vhFilterFromChart = function(kind, v){
    if(kind === 'sev'){
      var chip = document.querySelector('.chip[data-chip-sev="'+v+'"]');
      if(chip) window.vhSetSev(chip, v);
    } else if(kind === 'q'){
      var inp = document.getElementById('fsearch');
      if(inp){ inp.value = v; }
      window.vhSetQuery(v);
    }
  };
  window.vhSortTable = function(idx){
    var tb = document.querySelector('#findings-table tbody');
    if(!tb) return;
    var rows = Array.prototype.slice.call(tb.rows);
    var dir = tb.getAttribute('data-sort-dir') === 'asc' ? 'desc' : 'asc';
    tb.setAttribute('data-sort-dir', dir);
    rows.sort(function(a,b){
      var av = a.cells[idx].getAttribute('data-sort'); if(av === null){ av = a.cells[idx].textContent; }
      var bv = b.cells[idx].getAttribute('data-sort'); if(bv === null){ bv = b.cells[idx].textContent; }
      var an = parseFloat(av), bn = parseFloat(bv), cmp;
      if(!isNaN(an) && !isNaN(bn)){ cmp = an - bn; } else { cmp = String(av).localeCompare(String(bv)); }
      return dir === 'asc' ? cmp : -cmp;
    });
    rows.forEach(function(r){ tb.appendChild(r); });
  };
  function fallbackCopy(text){
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch(e) {}
    document.body.removeChild(ta);
  }
  document.addEventListener('click', function(e){
    var el = e.target.closest && e.target.closest('.copychip');
    if(!el) return;
    var text = el.getAttribute('data-copy') || el.textContent;
    if(navigator.clipboard && window.isSecureContext){
      navigator.clipboard.writeText(text).catch(function(){ fallbackCopy(text); });
    } else { fallbackCopy(text); }
    el.classList.add('copied');
    setTimeout(function(){ el.classList.remove('copied'); }, 1200);
  });
  function openFromHash(){
    var id = decodeURIComponent(location.hash.replace('#',''));
    if(!id) return;
    var card = document.getElementById(id);
    if(!card || card.tagName !== 'DETAILS') return;
    card.setAttribute('open','');
    var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    card.scrollIntoView({behavior: reduced ? 'auto' : 'smooth', block:'start'});
    if(!reduced){ card.classList.add('flash'); setTimeout(function(){ card.classList.remove('flash'); }, 1600); }
  }
  window.addEventListener('hashchange', openFromHash);
  document.addEventListener('DOMContentLoaded', function(){
    openFromHash();
    document.querySelectorAll('#findings-table tbody tr[data-finding-id]').forEach(function(r){
      r.addEventListener('click', function(){ location.hash = r.getAttribute('data-finding-id'); });
    });
    document.querySelectorAll('#findings-table thead th[data-sortcol]').forEach(function(th){
      th.addEventListener('click', function(){ vhSortTable(parseInt(th.getAttribute('data-sortcol'),10)); });
    });
  });
  function showGlossTip(el){
    var text = el.getAttribute('title'); if(!text) return;
    var tip = document.getElementById('glosstip');
    if(!tip){ tip = document.createElement('div'); tip.id = 'glosstip'; document.body.appendChild(tip); }
    tip.textContent = text;
    var r = el.getBoundingClientRect();
    tip.style.left = Math.max(8, r.left) + 'px';
    tip.style.top = (r.bottom + 8) + 'px';
    tip.classList.add('on');
  }
  function hideGlossTip(){ var tip = document.getElementById('glosstip'); if(tip){ tip.classList.remove('on'); } }
  document.addEventListener('mouseover', function(e){ var el = e.target.closest && e.target.closest('.gloss, abbr.ac'); if(el){ showGlossTip(el); } });
  document.addEventListener('focusin', function(e){ var el = e.target.closest && e.target.closest('.gloss, abbr.ac'); if(el){ showGlossTip(el); } });
  document.addEventListener('mouseout', function(e){ var el = e.target.closest && e.target.closest('.gloss, abbr.ac'); if(el){ hideGlossTip(); } });
})();
</script>"""


def build_html(md_text, has_pdf, md_name, pdf_name, L=None, mode="technical"):
    """Construye el informe TECNICO (B.html — nombre back-compat, panel/app.jsx
    ya apunta aqui). `mode` se preserva por firma/compat de tests; en la practica
    solo se ejerce 'technical': el ejecutivo se compone aparte en
    build_executive_html() (no via split de este markdown, ver diagnostic_card_spec)."""
    toc = build_toc(md_text)
    _base = md_name[:-3] if md_name.endswith(".md") else md_name
    self_name = _base + ".html" if mode == "technical" else _base + "-executive.html"
    sibling_name = _base + "-executive.html" if mode == "technical" else _base + ".html"
    sibling_label = "Ver versión ejecutiva" if mode == "technical" else "Ver versión técnica"
    toolbar_label = "informe técnico" if mode == "technical" else "informe ejecutivo"

    def _wrap(x):
        return decorate_tokens(wrap_acronyms(x))

    charts = ""
    if L is not None:
        try:
            # .md y .html divergen aquí a propósito: 1.1/1.2/1.3 se re-renderizan
            # como facets/tabla/cards HUD en vez de los bloques markdown genéricos
            # (build_md() no cambia — sigue siendo el artefacto de texto plano).
            h11 = md_text.index("### 1.1 Superficie de ataque")
            h11_end = md_text.index("\n", h11) + 1
            h12 = md_text.index("### 1.2 Hallazgos")
            h12_end = md_text.index("\n", h12) + 1
            h13 = md_text.index("### 1.3 Diagnóstico por hallazgo")
            h13_end = md_text.index("\n", h13) + 1
            h2 = md_text.index("---\n\n## 2. Estrategia y plan de remediación")
            body = (
                _wrap(md_to_html_blocks(md_text[:h11_end]))
                + build_attack_surface_html(L)
                + _wrap(md_to_html_blocks(md_text[h12:h12_end]))
                + build_findings_table_html(L)
                + _wrap(md_to_html_blocks(md_text[h13:h13_end]))
                + build_finding_cards_section_html(L, "technical", tech_html_name=self_name)
                + _wrap(md_to_html_blocks(md_text[h2:]))
            )
            charts = build_charts_html(L, mode="technical")
        except ValueError:
            # Literales no encontrados (md_text no vino de build_md()): fallback
            # plano, sin splice.
            body = _wrap(md_to_html_blocks(md_text))
            charts = build_charts_html(L, mode="technical")
    else:
        body = _wrap(md_to_html_blocks(md_text))

    pdf_link = f'<a class="dl" href="{esc(pdf_name)}" download><span class="dl-l">PDF</span></a>' if has_pdf else ""
    css = _report_css()
    js = _interactivity_js()

    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vuln-hunter — Informe de auditoría ({esc(toolbar_label)})</title>
<style>{css}</style></head><body>
<div class="bg-grid" aria-hidden="true"></div>
<div class="scanline" aria-hidden="true"></div>
<div class="toolbar">
  <span class="lbl">vuln-hunter // {esc(toolbar_label)}</span>
  <a class="dl" href="{esc(sibling_name)}">{esc(sibling_label)} →</a>
  {pdf_link}
  <a class="dl" href="{esc(md_name)}" download><span class="dl-l">MD</span></a>
  <button class="print" onclick="window.print()">Descargar PDF</button>
</div>
<div class="layout">
  {toc}
  <main class="doc">{charts}{body}</main>
</div>
{js}
</body></html>"""


def build_executive_html(L, md_name, pdf_name_exec, tech_html_name, has_pdf=False):
    """Informe EJECUTIVO (B-executive.html): compuesto directo desde compute()/
    risk_verdict()/action_buckets()/finding dicts — NO parsea build_md(), la
    estructura diverge demasiado (condensado por construcción, no por CSS que
    esconde cards que igual pesan)."""
    findings = L.get("findings", [])
    C = compute(L)
    lvl, vtext, vcolor = risk_verdict(L)
    now = datetime.now().isoformat(timespec="seconds")
    run = L.get("run", {})
    _base = md_name[:-3] if md_name.endswith(".md") else md_name
    self_name = _base + "-executive.html"

    # include_header=False: el hero de abajo ya cubre el veredicto + los KPIs,
    # así que aquí solo se pide la cuadrícula de gráficas (nada de repetirlos).
    charts = build_charts_html(L, mode="executive", include_header=False)
    inmediato, semana, mes = action_buckets(findings)

    def _bucket_col(title, items):
        if not items:
            body = '<p class="muted">(nada)</p>'
        else:
            body = "".join(
                f'<div class="chip actionchip"><code class="idtag">{esc(it.get("id","?"))}</code>'
                f'<span class="actiontxt">{esc(it.get("title",""))}</span></div>'
                for it in items
            )
        return f'<div class="actioncol"><div class="chart-t">{esc(title)}</div>{body}</div>'

    action_html = (
        '<div class="chart-grid">'
        + _bucket_col("Inmediato (P0 / KEV)", inmediato)
        + _bucket_col("Esta semana (P1)", semana)
        + _bucket_col("Este mes (P2 / P3)", mes)
        + '</div>'
    )

    cards_html = build_finding_cards_section_html(L, "executive", tech_html_name=tech_html_name)

    kev_alert = ""
    if C["kev"]:
        kev_alert = (
            '<div class="alert"><div class="aic">⚠</div><div class="atxt">'
            f'<b>{C["kev"]} dependencia(s)</b> de producción con CVE en <b>CISA KEV</b> '
            '(explotación confirmada in-the-wild). Parchea antes de desplegar.</div></div>'
        )

    open_kev = sum(1 for f in findings if isinstance(f, dict) and is_open(f) and (f.get("intel") or {}).get("in_cisa_kev"))
    deploy_html = (
        '<div class="alert card-alert" style="border-color:rgba(239,68,68,.4)"><div class="aic">⛔</div>'
        f'<div class="atxt"><b>Deploy bloqueado</b> · {open_kev} hallazgo(s) KEV abiertos.</div></div>'
        if open_kev else
        '<div class="facet good"><div class="flabel">Deploy</div><div class="fval">Sin bloqueos KEV activos.</div></div>'
    )

    # Nota honesta: si el triage filtro/dedupe buena parte de lo detectado, el
    # lector ejecutivo debe saberlo en una linea (no solo intuirlo comparando el
    # KPI "Hallazgos" contra la dona, que ya excluye lo filtrado) — evita que
    # "17 hallazgos" en el KPI lea como 17 amenazas reales.
    filtered_note = ""
    if C["filtered"]:
        filtered_note = (
            f'<p class="muted">{C["filtered"]} de {len(findings)} hallazgo(s) fueron descartados por el '
            f'triage (duplicados o refutados tras análisis) — quedan {max(len(findings) - C["filtered"], 0)} '
            f'reales. Ver el detalle de cada uno en el <a class="ext" href="{esc(tech_html_name)}">informe técnico</a>.</p>'
        )

    pdf_link = f'<a class="dl" href="{esc(pdf_name_exec)}" download><span class="dl-l">PDF</span></a>' if has_pdf else ""
    css = _report_css()
    js = _interactivity_js()

    body = f"""
<div class="toolbar">
  <span class="lbl">vuln-hunter // informe ejecutivo</span>
  <a class="dl" href="{esc(tech_html_name)}">Ver versión técnica →</a>
  {pdf_link}
  <a class="dl" href="{esc(md_name)}" download><span class="dl-l">MD</span></a>
  <button class="print" onclick="window.print()">Descargar PDF</button>
</div>
<div class="wrap">
  <div class="sub">Scope: <b>{esc(run.get('scope') or 'repo completo')}</b> · OWASP {esc(run.get('owasp_version','2025'))} · Branch {esc(run.get('branch','—'))} · Generado {esc(now)}</div>
  <div class="verdict hero" style="border-color:{esc(vcolor)}">
    <span class="verdict-dot" style="background:{esc(vcolor)}"></span>
    <span class="verdict-lvl" style="color:{esc(vcolor)}">Riesgo {esc(lvl)}</span>
    <span class="verdict-txt">{esc(vtext)}</span>
  </div>
  {kev_alert}
  <div class="stats">
    <div class="stat"><div class="n">{len(findings)}</div><div class="l">Hallazgos</div></div>
    <div class="stat"><div class="n" style="color:{HUD['green']}">{C['closed']}</div><div class="l">Cerrados</div></div>
    <div class="stat"><div class="n" style="color:{HUD['green_soft']}">{C['fixed']}</div><div class="l">Corregidos</div></div>
    <div class="stat"><div class="n" style="color:{HUD['red']}">{C['kev']}</div><div class="l">CISA KEV</div></div>
  </div>
  <div class="block">
    <div class="eyebrow">Panorama</div>
    {charts}
    {filtered_note}
  </div>
  <div class="block">{deploy_html}</div>
  <div class="block">
    <div class="eyebrow">Plan de acción</div>
    {action_html}
  </div>
  <div class="block">
    <div class="eyebrow">Casos prioritarios</div>
    {cards_html}
  </div>
  <footer>Generado el {esc(now)} · vuln-hunter es un primer pase disciplinado; no reemplaza auditoría humana.
    <a class="ext" href="{esc(tech_html_name)}">Informe técnico completo</a>
    <a class="ext" href="{esc(tech_html_name)}#glosario">Glosario</a>
  </footer>
</div>
{js}"""

    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vuln-hunter — Informe ejecutivo</title>
<style>{css}</style></head><body>
<div class="bg-grid" aria-hidden="true"></div>
<div class="scanline" aria-hidden="true"></div>
{body}
</body></html>"""


# ----------------------------- documento formal (PDF) -----------------------
# El PDF NO es un print-to-pdf del dashboard interactivo (fondo oscuro, cards
# colapsables, JS de filtrado) -- es un documento APARTE, deliberadamente mas
# simple, pensado para leerse de principio a fin en papel/pantalla: portada,
# indice con numeros de pagina REALES, encabezado/pie en cada pagina, paleta
# clara tradicional. Comparte toda la logica de DATOS con el dashboard
# (compute/prio_of/cvss_of/normalize_exploitability/sorted_findings/...) pero
# NO su capa de presentacion (esa inyecta el color oscuro inline; no vale la
# pena parametrizarla, son productos distintos con audiencias distintas).
#
# Requiere un motor de paginado REAL (soporte de target-counter() para los
# numeros de pagina del indice, y @page margin boxes para encabezado/pie con
# counter(page)/counter(pages)): verificado que weasyprint lo soporta
# correctamente y Chrome headless NO (ni con --print-to-pdf ni con ninguna
# combinacion de flags) -- ver try_formal_pdf(), que por eso invierte el
# orden de preferencia de try_pdf() SOLO para este documento.
PRINT = {
    "bg": "#ffffff", "bg_soft": "#f4f5f7", "panel": "#fbfbfc",
    "ink": "#1a1f2b", "ink_soft": "#3d4552", "ink_mute": "#6b7280",
    "line": "#d9dde3", "line_soft": "#eceef1",
    "red": "#b3261e", "orange": "#c2650a", "amber": "#8a6d1a", "green": "#15803d",
    "green_soft": "#1f9d5c", "accent": "#1d4e89", "accent_soft": "#2f6fb3",
}
PRINT_PRIO = {"P0": PRINT["red"], "P1": PRINT["orange"], "P2": PRINT["amber"],
              "P3": PRINT["ink_mute"], "FILTERED": PRINT["ink_mute"], "—": PRINT["ink_mute"]}
# Traduccion SOLO para el texto visible del PDF -- el literal en ingles
# (schema/ledger-contract, comparaciones == "EXPLOITABLE" etc.) no se toca en
# ningun lado: estos dict solo deciden que palabra imprimir en el badge.
PRINT_PRIO_LABEL = {"FILTERED": "FILTRADO"}
PRINT_EXPL_LABEL = {"EXPLOITABLE": "EXPLOTABLE", "CONDITIONAL": "CONDICIONAL", "NOT_EXPLOITABLE": "NO EXPLOTABLE"}
PRINT_VER_LABEL = {"CLOSED": "CERRADO", "NOT_CLOSED": "NO CERRADO", "REGRESSION": "REGRESIÓN"}
PRINT_SANS = "'Helvetica Neue',Helvetica,Arial,sans-serif"
PRINT_SERIF = "Georgia,'Times New Roman',serif"
PRINT_MONO = "'SFMono-Regular',Consolas,'Liberation Mono',monospace"


def _print_css(doc_title):
    return f"""
@page {{
  size: A4;
  margin: 24mm 20mm 20mm 20mm;
  @top-left {{ content: "vuln-hunter"; font-family:{PRINT_SANS}; font-size:8.5pt; font-weight:700; letter-spacing:.05em; color:{PRINT["ink_mute"]}; }}
  @top-right {{ content: "{doc_title}"; font-family:{PRINT_SANS}; font-size:8.5pt; color:{PRINT["ink_mute"]}; }}
  @bottom-center {{ content: "Página " counter(page) " de " counter(pages); font-family:{PRINT_SANS}; font-size:8.5pt; color:{PRINT["ink_mute"]}; }}
  @bottom-right {{ content: "CONFIDENCIAL"; font-family:{PRINT_SANS}; font-size:8pt; font-weight:700; letter-spacing:.05em; color:{PRINT["red"]}; }}
}}
@page :first {{
  @top-left {{ content:""; }} @top-right {{ content:""; }}
  @bottom-center {{ content:""; }} @bottom-right {{ content:""; }}
}}
*{{box-sizing:border-box}}
body{{margin:0;font-family:{PRINT_SERIF};color:{PRINT["ink"]};line-height:1.55;font-size:10.5pt;background:{PRINT["bg"]}}}
h1,h2,h3,h4{{font-family:{PRINT_SANS};color:#12151c;font-weight:700;line-height:1.25}}
p,li{{font-size:10pt}}
a{{color:{PRINT["accent"]}}}
code{{font-family:{PRINT_MONO};background:{PRINT["bg_soft"]};padding:1px 5px;border-radius:3px;font-size:.9em;overflow-wrap:anywhere}}

/* justify-content:center dejaba el bloque de titulo/tabla flotando a medio
   folio con un hueco enorme arriba Y abajo (visto en el PDF real) -- una
   portada formal ancla el titulo cerca del tercio superior y usa el resto
   para el veredicto + el pie legal, no para aire vacio de sobra. */
.cover{{break-after:page;min-height:235mm;display:flex;flex-direction:column;justify-content:flex-start;padding-top:58mm;border-top:5px solid {PRINT["accent"]}}}
.cover .brand{{font-family:{PRINT_SANS};font-size:12.5pt;letter-spacing:.14em;text-transform:uppercase;color:{PRINT["accent"]};font-weight:700;margin-bottom:.6em}}
.cover h1{{font-size:27pt;margin:0 0 .15em}}
.cover .subtitle{{font-family:{PRINT_SANS};font-size:12.5pt;color:{PRINT["ink_soft"]};margin-bottom:1.6em}}
.cover .meta-table{{width:65%;border-collapse:collapse;margin-bottom:1.6em}}
.cover .meta-table td{{padding:5px 0;font-size:10pt;border-bottom:1px solid {PRINT["line_soft"]}}}
.cover .meta-table td:first-child{{font-family:{PRINT_SANS};color:{PRINT["ink_mute"]};text-transform:uppercase;letter-spacing:.04em;font-size:8pt;width:38%}}
.cover .verdict-banner{{border:1.5px solid currentColor;border-radius:7px;padding:14px 20px;display:inline-block;margin-bottom:1.5em;max-width:75%}}
.cover .verdict-lvl{{font-family:{PRINT_SANS};font-weight:700;font-size:13pt;text-transform:uppercase;display:block;margin-bottom:3px}}
.cover .verdict-txt{{font-family:{PRINT_SERIF};font-size:10pt;color:{PRINT["ink_soft"]}}}
.cover .confidential{{margin-top:auto;padding-top:2em;font-family:{PRINT_SANS};font-size:9pt;color:{PRINT["red"]};font-weight:700;letter-spacing:.06em}}
.cover .disclaimer{{font-family:{PRINT_SANS};font-size:8.5pt;color:{PRINT["ink_mute"]};margin-top:.5em;max-width:80%}}

.toc-page{{break-after:page}}
.toc-page h2{{font-size:16pt;border-bottom:2px solid {PRINT["accent"]};padding-bottom:7px;margin-bottom:18px}}
.toc-row{{display:flex;align-items:baseline;gap:6px;font-family:{PRINT_SANS};font-size:10pt;margin:6px 0;text-decoration:none;color:{PRINT["ink"]}}}
.toc-row.lvl3{{padding-left:18px;font-size:9pt;color:{PRINT["ink_soft"]}}}
.toc-row .leader{{flex:1 1 auto;border-bottom:1px dotted {PRINT["line"]};position:relative;top:-3px;margin:0 4px;min-width:8px}}
/* target-counter() lee el atributo href del elemento AL QUE SE APLICA la
   regla -- por eso el numero de pagina va en el ::after del propio <a>
   (flex, asi cae despues de .leader en el orden visual), no en un <span>
   anidado sin href propio (eso se probo y quedaba vacio: attr() no sube a
   buscar el atributo en un ancestro). */
.toc-row::after{{content:target-counter(attr(href url),page);font-variant-numeric:tabular-nums}}

h2.sec{{font-size:15pt;border-bottom:1.5px solid {PRINT["line"]};padding-bottom:6px;margin:0 0 .7em;break-after:avoid}}
h2.sec .n{{color:{PRINT["accent"]};margin-right:.35em}}
h3.subsec{{font-size:11.5pt;color:{PRINT["accent"]};margin:1.5em 0 .5em;break-after:avoid}}
section.print-sec{{break-before:page}}
section.print-sec:first-of-type{{break-before:auto}}

table{{width:100%;border-collapse:collapse;font-size:9pt;margin:.6em 0 1.3em}}
th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid {PRINT["line_soft"]};vertical-align:top}}
th{{background:{PRINT["bg_soft"]};font-family:{PRINT_SANS};font-size:7.8pt;text-transform:uppercase;letter-spacing:.03em;color:{PRINT["ink_mute"]}}}
tr{{break-inside:avoid}}
/* zebra striping en tablas de datos (no en la portada, esa es 2 columnas
   etiqueta/valor y las franjas ahi solo ensucian) -- ayuda a seguir la fila
   en tablas anchas de 5-6 columnas como Hallazgos. */
table:not(.meta-table) tbody tr:nth-child(even){{background:{PRINT["bg_soft"]}}}

/* table-layout:auto exprimia la columna ID (contenido corto, "VULN-001")
   hasta partirla letra por letra para dejarle sitio a Titulo/Ubicacion (largos)
   -- visto en el PDF real via inspeccion visual pagina 7. Ancho fijo por
   columna + nowrap en el codigo del ID lo evita sin tocar el resto. */
table.findings-table{{table-layout:fixed}}
table.findings-table td:first-child code, table.findings-table th:first-child{{white-space:nowrap}}
/* la columna Prio debe caber "FILTERED" (el badge mas largo), no solo "P0"/"P1" */
table.findings-table td:nth-child(2) .sev-badge{{padding:1px 6px;font-size:7.3pt}}
table.findings-table.cols-6 th:nth-child(1),table.findings-table.cols-6 td:nth-child(1){{width:9%}}
table.findings-table.cols-6 th:nth-child(2),table.findings-table.cols-6 td:nth-child(2){{width:11%}}
table.findings-table.cols-6 th:nth-child(3),table.findings-table.cols-6 td:nth-child(3){{width:6%}}
table.findings-table.cols-6 th:nth-child(4),table.findings-table.cols-6 td:nth-child(4){{width:29%}}
table.findings-table.cols-6 th:nth-child(5),table.findings-table.cols-6 td:nth-child(5){{width:29%}}
table.findings-table.cols-6 th:nth-child(6),table.findings-table.cols-6 td:nth-child(6){{width:16%}}
table.findings-table.cols-4 th:nth-child(1),table.findings-table.cols-4 td:nth-child(1){{width:12%}}
table.findings-table.cols-4 th:nth-child(2),table.findings-table.cols-4 td:nth-child(2){{width:16%}}
table.findings-table.cols-4 th:nth-child(3),table.findings-table.cols-4 td:nth-child(3){{width:52%}}
table.findings-table.cols-4 th:nth-child(4),table.findings-table.cols-4 td:nth-child(4){{width:20%}}

.sev-badge{{display:inline-block;font-family:{PRINT_SANS};font-weight:700;font-size:8pt;padding:1px 8px;border-radius:4px;border:1.3px solid currentColor;white-space:nowrap}}
.tag-badge{{display:inline-block;font-family:{PRINT_SANS};font-weight:700;font-size:7.5pt;padding:1px 7px;border-radius:4px;color:#fff;margin-left:4px}}

.callout{{border:1px solid {PRINT["line"]};background:{PRINT["bg_soft"]};border-radius:6px;padding:11px 15px;margin:1em 0;font-size:9.5pt;break-inside:avoid}}
.callout.warn{{border-color:#e3b25a;background:#fbf3e3}}
.callout b{{font-family:{PRINT_SANS}}}

.finding-block{{break-inside:avoid-page;margin-bottom:1.5em;padding:.1em 0 1.2em 12px;border-bottom:1px solid {PRINT["line_soft"]}}}
.finding-block h3{{margin:0 0 .3em;font-size:11.5pt}}
.finding-block .fmeta{{font-family:{PRINT_SANS};font-size:8pt;color:{PRINT["ink_mute"]};margin-bottom:.6em}}
.fact-grid{{display:table;width:100%;margin:.4em 0 .8em;border-collapse:collapse}}
.fact-row{{display:table-row}}
.fact-label{{display:table-cell;width:20%;font-family:{PRINT_SANS};font-size:7.8pt;text-transform:uppercase;letter-spacing:.03em;color:{PRINT["ink_mute"]};padding:3px 10px 3px 0;vertical-align:top}}
.fact-val{{display:table-cell;padding:3px 0;font-size:9.5pt;vertical-align:top}}
.killstep{{margin:2px 0;font-family:{PRINT_MONO};font-size:8.6pt;color:{PRINT["ink_soft"]}}}
.killstep b{{color:{PRINT["ink"]};font-family:{PRINT_SANS}}}

.action-cols{{display:table;width:100%;table-layout:fixed;border-spacing:10px 0;margin:.5em -10px}}
.action-col{{display:table-cell;width:33.33%;vertical-align:top;border:1px solid {PRINT["line"]};border-radius:6px;padding:10px 12px}}
.action-col h4{{font-size:9pt;text-transform:uppercase;letter-spacing:.03em;color:{PRINT["ink_mute"]};margin:0 0 .5em}}
.action-item{{font-size:9pt;margin:.35em 0;break-inside:avoid}}
.action-item code{{display:block;margin-bottom:1px}}

dl.gloss{{font-size:9pt}}
dl.gloss dt{{font-family:{PRINT_SANS};font-weight:700;margin-top:.7em}}
dl.gloss dd{{margin:.15em 0 0}}
"""


def _print_verdict_color(lvl):
    return {"alto": PRINT["red"], "medio": PRINT["orange"], "moderado": PRINT["amber"],
            "controlado": PRINT["green"], "sin hallazgos": PRINT["ink_mute"]}.get(lvl, PRINT["ink_mute"])


def _print_cover_html(L, mode, doc_title):
    run = L.get("run", {})
    findings = L.get("findings", [])
    C = compute(L)
    lvl, vtext, vcolor = risk_verdict(L)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    subtitle = ("Informe técnico completo" if mode == "technical"
                else "Resumen ejecutivo — solo hallazgos de mayor riesgo")
    pcolor = _print_verdict_color(lvl)
    meta = [
        ("Alcance", run.get("scope") or "repo completo"),
        ("Branch", run.get("branch") or "—"),
        ("Marco OWASP", run.get("owasp_version") or "2025"),
        ("Hallazgos totales", str(len(findings))),
        ("Generado", now),
    ]
    meta_html = "".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in meta)
    return f"""<div class="cover">
  <div class="brand">vuln-hunter</div>
  <h1>{esc(doc_title)}</h1>
  <div class="subtitle">{esc(subtitle)}</div>
  <table class="meta-table"><tbody>{meta_html}</tbody></table>
  <div class="verdict-banner" style="color:{esc(pcolor)}">
    <span class="verdict-lvl">Riesgo {esc(lvl)}</span>
    <span class="verdict-txt">{esc(vtext)}</span>
  </div>
  <div class="confidential">CONFIDENCIAL — USO INTERNO</div>
  <div class="disclaimer">Auditoría defensiva y autorizada del código propio. No sustituye una auditoría
  humana ni herramientas SAST/DAST dedicadas. Generado de forma determinista desde el ledger de la
  corrida ({esc(C['closed'])} cerrados · {esc(C['fixed'])} corregidos de {esc(len(findings))} hallazgos).</div>
</div>"""


def _print_toc_html(entries):
    rows = []
    for slug, label, level in entries:
        cls = "toc-row lvl3" if level == 3 else "toc-row"
        rows.append(f'<a class="{cls}" href="#{esc(slug)}">{esc(label)}<span class="leader"></span></a>')
    return f'<div class="toc-page"><h2>Índice</h2>{"".join(rows)}</div>'


def _print_findings_table_html(findings, mode):
    if not findings:
        return "<p><em>Sin hallazgos en el ledger.</em></p>"
    heads = (["ID", "Prio", "CVSS", "Título", "Ubicación", "Estado"] if mode == "technical"
             else ["ID", "Prio", "Título", "Estado"])
    ths = "".join(f"<th>{esc(h)}</th>" for h in heads)
    rows = []
    for f in sorted_findings(findings):
        tri = f.get("triage") or {}
        ver = f.get("verification") or {}
        prio = prio_of(f)
        est = STATUS_LABEL.get(f.get("status"), f.get("status", "—"))
        if ver.get("verdict"):
            est += f" / {esc(PRINT_VER_LABEL.get(ver.get('verdict'), ver.get('verdict')))}"
        badge = (f'<span class="sev-badge" style="color:{esc(PRINT_PRIO.get(prio, PRINT["ink_mute"]))}">'
                 f'{esc(PRINT_PRIO_LABEL.get(prio, prio))}</span>')
        title_cell = f'<a href="#{esc(f.get("id",""))}">{esc(f.get("title") or "—")}</a>'
        if mode == "technical":
            cvss_v = cvss_of(tri)
            cvss_cell = f"{cvss_v:g}" if isinstance(cvss_v, (int, float)) else "—"
            rows.append(
                f"<tr><td><code>{esc(f.get('id','?'))}</code></td><td>{badge}</td>"
                f"<td>{esc(cvss_cell)}</td><td>{title_cell}</td>"
                f"<td><code>{esc(f.get('location') or '—')}</code></td><td>{esc(est)}</td></tr>"
            )
        else:
            rows.append(
                f"<tr><td><code>{esc(f.get('id','?'))}</code></td><td>{badge}</td>"
                f"<td>{title_cell}</td><td>{esc(est)}</td></tr>"
            )
    cols_cls = "cols-6" if mode == "technical" else "cols-4"
    return f"<table class=\"findings-table {cols_cls}\"><thead><tr>{ths}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _print_fact_row(label, value_html):
    return f'<div class="fact-row"><div class="fact-label">{esc(label)}</div><div class="fact-val">{value_html}</div></div>'


def _print_killsteps_html(steps):
    steps = [s for s in steps if s]
    if not steps:
        return ""
    cleaned = [_LEADING_NUM_RE.sub("", s, count=1) for s in steps]
    return "".join(f'<div class="killstep"><b>{i+1}.</b> {esc(s)}</div>' for i, s in enumerate(cleaned))


def _print_finding_block_html(f):
    """Un bloque por hallazgo (solo tecnico): igual de completo que la card
    interactiva (misma logica de datos: cvss_of/normalize_exploitability/
    _flow_steps), pero como texto formal en vez de widget colapsable."""
    fid = f.get("id", "?")
    title = f.get("title") or "(sin título)"
    prio = prio_of(f)
    tri = f.get("triage") or {}
    sast = f.get("sast") or {}
    intel = f.get("intel") or {}
    expl = normalize_exploitability(f.get("exploitability") or {})
    ver = f.get("verification") or {}
    fix = f.get("fix") or {}
    intel_flags = ("KEV" if intel.get("in_cisa_kev") else "") + (" RANSOMWARE" if intel.get("known_ransomware_use") else "")
    badges = (f'<span class="sev-badge" style="color:{esc(PRINT_PRIO.get(prio, PRINT["ink_mute"]))}">'
              f'{esc(PRINT_PRIO_LABEL.get(prio, prio))}</span>')
    if intel.get("in_cisa_kev"):
        badges += f'<span class="tag-badge" style="background:{PRINT["red"]}">KEV</span>'
    if intel.get("known_ransomware_use"):
        badges += f'<span class="tag-badge" style="background:{PRINT["orange"]}">RANSOMWARE</span>'
    est = STATUS_LABEL.get(f.get("status"), f.get("status", "—"))

    facts = [_print_fact_row("Ubicación", f'<code>{esc(f.get("location") or "—")}</code>')]
    owc = f.get("owasp_2025") or f.get("owasp_2021") or "—"
    facts.append(_print_fact_row("OWASP / CWE", f'{esc(owc)} / {esc(f.get("cwe") or "—")}'))

    if sast:
        sast_val = f'{esc(sast.get("tool","—"))} · regla <code>{esc(sast.get("rule","—"))}</code> · confianza {esc(sast.get("confidence","—"))}'
        if sast.get("hypothesis"):
            sast_val += f'<br>{esc(sast.get("hypothesis"))}'
        sast_val += _print_killsteps_html(_flow_steps(sast.get("flow")))
        facts.append(_print_fact_row("SAST", sast_val))

    if intel:
        dep_val = f'{esc(intel.get("package","—"))}@{esc(intel.get("installed_version","—"))}'
        if intel.get("fixed_version"):
            dep_val += f' → <b>{esc(intel.get("fixed_version"))}</b>'
        ids = joinlist(intel.get("cve_ids")) + ("  " + joinlist(intel.get("ghsa_ids")) if intel.get("ghsa_ids") else "")
        if ids:
            dep_val += f'<br>{esc(ids)}'
        if intel.get("epss") is not None:
            dep_val += f'<br>EPSS: {esc(intel.get("epss"))}'
        facts.append(_print_fact_row("Dependencia", dep_val))

    if expl:
        v = expl.get("verdict", "—")
        vcolor = PRINT["red"] if v == "EXPLOITABLE" else (PRINT["orange"] if v == "CONDITIONAL" else PRINT["ink_mute"])
        expl_val = f'<span class="sev-badge" style="color:{esc(vcolor)}">{esc(PRINT_EXPL_LABEL.get(v, v))}</span>'
        reachable, controllable = expl.get("reachable"), expl.get("controllable")

        def _si_no(b):
            return "—" if b is None else ("Sí" if b else "No")

        if reachable is None and controllable is None and expl.get("alcanzable"):
            expl_val += f' · {esc(expl.get("alcanzable"))}'
        elif reachable is not None or controllable is not None:
            expl_val += f' · alcanzable={esc(_si_no(reachable))}, controlable={esc(_si_no(controllable))}'
        if expl.get("conditions"):
            expl_val += f'<br>{esc(expl.get("conditions"))}'
        expl_val += _print_killsteps_html(_as_list(expl.get("conceptual_chain")))
        if expl.get("confidence_adjusted") is not None:
            expl_val += f'<br>Confianza ajustada: {esc(expl.get("confidence_adjusted"))}/10'
        facts.append(_print_fact_row("Explotabilidad", expl_val))

    if tri:
        cvss_v = cvss_of(tri)
        tri_val = f"{cvss_v:g} (v{tri.get('cvss_version','—')})" if isinstance(cvss_v, (int, float)) else "—"
        if tri.get("rationale"):
            tri_val += f'<br>{esc(tri.get("rationale"))}'
        if tri.get("dedup_of"):
            tri_val += f'<br>Duplicado de <a href="#{esc(tri.get("dedup_of"))}"><code>{esc(tri.get("dedup_of"))}</code></a>'
        facts.append(_print_fact_row("Triage", tri_val))

    if fix:
        fix_val = esc(fix.get("summary") or fix.get("root_cause") or "—")
        if fix.get("root_cause") and fix.get("summary"):
            fix_val = f'Causa raíz: {esc(fix.get("root_cause"))}<br>{esc(fix.get("summary"))}'
        if fix.get("asvs"):
            fix_val += f'<br>ASVS: {esc(joinlist(fix.get("asvs")))}'
        if fix.get("files_touched"):
            fix_val += f'<br><code>{esc(joinlist(fix.get("files_touched")))}</code>'
        facts.append(_print_fact_row("Fix aplicado" if fix.get("applied") else "Enfoque de fix", fix_val))

    honesty = ""
    if f.get("status") == "closed" and not is_truly_closed(f):
        honesty = ('<div class="callout warn"><b>estado: cerrado</b> pero sin veredicto <b>CERRADO</b> del '
                   'verify-engineer — no cuenta como cerrado en este informe.</div>')
    elif ver.get("verdict"):
        vcol = {"CLOSED": PRINT["green"], "NOT_CLOSED": PRINT["orange"], "REGRESSION": PRINT["red"]}.get(ver.get("verdict"), PRINT["ink_mute"])
        ev = f' — {esc(ver.get("evidence"))}' if ver.get("evidence") else ""
        honesty = (f'<div class="callout" style="border-color:{esc(vcol)}"><b>Verificación:</b> '
                   f'{esc(PRINT_VER_LABEL.get(ver.get("verdict"), ver.get("verdict")))}{ev}</div>')

    # barra de color a la izquierda = severidad, de un vistazo al hojear el PDF
    # (antes solo el badge P0/P1 lo indicaba, perdido si se hojea en miniatura)
    accent = esc(PRINT_PRIO.get(prio, PRINT["ink_mute"]))
    return (f'<div class="finding-block" id="{esc(fid)}" style="border-left:3px solid {accent}">'
            f'<h3><code>{esc(fid)}</code> — {esc(title)}</h3>'
            f'<div class="fmeta">{badges} · {esc(est)}{(" · " + esc(intel_flags.strip())) if intel_flags.strip() else ""}</div>'
            f'<div class="fact-grid">{"".join(facts)}</div>{honesty}</div>')


def _print_action_plan_html(findings):
    inmediato, semana, mes = action_buckets(findings)

    def _col(title, items):
        if not items:
            body = '<p class="action-item"><em>(nada)</em></p>'
        else:
            body = "".join(
                f'<div class="action-item"><code>{esc(it.get("id","?"))}</code>{esc(it.get("title",""))}</div>'
                for it in items
            )
        return f'<div class="action-col"><h4>{esc(title)}</h4>{body}</div>'

    return (f'<div class="action-cols">{_col("Inmediato (P0 / KEV)", inmediato)}'
            f'{_col("Esta semana (P1)", semana)}{_col("Este mes (P2 / P3)", mes)}</div>')


def _print_glossary_html():
    # el glosario markdown usa **negrita**; en texto formal basta mostrarlo sin marcado
    dts = "".join(
        f"<dt>{esc(term)}</dt><dd>{esc(desc).replace('**', '')}</dd>"
        for term, desc in GLOSSARY
    )
    return f'<dl class="gloss">{dts}</dl>'


def build_formal_document_html(L, mode="technical"):
    """Documento PDF formal completo: portada + índice con páginas reales +
    cuerpo en paleta clara. mode: "technical" (todo el detalle) | "executive"
    (condensado, solo P0/P1/KEV con detalle, el resto en una tabla-resumen)."""
    findings = L.get("findings", [])
    C = compute(L)
    lvl, vtext, vcolor = risk_verdict(L)
    doc_title = "Informe técnico de auditoría" if mode == "technical" else "Resumen ejecutivo"
    toc_entries = []
    parts = []

    # Numeracion AUTOMATICA (nunca hardcodeada): algunas secciones son
    # condicionales (p.ej. "Resultados" solo si hay fix/verification), asi que
    # numeros fijos ("6.", "7.") se desincronizan en cuanto una seccion de en
    # medio no se emite (visto: el indice saltaba de "5." a "7." sin "6.").
    sec_n = [0]

    def _sec(label, level=2):
        if level == 2:
            sec_n[0] += 1
        num = f"{sec_n[0]}." if level == 2 else ""
        full_label = f"{num} {label}" if num else label
        slug = slugify(full_label)
        toc_entries.append((slug, full_label, level))
        tag = "h2" if level == 2 else "h3"
        klass = "sec" if level == 2 else "subsec"
        prefix = f'<span class="n">{esc(num)}</span>' if num else ""
        heading = f'<{tag} id="{slug}" class="{klass}">{prefix}{esc(label)}</{tag}>'
        if level == 2:
            parts.append(f'<section class="print-sec">{heading}')
        else:
            parts.append(heading)

    def _close_sec(level=2):
        if level == 2:
            parts.append("</section>")

    _sec("Resumen ejecutivo")
    kev_html = ""
    if C["kev"]:
        kev_html = (f'<div class="callout warn"><b>Atención:</b> {C["kev"]} dependencia(s) de producción con CVE '
                    f'en <b>CISA KEV</b> (explotación confirmada in-the-wild). Parchea antes de desplegar.</div>')
    filtered_html = ""
    if C["filtered"]:
        filtered_html = (f'<p>{C["filtered"]} de {len(findings)} hallazgo(s) fueron descartados por el triage '
                         f'(duplicados o refutados tras análisis) — quedan {max(len(findings)-C["filtered"],0)} reales.</p>')
    parts.append(
        f'<p><b>Veredicto:</b> Riesgo {esc(lvl)} — {esc(vtext)}</p>'
        f'<table><tbody>'
        f'<tr><td>Hallazgos totales</td><td>{len(findings)}</td></tr>'
        f'<tr><td>Cerrados</td><td>{C["closed"]}</td></tr>'
        f'<tr><td>Corregidos</td><td>{C["fixed"]}</td></tr>'
        f'<tr><td>En CISA KEV</td><td>{C["kev"]}</td></tr>'
        f'</tbody></table>{kev_html}{filtered_html}'
    )
    _close_sec()

    if mode == "technical":
        asf = L.get("attack_surface") or {}
        if asf:
            _sec("Superficie de ataque")
            for label, key in [("Entrypoints", "entrypoints"), ("Trust boundaries", "trust_boundaries"),
                                ("Zonas de alto riesgo", "high_risk_zones")]:
                v = asf.get(key)
                if isinstance(v, (list, tuple)) and v:
                    items = "".join(f"<li><code>{esc(i)}</code></li>" for i in v)
                    parts.append(f"<h3 class='subsec'>{esc(label)}</h3><ul>{items}</ul>")
            _close_sec()

        _sec("Hallazgos")
        parts.append(_print_findings_table_html(findings, "technical"))
        _close_sec()

        _sec("Diagnóstico por hallazgo")
        for f in sorted_findings(findings):
            parts.append(_print_finding_block_html(f))
        _close_sec()

        _sec("Plan de remediación")
        parts.append(_print_action_plan_html(findings))
        _close_sec()

        applied = [f for f in findings if (f.get("fix") or {}).get("applied")]
        if applied or any(f.get("verification") for f in findings):
            _sec("Resultados")
            if applied:
                parts.append("<h3 class='subsec'>Fixes aplicados</h3>")
                rows = "".join(
                    f"<tr><td><code>{esc(f.get('id'))}</code></td><td>{esc(joinlist((f.get('fix') or {}).get('files_touched')))}</td>"
                    f"<td>{esc((f.get('fix') or {}).get('root_cause','—'))}</td></tr>" for f in applied
                )
                parts.append(f"<table><thead><tr><th>ID</th><th>Archivos</th><th>Causa raíz</th></tr></thead><tbody>{rows}</tbody></table>")
            safe = [f for f in findings if isinstance(f, dict) and (is_truly_closed(f) or is_filtered(f))]
            parts.append("<h3 class='subsec'>Qué está seguro</h3>")
            if safe:
                items = "".join(
                    f"<li><code>{esc(f.get('id'))}</code> {esc(f.get('title',''))} — "
                    f"{esc((f.get('triage') or {}).get('rationale') or (f.get('verification') or {}).get('verdict') or STATUS_LABEL.get(f.get('status'), f.get('status')))}</li>"
                    for f in safe
                )
                parts.append(f"<ul>{items}</ul>")
            else:
                parts.append("<p><em>(sin elementos verificados como cerrados/filtrados todavía)</em></p>")
            _close_sec()

        _sec("Glosario")
        parts.append(_print_glossary_html())
        _close_sec()
    else:
        # ejecutivo: detalle completo solo P0/P1/KEV, el resto en tabla-resumen
        top = [f for f in sorted_findings(findings) if isinstance(f, dict)
               and (prio_of(f) in ("P0", "P1") or (f.get("intel") or {}).get("in_cisa_kev"))]
        rest = [f for f in sorted_findings(findings) if f not in top]

        _sec("Plan de acción")
        parts.append(_print_action_plan_html(findings))
        _close_sec()

        _sec("Casos prioritarios")
        if top:
            for f in top:
                parts.append(_print_finding_block_html(f))
        else:
            parts.append("<p><em>Sin hallazgos P0/P1/KEV en esta corrida.</em></p>")
        if rest:
            parts.append(f"<h3 class='subsec'>Resto de hallazgos ({len(rest)})</h3>")
            parts.append(_print_findings_table_html(rest, "executive"))
        _close_sec()

    toc_html = _print_toc_html(toc_entries)
    cover_html = _print_cover_html(L, mode, doc_title)
    return (f"<!doctype html><html lang='es'><head><meta charset='UTF-8'>"
            f"<title>{esc(doc_title)}</title><style>{_print_css(esc(doc_title))}</style></head>"
            f"<body>{cover_html}{toc_html}{''.join(parts)}</body></html>")


def try_formal_pdf(html_path, pdf_path):
    """Como try_pdf(), pero para el documento formal: PREFIERE weasyprint
    (motor de paginado real, soporta target-counter()/@page margin boxes que
    el documento usa para el indice y el encabezado/pie) en vez de Chrome
    (confirmado que headless Chrome ignora ambas features -- el indice
    quedaria sin numeros de pagina y el encabezado/pie sin contenido)."""
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
    nombre de la herramienta usada, o None si ninguno esta disponible.

    Orden de preferencia (importa, no es arbitrario): Chrome/Chromium/Edge
    headless PRIMERO, weasyprint y wkhtmltopdf como fallback. El CSS del informe
    usa Grid moderno (incl. repeat(auto-fit,minmax(...))) para las cards de
    diagnostico y los graficos: verificado visualmente que weasyprint 66 (motor
    de layout propio, no un navegador real) recorta o SUPERPONE ese contenido en
    vez de apilarlo -> perdida de datos real en el PDF (no en el HTML, que se ve
    bien). Un Chrome/Chromium/Edge real soporta el CSS completo y produce un PDF
    fiel al HTML interactivo. Si no hay ningun Chrome disponible, weasyprint /
    wkhtmltopdf siguen siendo mejor que nada — por eso el CSS de impresion tiene
    ademas un fallback de una sola columna para ese caso (ver @media print)."""
    apath = os.path.abspath(html_path)
    ppath = os.path.abspath(pdf_path)

    def _run(cmd):
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=180)
            return os.path.exists(ppath) and os.path.getsize(ppath) > 0
        except Exception:
            return False

    chrome = _find_chrome()
    if chrome:
        url = "file://" + apath
        if _run([chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={ppath}", url]):
            return os.path.basename(chrome)
        if _run([chrome, "--headless", "--disable-gpu", f"--print-to-pdf={ppath}", url]):
            return os.path.basename(chrome)
    if shutil.which("weasyprint") and _run(["weasyprint", apath, ppath]):
        return "weasyprint"
    # El informe es self-contained (SVG inline, sin recursos externos), asi que NO
    # se habilita --enable-local-file-access: contenido derivado del ledger no debe
    # poder cargar archivos locales al renderizar.
    if shutil.which("wkhtmltopdf") and _run(["wkhtmltopdf", "--quiet", apath, ppath]):
        return "wkhtmltopdf"
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

    # Retrocompat: si el ledger viene de una auditoria ya corrida con una version
    # anterior del plugin (schema viejo y/o ids de recoleccion VULN-101/VULN-209
    # sin canonicalizar), generar el informe lo deja al dia — no hace falta que
    # el usuario corra primero /vuln-hunter:resume ni sepa que `ledger.py migrate`
    # existe. migrate() es idempotente: si ya estaba al dia, no se re-escribe nada.
    raw_snapshot = json.dumps(L, sort_keys=True)
    before_ids = {f.get("id") for f in L.get("findings", []) if isinstance(f, dict)}
    L = _ledger.migrate(L)
    if json.dumps(L, sort_keys=True) != raw_snapshot:
        after_ids = {f.get("id") for f in L.get("findings", []) if isinstance(f, dict)}
        try:
            _ledger.atomic_write_json(ledger_path, L)
        except Exception as e:
            print(f"vuln-hunter: no se pudo re-escribir el ledger migrado ({e}), sigo con la version en memoria",
                  file=sys.stderr)
        else:
            renumbered = len(before_ids - after_ids)
            if renumbered:
                print(f"vuln-hunter: {renumbered} id(s) de una auditoria anterior canonicalizados "
                      f"(VULN-101 -> VULN-001...) en {ledger_path}")
            else:
                print(f"vuln-hunter: ledger migrado a schema {_ledger.CURRENT_SCHEMA} en {ledger_path}")

    # Contrato de nombres (fijo): B.md, B.html/B.pdf = tecnico (back-compat,
    # panel/app.jsx ya apunta aqui), B-executive.html/B-executive.pdf = nuevo.
    md_path = base + ".md"
    html_path = base + ".html"
    pdf_path = base + ".pdf"
    exec_html_path = base + "-executive.html"
    exec_pdf_path = base + "-executive.pdf"
    md_name = os.path.basename(md_path)
    pdf_name = os.path.basename(pdf_path)
    exec_pdf_name = os.path.basename(exec_pdf_path)
    tech_html_name = os.path.basename(html_path)

    os.makedirs(os.path.dirname(os.path.abspath(base)), exist_ok=True)

    md_text = build_md(L, ledger_path)
    with open(md_path, "w") as fh:
        fh.write(md_text)

    with open(html_path, "w") as fh:
        fh.write(build_html(md_text, False, md_name, pdf_name, L, mode="technical"))
    with open(exec_html_path, "w") as fh:
        fh.write(build_executive_html(L, md_name, exec_pdf_name, tech_html_name))

    # El PDF NO es un print-to-pdf del dashboard (.html): se genera desde un
    # documento formal APARTE (portada, indice con paginas reales, paleta
    # clara — ver build_formal_document_html), escrito a un archivo temporal
    # que se borra despues de convertir. El .html interactivo (oscuro, JS de
    # filtrado) es un producto distinto y no cambia.
    def _render_formal_pdf(mode, pdf_path):
        formal_html = build_formal_document_html(L, mode=mode)
        fd, tmp_path = tempfile.mkstemp(prefix=f".vuln-hunter-formal-{mode}-", suffix=".html")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(formal_html)
            return try_formal_pdf(tmp_path, pdf_path)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    tool = _render_formal_pdf("technical", pdf_path)
    if tool:
        with open(html_path, "w") as fh:
            fh.write(build_html(md_text, True, md_name, pdf_name, L, mode="technical"))

    tool_exec = _render_formal_pdf("executive", exec_pdf_path)
    if tool_exec:
        with open(exec_html_path, "w") as fh:
            fh.write(build_executive_html(L, md_name, exec_pdf_name, tech_html_name, has_pdf=True))

    n = len(L.get("findings", []))
    print(f"vuln-hunter: informe escrito ({n} hallazgos)")
    print(f"  markdown:          {md_path}")
    print(f"  html (técnico):    {html_path}  (dashboard interactivo, botón 'PDF' descarga el formal de abajo)")
    if tool:
        print(f"  pdf (técnico):     {pdf_path}  (documento formal — portada/índice/paleta clara, via {tool})")
    else:
        print("  pdf (técnico):     no se generó (sin weasyprint/wkhtmltopdf/Chrome). "
              "Abre el HTML y usa 'Descargar PDF' (Cmd/Ctrl+P → Guardar como PDF) como alternativa manual "
              "(esa imprime el dashboard oscuro, no el documento formal).")
    print(f"  html (ejecutivo):  {exec_html_path}")
    if tool_exec:
        print(f"  pdf (ejecutivo):   {exec_pdf_path}  (documento formal, via {tool_exec})")
    else:
        print("  pdf (ejecutivo):   no se generó (sin weasyprint/wkhtmltopdf/Chrome).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
