---
description: Genera el informe formal de auditoria (Markdown + HTML imprimible + PDF) desde el ledger, con mapeo OWASP, plan y resultados
argument-hint: [base-salida]
allowed-tools: Bash(python3:*), Read
model: sonnet
---

# Informe formal de auditoria

## Tarea
Genera el informe a partir de `.vuln-hunter/ledger.json` con el generador
DETERMINISTA (no inventes datos; todo sale del ledger):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/report.py .vuln-hunter/ledger.json ${1:-.vuln-hunter/audit-report}
```
Produce TRES artefactos con el mismo contenido, descargables desde el panel:
- `.vuln-hunter/audit-report.md` — Markdown formal en 3 secciones.
- `.vuln-hunter/audit-report.html` — imprimible; boton **Descargar PDF**
  (Cmd/Ctrl+P -> Guardar como PDF) ademas de enlaces a .md y .pdf.
- `.vuln-hunter/audit-report.pdf` — solo si hay convertidor disponible
  (weasyprint / wkhtmltopdf / Chrome|Chromium|Edge headless). Si no, se omite y se
  usa el boton del HTML.

El informe tiene tres secciones:
1. **Auditoria y diagnostico** — superficie de ataque, tabla de hallazgos y
   diagnostico por hallazgo (SAST, intel/CVEs, explotabilidad, triage).
2. **Estrategia y plan de remediacion** — plan, enfoque de fix por hallazgo y
   Action Plan priorizado (Inmediato / Esta semana / Este mes).
3. **Resultados** — fixes aplicados, verificacion, "Que esta seguro" y estado final.

Luego:
1. Confirma las rutas generadas y un resumen de conteos (P0..P3, en KEV).
2. Recuerda al usuario que puede **descargarlo desde el panel** (boton "Informe")
   o abrir `.vuln-hunter/audit-report.html` y usar "Descargar PDF".

Todo es reproducible: re-generarlo con el mismo ledger da el mismo resultado.
