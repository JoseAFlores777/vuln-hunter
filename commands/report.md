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
Produce CINCO artefactos (version tecnica completa + version ejecutiva
condensada, mas el Markdown fuente), descargables desde el panel:
- `.vuln-hunter/audit-report.md` — Markdown formal en 3 secciones (fuente de
  verdad / volcado de datos).
- `.vuln-hunter/audit-report.html` — version TECNICA imprimible: detalle
  diagnostico completo por hallazgo, boton **Descargar PDF**
  (Cmd/Ctrl+P -> Guardar como PDF), enlaces a .md y .pdf, y acceso al resumen
  ejecutivo.
- `.vuln-hunter/audit-report.pdf` — PDF de la version tecnica, solo si hay
  convertidor disponible (weasyprint / wkhtmltopdf / Chrome|Chromium|Edge
  headless). Si no, se omite y se usa el boton del HTML.
- `.vuln-hunter/audit-report-executive.html` — version EJECUTIVA condensada:
  veredicto, KPIs, graficos, solo los hallazgos de mayor riesgo (P0/P1/KEV) y
  plan de accion, con enlace de vuelta a la version tecnica para el detalle
  completo.
- `.vuln-hunter/audit-report-executive.pdf` — PDF de la version ejecutiva,
  misma logica de convertidor que el PDF tecnico.

El informe tiene tres secciones:
1. **Auditoria y diagnostico** — superficie de ataque, tabla de hallazgos y
   diagnostico por hallazgo (SAST, intel/CVEs, explotabilidad, triage).
2. **Estrategia y plan de remediacion** — plan, enfoque de fix por hallazgo y
   Action Plan priorizado (Inmediato / Esta semana / Este mes).
3. **Resultados** — fixes aplicados, verificacion, "Que esta seguro" y estado final.

## Archiva la corrida al historial (automatico)
Tras generar el informe, snapshotea esta corrida al historial LOCAL para que el
panel pueda cargarla despues (modo solo-lectura):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/archive-run.py .vuln-hunter/ledger.json
```
Esto copia el ledger + activity + el informe a `.vuln-hunter/history/<id>/` y
actualiza `history/index.json`. Es idempotente (re-archivar la misma corrida la
sobreescribe). El historial es LOCAL (`.vuln-hunter/` esta en .gitignore): no se
commitea, asi que los detalles de hallazgos no se publican en git.

Luego:
1. Confirma las rutas generadas y un resumen de conteos (P0..P3, en KEV).
2. Recuerda al usuario que puede **descargarlo desde el panel** (botones
   "Informe" y "Resumen ejecutivo") o abrir `.vuln-hunter/audit-report.html`
   (tecnico) / `.vuln-hunter/audit-report-executive.html` (ejecutivo) y usar
   "Descargar PDF"; ambos HTML tienen un enlace cruzado al otro. El panel
   tiene un **selector de corridas** para revisar auditorias pasadas.

Todo es reproducible: re-generarlo con el mismo ledger da el mismo resultado.

## Retrocompatibilidad (auditorias de una version anterior del plugin)
`report.py` migra y canonicaliza el ledger EN SITIO antes de generar (mismo
`ledger.py migrate` de siempre, ver skill `ledger-contract`): si `.vuln-hunter/
ledger.json` viene de una auditoria corrida con una version anterior (ids de
recoleccion `VULN-101`/`VULN-209` sin canonicalizar), no hace falta correr nada
mas primero — al pedir el informe, el ledger en disco queda con ids `VULN-001`,
`VULN-002`... (el id viejo se preserva en `origin_id`). Es idempotente: si el
ledger ya estaba al dia, no cambia nada.
