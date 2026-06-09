---
description: Genera un informe de auditoria (HTML reproducible) a partir del ledger, con mapeo OWASP y Action Plan
argument-hint: [ruta-salida.html]
allowed-tools: Bash(python3:*), Read
model: sonnet
---

# Informe de auditoria

## Tarea
Genera el informe a partir de `.vuln-hunter/ledger.json` ejecutando el generador
DETERMINISTA (no inventes datos; el informe sale del ledger):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/report.py .vuln-hunter/ledger.json ${1:-.vuln-hunter/report.html}
```
Luego:
1. Confirma la ruta del HTML generado y un resumen de conteos (P0..P3, en KEV).
2. Si el usuario lo pide, complementa con un Action Plan en prosa
   (Inmediato / Esta semana / Este mes) derivado del mismo ledger, y una seccion
   "Que esta seguro" (areas revisadas sin hallazgos).

El HTML es reproducible: re-generarlo con el mismo ledger da el mismo resultado.
