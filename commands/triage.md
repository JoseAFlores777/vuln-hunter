---
description: Prioriza los hallazgos confirmados con CVSS+EPSS+KEV y produce el ledger final (delega en triage-judge)
argument-hint:
allowed-tools: Task, Read, Grep, Glob, Bash(python3:*)
model: sonnet
---

# Triage y priorizacion

## Tarea
Lanza el subagente **triage-judge** sobre los hallazgos confirmados. Deduplica
por archivo+CWE, filtra confianza <8 (a lista de revision humana), puntua con
CVSS v4.0/v3.1 + EPSS + CISA KEV y devuelve el vulnerability ledger priorizado
(P0/P1/P2/P3).

## Presentacion
El agente presenta su resultado con el skill `agent-presentation` (cabecera con
icono, resumen de 3 lineas, tabla con emoji-semaforo, barra de progreso) y cierra
con el bloque "▶ Siguiente paso". Tras priorizar, recomienda `/vuln-hunter:plan`.

## Eventos de actividad (panel)
Emite eventos al timeline del panel en los bordes de esta etapa:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=TRIAGE agent=triage-judge
# ... corre el subagente triage-judge ...
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=TRIAGE agent=triage-judge summary="<resumen corto>"
```
Si escribes `.vuln-hunter/deploy-blocked`:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py deploy:blocked reason="<motivo>"
```
