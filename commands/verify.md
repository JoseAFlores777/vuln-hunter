---
description: Verifica que los fixes cierran las vulnerabilidades sin regresion (delega en verify-engineer)
argument-hint: [VULN-NNN | all]
allowed-tools: Task, Read, Grep, Glob, Bash(git diff:*), Bash(python3:*)
model: sonnet
---

# Verificacion de cierre

## Tarea
Lanza el subagente **verify-engineer** sobre **$ARGUMENTS** (o `all`). Re-ejecuta
el escaner que detecto cada VULN para confirmar que el hallazgo desaparece, corre
la suite de tests para descartar regresion, re-escanea el diff por nuevas vulns y
devuelve veredicto CERRADO / NO_CERRADO / REGRESION por cada VULN. Si hay
regresion o sigue abierta, devuelve al appsec-fixer.

## Presentacion
El agente presenta su resultado con el skill `agent-presentation` (cabecera con
icono, resumen de 3 lineas, tabla con emoji-semaforo, barra de progreso) y cierra
con el bloque "▶ Siguiente paso". Tras verificar, recomienda `/vuln-hunter:report` (o `fix` si quedo abierto).

## Eventos de actividad (panel)
Emite eventos al timeline del panel en los bordes de esta etapa:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=VERIFY agent=verify-engineer
# ... corre el subagente verify-engineer ...
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=VERIFY agent=verify-engineer summary="<resumen corto>"
```
