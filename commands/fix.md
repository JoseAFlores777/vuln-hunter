---
description: Aplica los fixes de causa raiz en una branch vuln-hunter/* (delega en appsec-fixer). No commitea.
argument-hint: [VULN-NNN ... | all]
allowed-tools: Task, Read, Grep, Glob, Bash(git checkout:*), Bash(git branch:*), Bash(git status:*), Bash(python3:*)
model: opus
---

# Aplicar fixes (sin commit)

## Pre-requisito
Trabaja en branch `vuln-hunter/*`. Si estas en otra branch, el appsec-fixer
creara `vuln-hunter/fix-<...>`.

## Tarea
Lanza el subagente **appsec-fixer** para **$ARGUMENTS** (uno o varios VULN-ids
separados por espacio, o `all`). Aplica fixes
de causa raiz al working tree segun el plan, mapeando cada uno a su requisito
ASVS. NO commitea: deja los cambios listos para revision y para /vuln-hunter:patch.

## Presentacion
El agente presenta su resultado con el skill `agent-presentation` (cabecera con
icono, resumen de 3 lineas, tabla con emoji-semaforo, barra de progreso) y cierra
con el bloque "▶ Siguiente paso". Tras aplicar fixes, recomienda `/vuln-hunter:patch`.

## Eventos de actividad (panel)
Emite eventos al timeline del panel en los bordes de esta etapa:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=FIX agent=appsec-fixer
# ... corre el subagente appsec-fixer ...
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=FIX agent=appsec-fixer summary="<resumen corto>"
```
