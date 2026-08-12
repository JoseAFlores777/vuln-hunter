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

## Trazabilidad (ADR 0002)
El fixer solo toca lo atado a un VULN-id del plan. Un bump de dependencia exige un
finding SCA; si falta, el fixer invoca threat-intel-scout al vuelo en vez de subir
la dep en silencio. Nada se cambia sin un hallazgo que lo explique.

Si se creo un finding nuevo al vuelo, ese finding SIEMPRE nace con un id de
recoleccion (`VULN-2xx`, ver skill `ledger-contract`), no uno canonico: corre de
nuevo `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py migrate .vuln-hunter/ledger.json`
antes de seguir (es incremental — no toca los ids ya canonicalizados, solo le
asigna el siguiente `VULN-0NN` libre al finding nuevo).

## Presentacion
El agente presenta su resultado con el skill `agent-presentation` (cabecera con
icono, resumen de 3 lineas, tabla con emoji-semaforo, barra de progreso) y cierra
con el bloque "▶ Siguiente paso". Tras aplicar fixes, recomienda `/vuln-hunter:patch`.

## Eventos de actividad (panel)
Emite eventos al timeline del panel en los bordes de esta etapa:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=FIX agent=appsec-fixer
# Al EMPEZAR cada VULN (cambio de estado visible: "trabajandose ahora"):
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py finding:state id=VULN-NNN state=fixing
# ... el appsec-fixer aplica el fix y pone status:fixed en el ledger ...
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py finding:state id=VULN-NNN state=fixed
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=FIX agent=appsec-fixer summary="<resumen corto>"
```
