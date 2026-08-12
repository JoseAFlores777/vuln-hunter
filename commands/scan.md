---
description: Escanea con SAST+SCA por stack y normaliza hallazgos a SARIF + OWASP Top 10 (delega en sast-analyst)
argument-hint: [ruta-o-paquete]
allowed-tools: Task, Read, Grep, Glob, Bash(cat:*), Bash(python3:*)
model: sonnet
---

# Escaneo SAST/SCA

## Scope
- Stacks: !`cat .vuln-hunter/stacks.json 2>/dev/null || echo "ejecuta /vuln-hunter:detect"`

## Tarea
Lanza el subagente **sast-analyst** sobre **$ARGUMENTS** (o todos los paquetes si
esta vacio). El agente corre las herramientas que correspondan al stack, traza
flujos source->sink, asigna confianza 1-10 y mapea a OWASP 2021/2025 + CWE.
Devuelve el ledger preliminar de hipotesis.

## Presentacion
El agente presenta su resultado con el skill `agent-presentation` (cabecera con
icono, resumen de 3 lineas, tabla con emoji-semaforo, barra de progreso) y cierra
con el bloque "▶ Siguiente paso". Tras el SAST, recomienda `/vuln-hunter:redteam all`.

## Eventos de actividad (panel)
Emite eventos al timeline del panel en los bordes de esta etapa:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=SAST agent=sast-analyst
# ... corre el subagente sast-analyst ...
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=SAST agent=sast-analyst summary="<N findings>"
```
Por cada finding NUEVO agregado al ledger:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py finding:new id=<VULN-1xx> title="<titulo>" source=sast
```

## Canonicaliza los ids (antes del `stage:end`)
`VULN-1xx` es el rango interno de recoleccion, no el id final (ver skill
`ledger-contract`). En cuanto el sast-analyst termine de escribir sus findings,
corre (determinista, idempotente):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py migrate .vuln-hunter/ledger.json
```
Asi el panel y el dashboard muestran `VULN-001`, `VULN-002`... desde ya, aunque
`/vuln-hunter:scan` se corra suelto (sin pasar por `/hunt`).
