---
description: Cruza las dependencias de PRODUCCION con fuentes oficiales (OSV/NVD/KEV/EPSS) para detectar CVEs recientes y prevenir ransomware (delega en threat-intel-scout)
argument-hint: [ruta-lockfile-o-paquete] [--gate]
allowed-tools: Task, Read, Glob, Bash(osv-scanner:*), Bash(trivy:*), Bash(npm:*), Bash(dotnet:*), Bash(pip-audit:*), Bash(ls:*), Bash(cat:*), WebSearch, WebFetch, Bash(python3:*)
model: sonnet
---

# vuln-hunter: vigilancia de amenazas en dependencias

## Contexto
- Lockfiles presentes: !`ls -1 *.lock package-lock.json pnpm-lock.yaml poetry.lock uv.lock packages.lock.json requirements.txt 2>/dev/null | head -20`
- Stacks: !`cat .vuln-hunter/stacks.json 2>/dev/null || echo "ejecuta /vuln-hunter:detect primero"`

## Regla
Solo se consultan fuentes oficiales (OSV.dev, NVD, GitHub Advisories, CISA KEV,
FIRST EPSS, MSRC, advisories de Django/Node/Next.js). No se buscan ni ejecutan
exploits. Enfoque defensivo de prevencion y parcheo.

## Tarea
Lanza el subagente **threat-intel-scout** sobre **$ARGUMENTS** (o todos los
lockfiles de produccion si esta vacio). El agente:
1. Inventaria las dependencias de PRODUCCION (omitiendo dev).
2. Cruza cada paquete+version exacta con OSV.dev y enriquece con NVD/EPSS/KEV.
3. Prioriza con SSVC; marca como bloqueantes los CVE en KEV o con EPSS alto.
4. Escribe los hallazgos en el ledger (`findings[].intel`, ids VULN-2xx) segun el
   skill ledger-contract.

## Modo gate (`--gate`)
Si se pasa `--gate`, ademas de reportar, MATERIALIZA el gate de despliegue de
forma DETERMINISTA a partir del ledger (no a mano): corre

```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/deploy-gate.py .vuln-hunter/ledger.json
```

Ese script DERIVA `.vuln-hunter/deploy-blocked` del ledger: lo escribe (con los
VULN-ids bloqueantes) si hay alguna dependencia de PRODUCCION abierta con CVE en
CISA KEV o EPSS alto, y lo elimina si no hay ninguna. Devuelve **APTO_PARA_DESPLIEGUE**
o **DESPLIEGUE_BLOQUEADO**. El hook `guard-commit-and-exec.py` solo LEE ese archivo,
asi que la decision queda atada al ledger y no a que el LLM lo escriba a mano.
NO crees ni borres `.vuln-hunter/deploy-blocked` manualmente: deja que el script
lo derive.

## Presentacion
El agente presenta su resultado con el skill `agent-presentation` (cabecera con
icono, resumen de 3 lineas, tabla con emoji-semaforo, barra de progreso) y cierra
con el bloque "▶ Siguiente paso". Si hay KEV/EPSS alto, recomienda `/vuln-hunter:triage` y avisa del bloqueo de deploy.

## Eventos de actividad (panel)
Emite eventos al timeline del panel en los bordes de esta etapa:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=INTEL agent=threat-intel-scout
# ... corre el subagente threat-intel-scout ...
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=INTEL agent=threat-intel-scout summary="<resumen corto>"
```
Por cada finding NUEVO agregado al ledger:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py finding:new id=<VULN-2xx> title="<titulo>" source=sca
```

## Canonicaliza los ids (antes del `stage:end`)
`VULN-2xx` es el rango interno de recoleccion, no el id final (ver skill
`ledger-contract`). En cuanto el threat-intel-scout termine de escribir sus
findings, corre (determinista, idempotente):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py migrate .vuln-hunter/ledger.json
```
Asi el panel y el dashboard muestran `VULN-001`, `VULN-002`... desde ya, aunque
`/vuln-hunter:watch` se corra suelto (sin pasar por `/hunt`).
