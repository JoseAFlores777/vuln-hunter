---
description: Detecta los stacks del proyecto/monorepo y guarda el scope en .vuln-hunter/stacks.json
argument-hint: [ruta-raiz] [--no-panel]
allowed-tools: Read, Glob, Bash(find:*), Bash(mkdir:*), Bash(python3:*), Bash(bash:*), Write
model: sonnet
---

# Deteccion de stack del monorepo

## Marcadores presentes
- Django/Python: !`find ${1:-.} -maxdepth 3 -name "manage.py" -o -name "requirements.txt" -o -name "pyproject.toml" 2>/dev/null | head -20`
- Next.js/React/TS: !`find ${1:-.} -maxdepth 3 -name "next.config.*" -o -name "package.json" 2>/dev/null | head -20`
- .NET/C#: !`find ${1:-.} -maxdepth 4 -name "*.csproj" -o -name "*.sln" 2>/dev/null | head -20`
- Angular: !`find ${1:-.} -maxdepth 3 -name "angular.json" 2>/dev/null | head -20`

## Tarea
Usa el skill **stack-detector** para clasificar cada paquete/subproyecto del
monorepo por stack y delimitar su subarbol (scoping por paquete). Escribe el
resultado en `.vuln-hunter/stacks.json` con esta forma:
```json
{ "packages": [ { "path": "apps/example-app", "stack": "django", "scanners": ["bandit","semgrep:p/django","pip-audit","gitleaks"] } ] }
```
Esto permite que /vuln-hunter:scan corra solo las herramientas correctas en cada
subarbol y evita falsos positivos cross-paquete.

## Presentacion
El agente presenta su resultado con el skill `agent-presentation` (cabecera con
icono, resumen de 3 lineas, tabla con emoji-semaforo, barra de progreso) y cierra
con el bloque "▶ Siguiente paso". Tras detectar, recomienda `/vuln-hunter:scan` + `/vuln-hunter:watch`.

## Paso 0: panel vivo (LO PRIMERO, antes de detectar)
Como `detect` suele ser el inicio del flujo, levanta el panel y abrelo en el
navegador ANTES de nada, para que el usuario vea el proceso desde el principio:
```
bash ${CLAUDE_PLUGIN_ROOT}/scripts/serve-panel.sh
```
- Una sola vez, al inicio. Idempotente: si ya esta corriendo, no reabre.
- Si el usuario paso `--no-panel`, OMITE este paso.

## Eventos de actividad (panel)
Con el panel ya abierto (Paso 0), al empezar la deteccion emite:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py run:start scope="<scope o repo completo>"
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=detect
```
Al terminar, tras escribir `.vuln-hunter/stacks.json`:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=detect summary="<stacks detectados>"
```
