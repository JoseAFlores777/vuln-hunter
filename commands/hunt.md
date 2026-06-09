---
description: Orquesta el flujo completo de seguridad recon -> scan(SAST) + watch(SCA) -> red-team -> triage -> plan -> fix -> patch -> verify sobre el repo o un paquete
argument-hint: [ruta-o-paquete] [--solo-deteccion] [--dry-run]
allowed-tools: Task, Read, Grep, Glob, Bash(git:*), Bash(mkdir:*), Write, TodoWrite, WebSearch, WebFetch
model: opus
---

# vuln-hunter: caceria completa

## Contexto del repositorio
- Branch actual: !`git branch --show-current 2>/dev/null || echo "(sin git)"`
- Stacks detectados: !`cat .vuln-hunter/stacks.json 2>/dev/null || echo "ejecuta /vuln-hunter:detect primero"`
- Estado git: !`git status --short 2>/dev/null | head -20`

## Reglas de esta sesion
Trabajo DEFENSIVO y AUTORIZADO del codigo propio. El red-team produce solo PoCs
conceptuales; el threat-intel-scout solo LEE fuentes oficiales; el patcher nunca
commitea sin aprobacion humana por hash del diff. Lo imponen agentes y hooks.

## Estado compartido (ledger)
Todos los agentes leen y escriben `.vuln-hunter/ledger.json` segun el skill
**ledger-contract**. Inicializa el ledger si no existe. No se pasa prosa entre
agentes: se pasa el ledger.

## Modos
- `--dry-run`: ejecuta deteccion, SAST, SCA, red-team y triage, y PRESENTA el
  plan, pero NO aplica fixes, NO commitea y NO toca el working tree. Ideal para
  un primer pase seguro.
- `--solo-deteccion`: como dry-run pero se detiene tras el triage (sin plan/fix).

## Orquestacion (subagentes via Task, en orden)
1. **recon-cartographer** -> escribe `attack_surface` en el ledger (bloquea).
2. En paralelo:
   - **sast-analyst** -> SAST de CODIGO propio -> `findings[].sast` (VULN-1xx).
   - **threat-intel-scout** -> SCA de DEPENDENCIAS de produccion, cruce con
     OSV/NVD/KEV/EPSS -> `findings[].intel` (VULN-2xx). Marca bloqueantes de deploy.
3. **redteam-whitehat** -> confirma explotabilidad (PoC conceptual) -> `exploitability`.
4. **triage-judge** -> consolida, deduplica, prioriza (CVSS+EPSS+KEV) -> `triage`.
   Si hay un CVE en KEV en dependencia de produccion, escribe el motivo en
   `.vuln-hunter/deploy-blocked` (lo consume el gate del hook).
5. **PLAN** (`/vuln-hunter:plan`) -> plan de remediacion (superpowers si esta;
   si no, plan propio). Guarda `plan_ref`.
6. Si NO es dry-run NI solo-deteccion:
   - **appsec-fixer** -> fixes de causa raiz en branch `vuln-hunter/*` -> `fix`.
   - **/vuln-hunter:patch** -> diffs + aprobacion humana por hash -> commit.
   - **verify-engineer** -> confirma cierre sin regresion -> `verification`.

## Salida final
Informe consolidado desde el ledger: vulnerability ledger, plan, fixes (si
aplica), verificacion, seccion "Que esta seguro" y Action Plan priorizado
(Inmediato / Esta semana / Este mes). Sugiere `/vuln-hunter:report` para el HTML.

## Visualizacion entre pasos (importante para la UX)
Tras CADA agente del flujo, muestra el dashboard de estado para que el usuario
vea el progreso y el siguiente paso:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/status.py .vuln-hunter/ledger.json
```
Y respeta el skill `agent-presentation`: cada agente abre con su cabecera
(icono+etiqueta), resumen de 3 lineas, tabla con emoji-semaforo, barra de
progreso y bloque "▶ Siguiente paso". Cuando necesites una decision del usuario,
usa el formato de pregunta unica enumerada del skill (o la herramienta de
opciones interactivas si esta disponible) — nunca mas de una pregunta a la vez.
