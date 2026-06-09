---
description: Orquesta el flujo completo de seguridad recon -> scan(SAST) + watch(SCA) -> red-team -> triage -> plan -> fix -> patch -> verify sobre el repo o un paquete
argument-hint: [ruta-o-paquete] [--solo-deteccion] [--dry-run] [--no-panel]
allowed-tools: Task, Read, Grep, Glob, Bash(git:*), Bash(mkdir:*), Bash(python3:*), Bash(bash:*), Write, TodoWrite, WebSearch, WebFetch
model: opus
---

# vuln-hunter: caceria completa

## Contexto del repositorio
- Branch actual: !`git branch --show-current 2>/dev/null || echo "(sin git)"`
- Stacks detectados: !`cat .vuln-hunter/stacks.json 2>/dev/null || echo "ejecuta /vuln-hunter:detect primero"`
- Estado git: !`git status --short 2>/dev/null | head -20`
- Auditoria previa: !`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py resume .vuln-hunter/ledger.json 2>/dev/null || echo "ninguna (run nuevo)"`

## Reglas de esta sesion
Trabajo DEFENSIVO y AUTORIZADO del codigo propio. El red-team produce solo PoCs
conceptuales; el threat-intel-scout solo LEE fuentes oficiales; el patcher nunca
commitea sin aprobacion humana por hash del diff. Lo imponen agentes y hooks.

## Estado compartido (ledger)
Todos los agentes leen y escriben `.vuln-hunter/ledger.json` segun el skill
**ledger-contract**. Inicializa el ledger si no existe. No se pasa prosa entre
agentes: se pasa el ledger.

## Paso 0: panel vivo (LO PRIMERO, antes de todo lo demas)
Antes de la pregunta de reanudacion y de cualquier subagente o evento, levanta el
panel y abrelo en el navegador para que el usuario vea el proceso DESDE EL
PRINCIPIO:
```
bash ${CLAUDE_PLUGIN_ROOT}/scripts/serve-panel.sh
```
- Corre esto UNA sola vez, al inicio (antes de `run:start`).
- Es idempotente: si el panel ya esta corriendo, no abre otra pestana.
- Arranca vacio y se va llenando solo (polling 2s) conforme emites los eventos de
  actividad de abajo: el usuario ve aparecer recon, SAST, hallazgos, etc. en vivo.
- Si el usuario paso `--no-panel`, OMITE este paso (no levantes el panel).

## Reanudacion y retrocompatibilidad (importante)
Si YA existe `.vuln-hunter/ledger.json` (ver "Auditoria previa" arriba), NO
reinicies desde cero:
1. Migra el ledger al schema actual (preserva findings y estado, es retrocompat):
   ```
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py migrate .vuln-hunter/ledger.json
   ```
2. Mira `next_command` de `ledger.py resume`: es donde quedo el run anterior.
3. Pregunta al usuario (una sola pregunta) si quiere **reanudar** desde ahi o
   **empezar de cero**. Si reanuda, continua la cadena desde `next_command` sin
   repetir etapas completas (equivalente a `/vuln-hunter:resume`).
Si no existe ledger, es un run nuevo: sigue el flujo completo de abajo.

## Modos
- `--dry-run`: ejecuta deteccion, SAST, SCA, red-team y triage, y PRESENTA el
  plan, pero NO aplica fixes, NO commitea y NO toca el working tree. Ideal para
  un primer pase seguro.
- `--solo-deteccion`: como dry-run pero se detiene tras el triage (sin plan/fix).
- `--no-panel`: no levanta ni abre el panel vivo (util en CI/headless). Por
  defecto el panel se abre solo al inicio (ver Paso 0).

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
(Inmediato / Esta semana / Este mes).

### Informe formal descargable (AUTOMATICO al terminar)
Cuando el flujo termina (tras verify, o tras triage si es dry-run/solo-deteccion),
GENERA el informe formal automaticamente — no esperes a que el usuario lo pida:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/report.py .vuln-hunter/ledger.json .vuln-hunter/audit-report
```
Esto escribe `.vuln-hunter/audit-report.md`, `.html` y (si hay convertidor) `.pdf`,
con las 3 secciones: auditoria/diagnostico, estrategia/plan y resultados. Luego
dile al usuario que puede **descargarlo desde el panel** (boton "Informe") o abrir
`.vuln-hunter/audit-report.html` y usar "Descargar PDF".

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

## Eventos de actividad (alimentan el panel vivo)
Ademas del dashboard de texto, emite eventos al timeline del panel con el helper
`scripts/activity.py`. Hazlo en los BORDES de cada etapa (no dentro del agente):

- Al iniciar TODO el flujo, una vez (el panel del Paso 0 ya esta abierto y
  esperando estos eventos):
  ```
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py run:start scope="<scope o repo>"
  ```
- Antes de lanzar cada subagente: `stage:start`; al volver: `stage:end`. Usa estas
  claves de etapa EXACTAS y su agente:
  | stage | agent |
  |---|---|
  | RECON | recon-cartographer |
  | SAST | sast-analyst |
  | INTEL | threat-intel-scout |
  | RED-TEAM | redteam-whitehat |
  | TRIAGE | triage-judge |
  | FIX | appsec-fixer |
  | VERIFY | verify-engineer |

  Ejemplo:
  ```
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=SAST agent=sast-analyst
  # ... corre el subagente ...
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=SAST agent=sast-analyst summary="<N findings>"
  ```
- Por cada finding NUEVO que un agente agregue al ledger:
  ```
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py finding:new id=VULN-101 title="<titulo>" source=sast
  ```
- Si el triage escribe `.vuln-hunter/deploy-blocked`:
  ```
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py deploy:blocked reason="<paquete@version CVE en KEV>"
  ```
- Las etapas `detect` y `plan` no tienen subagente; emite igual `stage:start`/
  `stage:end` con `stage=detect` y `stage=plan`.
- Al terminar TODO el flujo, una vez:
  ```
  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py run:done
  ```

El panel ya quedo abierto desde el Paso 0; el usuario vio todo el proceso en vivo.
Si lo cerro, puede reabrirlo con `/vuln-hunter:panel`.
