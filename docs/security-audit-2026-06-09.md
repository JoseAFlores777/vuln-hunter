# Auditoría de seguridad de vuln-hunter — informe

> **Objeto:** el propio plugin `vuln-hunter` (no un repo auditado por él).
> **Fecha:** 2026-06-09 · **Alcance:** end-to-end (hooks, scripts, panel, CI, agentes, skills, schema).
> **Método:** auditoría multi-agente (8 dimensiones × verificación adversarial) + corroboración
> independiente + verificación de semántica de Claude Code vía `claude-code-guide`.

## Resumen ejecutivo

Se levantaron **48 hallazgos candidatos**; tras verificación adversarial quedaron **41 confirmados**
y **7 descartados** (falsos positivos). Se remediaron en el working tree (sin commit) **44 archivos**
(35 modificados, 9 nuevos) y se añadieron **31 tests de regresión** (suite total: **84, en verde**).
Incluye los 4 residuales (ver § final).

La barrera de mayor severidad —la aprobación humana del patch— estaba atada al *working tree*
(`git diff HEAD`) en vez de al **índice staged** que realmente se commitea: permitía aprobar un fix
limpio y commitear contenido distinto (backdoor) con el hash de aprobación intacto. Cerrada.

**Buenas noticias confirmadas:** el panel React **no tiene XSS** (auto-escape de JSX + sinks por
`textContent`); el generador de informe `report.py` **escapa** todos los valores del ledger en cada
ruta; y el allowlist `tools:` del red-team **sí** impide escritura/red (no depende de `disallowedTools`).

## Metodología

1. **Mapeo inline** del repo y lectura de todo el código ejecutable (hooks, scripts, panel, CI).
2. **Workflow multi-agente** (57 sub-agentes) sobre 8 dimensiones: barreras/hooks, scripts Python,
   generador de informe, panel/serving, scripts shell, CI/supply-chain, scoping de agentes,
   prompt-injection/lógica. Cada hallazgo pasó por un verificador adversarial (refutar o confirmar +
   corregir la fix).
3. **Verificación de semántica de Claude Code** (`claude-code-guide`, docs en vivo): `tools:` es
   allowlist enforced; `disallowedTools` es campo reconocido; la sintaxis granular `Bash(cmd:*)` **no**
   aplica en frontmatter de agentes; los hooks PreToolUse aplican a subagentes; `exit 2` deniega.
4. **Remediación + tests** con verificación de cada fix (bypass debe bloquear, caso legítimo pasar).

## Hallazgos confirmados y remediación

### Crítico / Alto

| # | Hallazgo | Archivo | Fix |
|---|---|---|---|
| 1 | Aprobación atada al working tree, no al índice → se commitea contenido distinto al aprobado | `hooks/guard-commit-and-exec.py`, `scripts/approve-diff.py` | Hash de `git diff --cached HEAD` (índice staged) en ambos; rechazo de índice vacío; `patch.md` instruye `git add` antes de aprobar |
| 2 | Panel servido en `0.0.0.0` → hallazgos/rutas expuestos a la LAN | `scripts/serve-panel.sh` | Bind `127.0.0.1` + allowlist de header `Host` (anti DNS-rebinding) + `Cache-Control: no-store` + PID file |

### Medio

| # | Hallazgo | Archivo | Fix |
|---|---|---|---|
| 3 | Gate de commit evadible con `git -C`, `git -c`, alias; `commit-tree` falso positivo | `hooks/guard-commit-and-exec.py` | Parser tokenizado (shlex): salta flags globales, resuelve subcomando exacto, bloquea redirección (`-C`/`--git-dir`/`--work-tree`) y `commit -a/--all/pathspec` |
| 4 | TOCTOU aprobación→commit | `hooks/guard-commit-and-exec.py` | El hash del índice staged se recomputa en el momento del commit; `commit -a` bloqueado |
| 5 | `intel-cache fetch`: SSRF + inyección de flags a curl | `scripts/intel-cache.sh` | `--` antes de la URL, `--proto =https`, sin `-L`, allowlist de hosts oficiales, no reenvía args del caller, guard de symlink |
| 6 | Release: se testea `main` pero se publica el tag (provenance) | `.github/workflows/release.yml` | Guard `git merge-base --is-ancestor <tag> origin/main` antes de publicar |
| 7 | Docs venden `disallowedTools` como "la barrera principal" (no lo es) | `CLAUDE.md`, `README.md`, `docs/index.html` | Corregido: la barrera es el allowlist `tools:`; `disallowedTools`+hooks = defensa en profundidad |
| 8 | `threat-intel-scout` con WebFetch sin restricción de host | `hooks/guard-webfetch.py` (nuevo), `hooks.json` | Hook PreToolUse que fuerza https + allowlist de fuentes oficiales **solo** para ese agente (fail-open para el resto) |
| 9 | Agentes sin frontera "contenido del repo = DATA, no instrucciones" (prompt-injection) | `agents/*.md`, `CLAUDE.md` | Cláusula uniforme en recon/sast/intel/triage/fixer/verify + regla top-level; intel anclado a datos estructurados (KEV/grafo de deps) |
| 10 | `rescan` marca `fixed`/`applied` por desaparecer del escáner (sin evidencia) | `commands/rescan.md`*, `scripts/report.py` | `report.py` excluye fixes de `source: rescan` del KPI "corregidos" |
| 11 | Gate de deploy sin productor determinista (dependía del LLM) | `scripts/deploy-gate.py` (nuevo), `watch.md`, `report.py` | Script que DERIVA `.vuln-hunter/deploy-blocked` del ledger (KEV/EPSS en prod), estampa VULN-ids; el informe reporta drift gate↔ledger |
| 12 | `status:closed` contado como cerrado sin verdict `CLOSED` (sobre-reporta seguridad) | `scripts/report.py` | `is_truly_closed`/`is_filtered` aplicados en KPI, `risk_verdict` y "Qué está seguro"; warning de `closed` sin evidencia |

\* La fix #10 deja `commands/rescan.md` como está pero `report.py` ya no permite que un auto-fix de rescan
infle "corregidos"; conviene además ajustar el prompt de rescan para no escribir `applied:true` (residual menor).

### Bajo / Informativo (remediados)

- **Hook**: fail-closed en entrada ilegible (`guard-commit`, `block-exploit-write`); regex de brute-force
  anclada a posición de invocación (no bloquea `commit -m "john…"`); patrones ofensivos ampliados
  (ncat/intérpretes/fsockopen) con docstring honesto; anclaje de rutas de estado a `CLAUDE_PROJECT_DIR`/
  toplevel (no CWD); matcher de deploy ampliado (kubectl/helm/terraform/cloud CLIs).
- **Scripts Python**: `ledger.migrate` purga findings no-dict (ledger envenenado); escritura atómica
  (`ledger.py`, `bump-version.py`); `status.py` robusto a ledger no-dict; `activity.py` protege claves
  reservadas (`type`/`ts`); resume rutea ledger solo-intel a `triage`.
- **Report**: se quita `--enable-local-file-access` de wkhtmltopdf; clamp de `margin-left`.
- **Shell**: `run-scan.sh` usa `npx --no-install` (no auto-instala desde el registry); cache `chmod 700`.
- **Panel**: React/ReactDOM/Babel **pineados a versión exacta + SRI** (integrity); `crossorigin`.
- **CI**: acciones **pineadas por SHA** (ci + release) + `dependabot.yml`.
- **Schema**: `schema_version` `const "1.0"` → `enum ["1.0","1.1","1.2"]`; skill init a `1.2`; test de lockstep.
- **Manifest**: `plugin.json` re-declara `"hooks": "./hooks/hooks.json"`.

## Descartados (falsos positivos — verificados)

- **Panel DOM-XSS**: limpio. JSX auto-escapa; el tooltip de glosario usa `textContent`; los `href`
  se construyen con `encodeURIComponent`/constantes. No hay `dangerouslySetInnerHTML`.
- **`tools:` del red-team es la barrera real**: aunque `disallowedTools` fuese ignorado, el allowlist
  (Read/Grep/Glob, sin Bash de red ni Write) ya impide escribir/lanzar exploits.
- **`fixer` omite `git commit` del allowlist** (correcto); `VULN_ACTIVITY` path arbitrario (es ruta
  local del operador); cache-key/url unbound y `run-scan target` sin `--` (no explotables en contexto).

## Verificación

- **Suite:** `python3 -m unittest discover -s tests` → **84 OK** (53 previos + 31 nuevos).
- **Pruebas dirigidas:** el hook bloquea re-staging post-aprobación (backdoor), `-C`/`-c`/`commit-tree`,
  `commit -a`, deploy con gate, ofensivos; permite commit legítimo aprobado y `git status`. El panel
  sirve solo en loopback (Host bueno→200, rebind→421). `intel-cache` rechaza http/host no oficial/
  arg-injection/`file://`. `deploy-gate` bloquea KEV/EPSS y limpia al parchear.
- **Sanidad:** `bump-version.py --check` OK; `py_compile`/`bash -n`/`json.load` de todos los artefactos OK.

## Residuales — RESUELTOS en seguimiento

Los 4 residuales se implementaron tras el primer pase:

1. **Panel sin Babel-en-navegador + CSP estricta.** El JSX se pre-compila a JS plano
   (`scripts/build-panel.sh`, fuente en `panel/app.jsx`); `index.html` lleva una CSP por hash sha256
   del script inline, **sin `unsafe-eval`**. Verificado: el panel renderiza en Chrome headless bajo la
   CSP (React monta, grafo SVG y hallazgos visibles).
2. **`rescan` honesto.** Nuevo estado `candidate-resolved` (en schema, report, panel, ledger, status);
   `rescan.md` ya NO escribe `fix.applied:true`/`status:fixed`. El finding sigue abierto hasta que
   `verify` lo cierre con evidencia.
3. **Aislamiento documentado.** Nuevo `SECURITY.md` con la postura (correr repos no confiables en
   contenedor/VM sin red ni secretos); aviso en `run-scan.sh` y enlace en README.
4. **Release no muta `main`.** El sync de versión se hace en `scripts/release.sh` (local, antes del tag);
   `release.yml` hace checkout del **tag**, valida (`bump-version --check`), testea ese árbol y publica —
   sin `git push` a `main`.

**Estado final:** 44 archivos tocados (35 modificados, 9 nuevos) · **84 tests en verde**.

---
_Auditoría defensiva y autorizada del propio kit. No reemplaza una revisión humana independiente._
