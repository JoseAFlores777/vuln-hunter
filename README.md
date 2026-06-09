# vuln-hunter 🛡️ (v1.1)

Kit **multi-agente** de Claude Code para **detectar, vigilar amenazas, triar,
planificar, arreglar, parchear y verificar** vulnerabilidades en un proyecto o
monorepo. Alineado a **OWASP Top 10 (2021 y 2025)**. Cada subagente está modelado
como un profesional de seguridad real.

> **Marco de uso:** auditoría **defensiva y autorizada** del código propio, para
> **remediar**. El red-team produce solo PoCs *conceptuales*; el threat-intel solo
> *lee* fuentes oficiales; el patcher nunca commitea sin aprobación humana **del
> diff exacto**. Lo refuerzan hooks deterministas, no solo los prompts.

## Los 7 agentes

| Agente | Rol / persona | Metodología |
|---|---|---|
| `recon-cartographer` | Cartógrafo de superficie de ataque | PTES, STRIDE, PASTA, attack trees |
| `sast-analyst` | Análisis estático (**código propio**) | Taint/data-flow, Semgrep/Bandit/Roslyn, SARIF |
| `threat-intel-scout` | CTI / vuln-management (**dependencias**) | OSV/NVD/KEV/EPSS, SSVC, MITRE ATT&CK T1190 |
| `redteam-whitehat` | Pentester ético (OSCP/OSWE) | PTES, WSTG — **PoC conceptual** |
| `triage-judge` | Analista de triage | CVSS v4.0/v3.1, EPSS, CISA KEV |
| `appsec-fixer` | Security architect / AppSec | OWASP ASVS v5.0.0 — fix de causa raíz |
| `verify-engineer` | Verificación / detección | Re-escaneo + tests, verificación honesta |

## Comandos

| Comando | Qué hace |
|---|---|
| `/vuln-hunter:hunt [path] [--dry-run] [--solo-deteccion]` | Orquesta el flujo completo (auto-detecta y reanuda un run previo) |
| `/vuln-hunter:resume [path]` | **Reanuda** desde donde quedó el run anterior (migra el ledger, retrocompatible, y continúa la cadena sin repetir etapas) |
| `/vuln-hunter:detect [path]` | Detecta stacks del monorepo (scoping) |
| `/vuln-hunter:scan [path]` | SAST de código (delega en sast-analyst) |
| `/vuln-hunter:rescan <path>` | **Re-escanea** SAST un subárbol y fusiona con el ledger; marca como candidato-resuelto lo que ya no aparece |
| `/vuln-hunter:watch [lockfile] [--gate]` | **Threat intel de dependencias de producción** (OSV/NVD/KEV/EPSS) |
| `/vuln-hunter:redteam [VULN\|all]` | Confirma explotabilidad (conceptual) |
| `/vuln-hunter:triage` | Prioriza (CVSS+EPSS+KEV) |
| `/vuln-hunter:plan` | Plan de remediación (superpowers si está, si no propio) |
| `/vuln-hunter:fix [VULN\|all]` | Aplica fixes (sin commit) |
| `/vuln-hunter:patch` | Diffs + aprobación humana por hash + commit |
| `/vuln-hunter:verify [VULN\|all]` | Verifica cierre sin regresión |
| `/vuln-hunter:report [salida.html]` | Informe HTML reproducible desde el ledger |
| `/vuln-hunter:status` | **Dashboard**: progreso del flujo, hallazgos y siguiente comando |
| `/vuln-hunter:panel [puerto]` | **Panel vivo** (React+CDN, estático): lee `.vuln-hunter/ledger.json` + `activity.jsonl` y se actualiza por polling cada 2s para ver hallazgos y su mitigación en tiempo real |

## Flujo

```
recon → [ scan (SAST código) ∥ watch (SCA dependencias) ] → red-team
      → triage → PLAN → fix → patch (aprobación por hash) → verify → report
```

## Estado compartido: el ledger
Todos los agentes leen/escriben `.vuln-hunter/ledger.json` (esquema en
`schemas/ledger.schema.json`). Nadie se pasa prosa: cada agente enriquece su parte
del mismo objeto. Esto unifica severidad, deduplicación y el informe final.

## Prevención de ransomware (lo nuevo)
`threat-intel-scout` cruza tus dependencias de **producción** con fuentes
oficiales y marca como **bloqueantes de deploy** los CVE en **CISA KEV** o con
**EPSS alto** — el vector inicial típico de ransomware (MITRE ATT&CK **T1190**).
El hook escribe `.vuln-hunter/deploy-blocked` y **detiene el despliegue** hasta
parchear. Úsalo así:
```
/vuln-hunter:watch --gate          # veredicto APTO / BLOQUEADO
```

## Instalación
```bash
/plugin marketplace add JoseAFlores777/vuln-hunter
/plugin install vuln-hunter@vuln-hunter-marketplace
```
**superpowers es OPCIONAL** (mejora el planning). Si lo quieres:
```bash
/plugin marketplace add obra/superpowers-marketplace
/plugin install superpowers@superpowers-marketplace
```

## Validar que NO es teatro de seguridad
Incluye un laboratorio con **9 vulnerabilidades plantadas** y su ground truth en
`examples/vulnerable-lab/`. Corre el flujo en `--dry-run` y compara:
```
/vuln-hunter:detect examples/vulnerable-lab
/vuln-hunter:hunt examples/vulnerable-lab --dry-run
```
Cuenta verdaderos positivos (de 9), falsos negativos y falsos positivos (hay un
control negativo que NO debe marcarse). Ese número te dice si el plugin sirve.

## Aprobar un patch (gesto humano)
```bash
git diff HEAD                                   # revisa
python3 scripts/approve-diff.py                 # aprueba ESE diff (por hash)
# si editas más, la aprobación caduca: re-aprueba
```

## Salvaguardas (hooks, todas probadas)
- `block-exploit-write.py` — bloquea contenido de exploit ejecutable; advierte
  (no bloquea) ante nombres meramente sospechosos.
- `guard-commit-and-exec.py` — aprobación por hash del diff + gate de deploy
  (KEV) + bloqueo de ejecución ofensiva.

## Estructura
```
vuln-hunter/
├── .claude-plugin/{plugin.json, marketplace.json}
├── agents/        (7 subagentes)
├── commands/      (12 slash commands)
├── skills/        (stack-detector, owasp-reference, ledger-contract)
├── hooks/         (hooks.json + 2 guardianes)
├── scripts/       (run-scan.sh, intel-cache.sh, approve-diff.py, report.py)
├── schemas/       (ledger.schema.json)
├── examples/      (vulnerable-lab con ground truth)
├── CLAUDE.md      (reglas persistentes)
└── README.md
```

## Aviso
No sustituye a un auditor humano ni a SAST/DAST dedicados; es un primer pase
disciplinado. Mide su tasa de acierto con el laboratorio antes de confiar en él.
Licencia MIT.

## Visualizacion y guia paso a paso (v1.2)
Cada agente presenta su resultado con un formato uniforme (skill
`agent-presentation`): cabecera con icono, resumen de 3 lineas, tabla de
hallazgos con emoji-semaforo de severidad (🔴P0 🟠P1 🟡P2 🟢P3 ⚪filtrado), barra
de progreso del flujo, y un bloque **"▶ Siguiente paso"** que recomienda el
comando exacto a ejecutar.

En cualquier momento, `/vuln-hunter:status` muestra un **dashboard determinista**
(generado por `scripts/status.py` desde el ledger, sin depender del LLM) con
donde estas en el flujo, los hallazgos por severidad, la alerta de KEV y el
siguiente comando recomendado. Las decisiones se piden con preguntas unicas y
enumeradas (una a la vez), o con botones si el entorno los soporta.

Para verlo en vivo, `/vuln-hunter:panel` levanta un frontend estatico (sin build,
sin instalar nada) servido con `python3 -m http.server`. La verdad de estado es el
ledger; `activity.jsonl` (append-only, escrito por `scripts/activity.py`) es el
timeline. El panel hace polling cada 2s, asi que muestra los hallazgos y su
mitigacion en tiempo real mientras corre la auditoria. Ver
`docs/adr/0001-panel-liveness-architecture.md`.

![Panel vivo de vuln-hunter: pipeline tipo GitHub Actions, bitacora y hallazgos por estado](docs/assets/panel-overview.png)

El grafo de pipeline (estilo GitHub Actions) muestra que agente trabaja, con el
fork paralelo `scan`/`watch`; la bitacora es el timeline de lo que se va
encontrando; las pestanias **Encontrados / Mitigando / Arreglados** mueven cada
hallazgo segun avanza. Para reanudar un run anterior usa `/vuln-hunter:resume`
(retrocompatible: migra el ledger sin perder estado) y para re-escanear un
subarbol `/vuln-hunter:rescan <path>`.
