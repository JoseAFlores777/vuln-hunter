---
name: ledger-contract
description: Define el contrato del estado compartido de vuln-hunter (.vuln-hunter/ledger.json). Usa este skill SIEMPRE que un agente del flujo (recon, sast, threat-intel, red-team, triage, fixer, verify) necesite leer o escribir hallazgos, para que todos hablen el mismo formato JSON en vez de pasarse prosa.
---

# Contrato del Ledger compartido

Todos los agentes de vuln-hunter se comunican a traves de UN solo archivo:
`.vuln-hunter/ledger.json`, validado por `schemas/ledger.schema.json`. No te
pases prosa entre agentes: lee el ledger, enriquece tu parte y reescribelo.

## Regla de oro
Cada finding tiene un `id` estable (VULN-001, VULN-002...). Un agente **AÑADE su
sub-objeto** (`sast`, `exploitability`, `intel`, `triage`, `fix`, `verification`)
al finding existente por su id. NUNCA dupliques un finding ni renumeres.

## Quien escribe que (ownership claro)
| Agente | Sub-objeto que escribe | Tambien actualiza |
|---|---|---|
| recon-cartographer | `attack_surface` | crea findings tipo `recon` si detecta zonas |
| **sast-analyst** | `findings[].sast` (SAST de CODIGO unicamente) | `status: hypothesis` |
| **threat-intel-scout** | `findings[].intel` (SCA de DEPENDENCIAS unicamente) | `status: hypothesis` |
| redteam-whitehat | `findings[].exploitability` | `status: confirmed` |
| triage-judge | `findings[].triage` | `status: triaged` o `filtered` |
| appsec-fixer | `findings[].fix` | `status: fixing` al EMPEZAR cada VULN (emite `finding:state id=VULN-x state=fixing`), `status: fixed` al aplicar |
| verify-engineer | `findings[].verification` | `status: closed` o vuelve a `fixed` |

> Division SCA/SAST (importante): el **sast-analyst** NO escanea dependencias; eso
> es del **threat-intel-scout**. Asi no se escanea dos veces ni se reconcilia a
> mano. SAST = codigo propio; SCA/intel = dependencias de terceros.

## Versionado y retrocompatibilidad
El ledger lleva `schema_version`. La version actual es **1.2** (añade el status
`fixing`, el evento de actividad `finding:state`, y la canonicalizacion de ids
— ver abajo). Un run nuevo debe ser RETROCOMPATIBLE con ledgers de versiones
anteriores: antes de leer/escribir, migra con el helper determinista (sube
`schema_version`, rellena defaults, CANONICALIZA ids de recoleccion a
VULN-001/002/003... y preserva todos los findings y su estado; idempotente):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py migrate .vuln-hunter/ledger.json
```
Esto es lo que hace retrocompatible el cambio a ids crecientes: si actualizas el
plugin en un repo que YA corrio una auditoria (ledger con `VULN-101`, `VULN-209`
sin canonicalizar), no hace falta ningun paso manual — `migrate` ya se corria en
cada comando que toca un ledger existente (`/vuln-hunter:hunt`, `:resume`,
`:rescan`) y ahora, ademas de subir el schema, tambien renumera. `report.py`
tambien lo llama internamente y re-escribe el ledger si algo cambio, asi que con
solo pedir `/vuln-hunter:report` sobre una auditoria vieja, el ledger en disco
queda canonicalizado.
Para saber por donde iba un run anterior (continuidad), usa:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py resume .vuln-hunter/ledger.json
```
Devuelve las etapas completas y el `next_command` de la cadena. Lo consumen
`/vuln-hunter:resume` y `/vuln-hunter:hunt` (auto-deteccion). Nunca reinicies un
ledger existente: enriquece sobre el.

## Inicializacion
Si `.vuln-hunter/ledger.json` no existe, crea el esqueleto (o, mejor, corre
`ledger.py migrate` para no duplicar el numero de version a mano):
```json
{
  "schema_version": "1.2",
  "run": { "started_at": "<ISO>", "scope": "<scope>", "owasp_version": "2025", "branch": "<branch>", "stacks": [] },
  "findings": []
}
```

## Lectura/escritura segura
- Lee el archivo completo, parsea, modifica en memoria, vuelve a escribir todo.
- No hagas ediciones parciales por regex sobre el JSON.
- Si dos agentes corren en paralelo (sast + threat-intel), cada uno trabaja sobre
  rangos de id distintos (SAST-/INTEL-) y el orquestador los fusiona; evita
  escrituras concurrentes al mismo archivo.

## Mapeo de id por fuente (para evitar colisiones) — SOLO durante la recoleccion
- SAST de codigo: `VULN-1xx`
- SCA/threat-intel: `VULN-2xx`
- recon (zonas): `VULN-9xx`
Estos rangos existen unicamente para que sast-analyst y threat-intel-scout (que
corren EN PARALELO, ver `/vuln-hunter:hunt` paso 2) puedan asignar ids sin
coordinarse y sin chocar. NO son el id final que ve el usuario.

## Canonicalizacion de ids (automatica via migrate; obligatoria al consolidar el triage)
`VULN-101`, `VULN-209`, etc. son ids internos de recoleccion — confunden en el
informe (no son crecientes, no dicen nada del orden real). `ledger.py migrate`
ya los reasigna a `id` = `VULN-001`, `VULN-002`, `VULN-003`... crecientes desde
1, en el orden real de descubrimiento (por el numero del id de recoleccion). El
id viejo NO se pierde: queda en `origin_id` para trazabilidad. Es idempotente e
incremental: findings ya canonicos (con `origin_id`) no se tocan, y findings
nuevos (p.ej. un SCA creado al vuelo por appsec-fixer al bump-ear una
dependencia) se numeran a continuacion de la secuencia existente. Si un finding
tenia `triage.dedup_of` apuntando al id viejo de otro finding renumerado, se
actualiza esa referencia al id nuevo.

Aunque `migrate` ya lo hace, en cuanto el **triage-judge** consolida y escribe
`findings[].triage`, el orquestador corre explicitamente (determinista, sin LLM
— no le pidas al agente que renumere a mano; `renumber` es un alias de
`migrate`, mismo resultado, mensaje mas claro en ese punto del flujo):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py migrate .vuln-hunter/ledger.json
```
para garantizar que TODO lo consolidado en este paso (incluidos findings que
llegaron de SAST/threat-intel despues de la ultima migracion) quede canonico
antes del plan/gate/fix.

Nota honesta: `activity.jsonl` es un log append-only (nunca se reescribe), asi
que las lineas ya escritas ANTES de renumerar conservan el id de recoleccion que
tenian en ese instante (p.ej. `finding:new id=VULN-101 ...`). El panel las sigue
mostrando; solo pierden el chip de severidad/KEV enriquecido si el id ya no
matchea contra el ledger (cosmetico, no rompe nada — los comandos que copia el
panel usan siempre el id ACTUAL del ledger).
