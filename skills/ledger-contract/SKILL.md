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
| appsec-fixer | `findings[].fix` | `status: fixed` |
| verify-engineer | `findings[].verification` | `status: closed` o vuelve a `fixed` |

> Division SCA/SAST (importante): el **sast-analyst** NO escanea dependencias; eso
> es del **threat-intel-scout**. Asi no se escanea dos veces ni se reconcilia a
> mano. SAST = codigo propio; SCA/intel = dependencias de terceros.

## Versionado y retrocompatibilidad
El ledger lleva `schema_version`. La version actual es **1.1**. Un run nuevo debe
ser RETROCOMPATIBLE con ledgers de versiones anteriores: antes de leer/escribir,
migra con el helper determinista (sube `schema_version`, rellena defaults y
preserva todos los findings y su estado, idempotente):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py migrate .vuln-hunter/ledger.json
```
Para saber por donde iba un run anterior (continuidad), usa:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py resume .vuln-hunter/ledger.json
```
Devuelve las etapas completas y el `next_command` de la cadena. Lo consumen
`/vuln-hunter:resume` y `/vuln-hunter:hunt` (auto-deteccion). Nunca reinicies un
ledger existente: enriquece sobre el.

## Inicializacion
Si `.vuln-hunter/ledger.json` no existe, crea el esqueleto:
```json
{
  "schema_version": "1.1",
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

## Mapeo de id por fuente (para evitar colisiones)
- SAST de codigo: `VULN-1xx`
- SCA/threat-intel: `VULN-2xx`
- recon (zonas): `VULN-9xx`
El triage puede renombrar a VULN-001.. al consolidar, registrando el origen en
`dedup_of`.
