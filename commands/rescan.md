---
description: Re-escanea (SAST) un path/subarbol del repo y fusiona con el ledger sin perder estado; marca como candidato-resuelto lo que ya no aparece
argument-hint: <ruta-o-paquete>
allowed-tools: Task, Read, Grep, Glob, Bash(python3:*), Bash(cat:*)
model: opus
---

# Re-escaneo de un path

## Contexto
- Hallazgos actuales en el path: !`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py under .vuln-hunter/ledger.json "$ARGUMENTS" 2>/dev/null || echo "sin ledger o sin path"`

## Retrocompatibilidad (primero)
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py migrate .vuln-hunter/ledger.json
```

## Tarea
Re-escanea SOLO el subarbol **$ARGUMENTS** con el subagente **sast-analyst**
(scoping por path) y FUSIONA con el ledger existente segun esta politica de merge:

1. **Sigue presente** (misma ubicacion/regla): conserva su `id` y TODO su estado
   acumulado (`sast`, `exploitability`, `intel`, `triage`, `fix`, `verification`,
   `status`). No lo reinicies.
2. **Nuevo**: agregalo con `id` nuevo (VULN-NNN) y `status:"hypothesis"`. Emite
   `finding:new`.
3. **Previo del path que YA NO aparece** y estaba ABIERTO (status hypothesis/
   confirmed/triaged/planned): es candidato a resuelto. Marca `status:"fixed"` y
   añade:
   ```json
   "fix": { "root_cause": "(ya no detectado en rescan)",
            "summary": "Desaparecio en rescan; pendiente de verificacion",
            "applied": true, "source": "rescan" }
   ```
   NO lo borres (conserva trazabilidad). Los que ya estaban `fixed`/`closed`/
   `filtered` no se tocan.

Usa `ledger.py under .vuln-hunter/ledger.json $ARGUMENTS` para saber que findings
habia en ese path ANTES del rescan y poder comparar.

## Eventos de actividad (panel)
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=SAST agent=sast-analyst
# ... re-escaneo del subarbol ...
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py finding:new id=<VULN-id> title="<titulo>" source=sast
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end stage=SAST agent=sast-analyst summary="<N nuevos, M candidatos a resuelto>"
```

## Presentacion
Cierra con `agent-presentation` y el bloque "▶ Siguiente paso": normalmente
`/vuln-hunter:verify <VULN-ids candidatos>` para confirmar cierres, y
`/vuln-hunter:redteam <VULN-ids nuevos>` para los hallazgos nuevos.
