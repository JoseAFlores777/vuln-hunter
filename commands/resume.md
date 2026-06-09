---
description: Reanuda la auditoria desde donde quedo el run anterior (lee y migra el ledger, y continua la cadena sin repetir lo ya hecho)
argument-hint: [ruta-o-paquete]
allowed-tools: Task, Read, Grep, Glob, Bash(git:*), Bash(mkdir:*), Bash(python3:*), Write, TodoWrite, WebSearch, WebFetch
model: opus
---

# Reanudar auditoria

## Contexto del repositorio
- Ledger: !`test -f .vuln-hunter/ledger.json && echo "existe" || echo "no existe"`
- Punto de reanudacion: !`python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py resume .vuln-hunter/ledger.json 2>/dev/null || echo "sin ledger"`

## Retrocompatibilidad (primero)
Migra el ledger al schema actual; preserva findings y su estado, rellena defaults
y sube `schema_version`. Asi un ledger de una version anterior queda compatible:
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/ledger.py migrate .vuln-hunter/ledger.json
```

## Tarea
1. Toma `next_command` de `ledger.py resume`: es el siguiente paso real de la
   cadena segun el estado del ledger (no reinicia lo ya completado).
2. Continua la cadena DESDE ahi, en orden canonico, reusando el ledger existente
   (las etapas ya hechas NO se repiten):
   scan/watch -> redteam -> triage -> plan -> fix -> patch -> verify -> report.
3. Trabajo DEFENSIVO y AUTORIZADO del codigo propio. El red-team solo PoCs
   conceptuales; el patcher no commitea sin aprobacion humana por hash.
4. Tras cada etapa, muestra el dashboard de texto y respeta `agent-presentation`;
   pide decisiones con una sola pregunta enumerada a la vez.
   ```
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/status.py .vuln-hunter/ledger.json
   ```

## Eventos de actividad (panel)
Emite `run:start` marcando que es una reanudacion, y los `stage:start`/`stage:end`
de cada etapa que ejecutes (igual que /vuln-hunter:hunt):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py run:start scope="<scope o repo> (resume)"
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:start stage=<STAGE> agent=<AGENT>
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/activity.py stage:end   stage=<STAGE> agent=<AGENT> summary="<resumen>"
```
Sugiere abrir `/vuln-hunter:panel` para ver la reanudacion en vivo.

## Nota
Si no existe `.vuln-hunter/ledger.json` no hay nada que reanudar: corre
`/vuln-hunter:detect` + `/vuln-hunter:hunt` para empezar de cero.
