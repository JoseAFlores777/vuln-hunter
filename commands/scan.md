---
description: Escanea con SAST+SCA por stack y normaliza hallazgos a SARIF + OWASP Top 10 (delega en sast-analyst)
argument-hint: [ruta-o-paquete]
allowed-tools: Task, Read, Grep, Glob, Bash(cat:*)
model: sonnet
---

# Escaneo SAST/SCA

## Scope
- Stacks: !`cat .vuln-hunter/stacks.json 2>/dev/null || echo "ejecuta /vuln-hunter:detect"`

## Tarea
Lanza el subagente **sast-analyst** sobre **$ARGUMENTS** (o todos los paquetes si
esta vacio). El agente corre las herramientas que correspondan al stack, traza
flujos source->sink, asigna confianza 1-10 y mapea a OWASP 2021/2025 + CWE.
Devuelve el ledger preliminar de hipotesis.

## Presentacion
El agente presenta su resultado con el skill `agent-presentation` (cabecera con
icono, resumen de 3 lineas, tabla con emoji-semaforo, barra de progreso) y cierra
con el bloque "▶ Siguiente paso". Tras el SAST, recomienda `/vuln-hunter:redteam all`.
