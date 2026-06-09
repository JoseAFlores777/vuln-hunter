---
description: Confirma explotabilidad de un hallazgo (o de todos) con PoC conceptual (delega en redteam-whitehat)
argument-hint: [VULN-NNN | all]
allowed-tools: Task, Read, Grep, Glob
model: opus
---

# Confirmacion de explotabilidad (sombrero blanco)

## Regla
Solo PoCs conceptuales sobre el codigo del propio usuario, en scope autorizado.
Sin exploits ejecutables, sin malware, sin trafico de red. Lo imponen el agente
y los hooks.

## Tarea
Lanza el subagente **redteam-whitehat** sobre el hallazgo **$ARGUMENTS** (o `all`).
Devuelve veredicto EXPLOTABLE / NO_EXPLOTABLE / CONDICIONAL con la cadena
conceptual y la confianza ajustada.

## Presentacion
El agente presenta su resultado con el skill `agent-presentation` (cabecera con
icono, resumen de 3 lineas, tabla con emoji-semaforo, barra de progreso) y cierra
con el bloque "▶ Siguiente paso". Tras los veredictos, recomienda `/vuln-hunter:triage`.
