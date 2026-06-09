---
description: Genera el plan de remediacion. Usa el motor de planning de superpowers si esta instalado; si no, genera un plan propio por prioridad.
argument-hint:
allowed-tools: Task, Skill, Read, Write, TodoWrite
model: opus
---

# Plan de remediacion

## Tarea
A partir del vulnerability ledger priorizado (`.vuln-hunter/ledger.json`), genera
un plan de remediacion en tareas pequenas (2-5 min), con paths concretos y los
tests escritos ANTES del codigo, ordenado por prioridad (P0 -> P3).

## Motor de planning (superpowers OPCIONAL, recomendado)
1. Comprueba si **superpowers** esta instalado (skills `brainstorming` /
   `writing-plans` disponibles).
2. **Si esta instalado**: usalo como motor.
   - `brainstorming` para explorar enfoques de fix (uno por VULN o agrupados por
     causa raiz), respetando su HARD-GATE (no escribir codigo antes de aprobar el
     diseno).
   - `writing-plans` para descomponer y guardar el plan en `docs/superpowers/plans/`.
   Guarda la ruta del plan en `plan_ref` del ledger.
3. **Si NO esta instalado**: genera un plan propio en `.vuln-hunter/plan.md`
   (tareas por prioridad, con archivo y test por tarea) y registra esa ruta en
   `plan_ref`. Sugiere, sin bloquear, instalar superpowers para un planning mas
   rico:
   ```
   /plugin marketplace add obra/superpowers-marketplace
   /plugin install superpowers@superpowers-marketplace
   ```

El plan es la entrada del appsec-fixer.
