---
description: Muestra el dashboard del estado de la auditoria (progreso del flujo, hallazgos y siguiente comando recomendado) leido del ledger
argument-hint:
allowed-tools: Bash(python3:*), Read
model: haiku
---

# Estado de la auditoria

Ejecuta el dashboard DETERMINISTA (no inventes el estado; sale del ledger):
```
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/status.py .vuln-hunter/ledger.json
```
Muestra su salida tal cual al usuario. Es un mapa de "donde estoy y que sigue":
barra de progreso del flujo, conteo por severidad, tabla de hallazgos y el
siguiente comando recomendado. Si el usuario confirma, ejecuta ese comando.
