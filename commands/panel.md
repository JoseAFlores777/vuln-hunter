---
description: Levanta el panel administrativo vivo (React+CDN, estatico) que lee el ledger y activity.jsonl y se actualiza por polling
argument-hint: [puerto]
allowed-tools: Bash(bash:*), Read
model: haiku
---

# Panel vivo de vuln-hunter

Sirve el panel estatico desde `.vuln-hunter/` y lo abre en el navegador. El panel
hace polling de `ledger.json` y `activity.jsonl` cada 2s, asi que se actualiza
solo mientras corre la auditoria.

## Pasos
1. Levanta el panel y abrelo en el navegador con el helper compartido (mkdir + cp
   del asset + servidor estatico en segundo plano + open). Puerto $ARGUMENTS o
   8765 por defecto. Es idempotente: si ya esta corriendo, no abre otra pestana:
   ```
   bash ${CLAUDE_PLUGIN_ROOT}/scripts/serve-panel.sh ${ARGUMENTS:-8765}
   ```
   Es el MISMO helper que `/vuln-hunter:hunt` y `/vuln-hunter:detect` corren solos
   al inicio, asi que aqui solo lo usas para (re)abrirlo manualmente.
2. Dile al usuario:
   - URL: `http://localhost:<puerto>/index.html` (el servidor escucha SOLO en
     loopback / 127.0.0.1: el estado de la auditoria no se expone a la red).
   - El panel se refresca solo cada 2s; deja esta terminal y corre la auditoria en
     otra (o sigue con `/vuln-hunter:hunt`).
   - Para detenerlo: `kill $(cat .vuln-hunter/panel.pid)`.

## Historial de corridas
El panel trae un **selector de corridas** (arriba): "En vivo" muestra la auditoria
actual con polling; al elegir una corrida pasada, carga su snapshot en modo
**solo-lectura** (sin polling). Las corridas se archivan solas al generar el
informe (`/vuln-hunter:report` -> `scripts/archive-run.py`) en
`.vuln-hunter/history/`. El historial es LOCAL (`.vuln-hunter/` esta en .gitignore):
no se commitea.

## Nota
Si aun no existe `.vuln-hunter/ledger.json`, el panel muestra un estado vacio que
invita a correr `/vuln-hunter:detect` o `/vuln-hunter:hunt`. No es un error.
