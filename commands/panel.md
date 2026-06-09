---
description: Levanta el panel administrativo vivo (React+CDN, estatico) que lee el ledger y activity.jsonl y se actualiza por polling
argument-hint: [puerto]
allowed-tools: Bash(python3:*), Bash(cp:*), Bash(mkdir:*), Bash(open:*), Read
model: haiku
---

# Panel vivo de vuln-hunter

Sirve el panel estatico desde `.vuln-hunter/` y lo abre en el navegador. El panel
hace polling de `ledger.json` y `activity.jsonl` cada 2s, asi que se actualiza
solo mientras corre la auditoria.

## Pasos
1. Asegura la carpeta de estado:
   ```
   mkdir -p .vuln-hunter
   ```
2. Copia el panel (asset del plugin) junto a los datos para que los `fetch()` sean
   hermanos:
   ```
   cp ${CLAUDE_PLUGIN_ROOT}/panel/index.html .vuln-hunter/index.html
   ```
3. Lanza el servidor estatico EN SEGUNDO PLANO (puerto $ARGUMENTS o 8765 por
   defecto) y abre el navegador:
   ```
   (python3 -m http.server ${ARGUMENTS:-8765} --directory .vuln-hunter >/dev/null 2>&1 &) ; sleep 1 ; open "http://localhost:${ARGUMENTS:-8765}/index.html"
   ```
4. Dile al usuario:
   - URL: `http://localhost:<puerto>/index.html`
   - El panel se refresca solo cada 2s; deja esta terminal y corre la auditoria en
     otra (o sigue con `/vuln-hunter:hunt`).
   - Para detenerlo: `pkill -f "http.server <puerto>"`.

## Nota
Si aun no existe `.vuln-hunter/ledger.json`, el panel muestra un estado vacio que
invita a correr `/vuln-hunter:detect` o `/vuln-hunter:hunt`. No es un error.
