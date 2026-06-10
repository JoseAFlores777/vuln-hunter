#!/usr/bin/env bash
# vuln-hunter :: serve-panel.sh
# Levanta el panel vivo (estatico, React+CDN) desde .vuln-hunter/ y lo abre en el
# navegador. Pensado para correr UNA vez al inicio de /vuln-hunter:hunt y
# /vuln-hunter:detect, para que el usuario vea el proceso desde el principio.
#
# El panel hace polling de ledger.json y activity.jsonl (hermanos de index.html)
# cada 2s, asi que se refresca solo mientras corre la auditoria.
#
# Idempotente: si el servidor ya escucha el puerto, NO arranca otro ni reabre una
# pestana nueva (asi un segundo hunt en la misma sesion no spamea el navegador).
#
# Uso:
#   bash scripts/serve-panel.sh [puerto]        # default 8765
# Variables de entorno:
#   VH_PANEL_NO_OPEN=1   no abre el navegador (CI / pruebas); solo sirve.
set -u

PORT="${1:-8765}"
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
STATE_DIR=".vuln-hunter"
URL="http://localhost:${PORT}/index.html"

# --- abre una URL segun el SO (no-op si no hay abridor: CI/headless) ---
open_url() {
  [ "${VH_PANEL_NO_OPEN:-0}" = "1" ] && return 0
  if command -v open >/dev/null 2>&1; then open "$1" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$1" >/dev/null 2>&1 || true
  elif command -v cmd.exe >/dev/null 2>&1; then cmd.exe /c start "" "$1" >/dev/null 2>&1 || true
  fi
}

# --- true si algo ya escucha el puerto ---
port_up() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1 && return 0 || return 1
  elif command -v nc >/dev/null 2>&1; then
    nc -z localhost "$PORT" >/dev/null 2>&1 && return 0 || return 1
  elif command -v curl >/dev/null 2>&1; then
    curl -s -o /dev/null --max-time 1 "$URL" && return 0 || return 1
  fi
  return 1
}

mkdir -p "$STATE_DIR"

# refresca el asset del panel para que los fetch() sean hermanos de los datos
if [ -f "${PLUGIN_ROOT}/panel/index.html" ]; then
  cp "${PLUGIN_ROOT}/panel/index.html" "${STATE_DIR}/index.html"
else
  echo "vuln-hunter: no encuentro ${PLUGIN_ROOT}/panel/index.html" >&2
fi

if port_up; then
  echo "panel ya activo: ${URL} (no se reabre)"
  exit 0
fi

# servidor estatico en segundo plano, desconectado de esta shell (sobrevive al
# fin del comando). Mismo patron que /vuln-hunter:panel.
#
# SEGURIDAD: el directorio servido (.vuln-hunter/) contiene el estado completo de
# la auditoria (hallazgos, rutas de archivos, CVEs, cadenas de explotacion). Por
# eso:
#  - bind SOLO a 127.0.0.1 (loopback). NO 0.0.0.0: no se expone a la LAN.
#  - allowlist del header Host (Host == localhost/127.0.0.1:PORT) para frenar
#    DNS-rebinding desde un sitio web malicioso.
#  - Cache-Control: no-store para que el navegador no deje copias en disco.
# El servidor se implementa inline (subclase de SimpleHTTPRequestHandler) porque
# `python3 -m http.server` no permite filtrar Host ni anadir cabeceras.
SERVER_PY="$(cat <<'PYEOF'
import os, sys
from http.server import HTTPServer, SimpleHTTPRequestHandler

port = int(sys.argv[1]); directory = sys.argv[2]
allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=directory, **k)
    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip()
        if host in allowed_hosts:
            return True
        self.send_response(421)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"vuln-hunter panel: Host no permitido (anti DNS-rebinding).")
        return False
    def do_GET(self):
        if self._host_ok():
            super().do_GET()
    def do_HEAD(self):
        if self._host_ok():
            super().do_HEAD()
    def end_headers(self):
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PYEOF
)"

nohup python3 -c "$SERVER_PY" "$PORT" "$STATE_DIR" >/dev/null 2>&1 &
echo $! > "${STATE_DIR}/panel.pid"
disown 2>/dev/null || true

# espera a que levante (max ~3s) antes de abrir el navegador
for _ in 1 2 3 4 5 6; do
  port_up && break
  sleep 0.5
done

open_url "$URL"
echo "panel: ${URL} (loopback · se refresca cada 2s) · detener: kill \$(cat ${STATE_DIR}/panel.pid) 2>/dev/null"
