#!/usr/bin/env bash
# vuln-hunter :: build-panel.sh
# Pre-compila el JSX del panel (panel/app.jsx) a JS plano y lo inyecta en
# panel/index.html, recalculando el hash sha256 de la CSP. Asi el panel NO usa
# Babel-en-navegador (sin 'unsafe-eval') y la CSP sigue siendo estricta.
#
# Corre esto SIEMPRE que edites panel/app.jsx.
#
# Requisitos: node + curl (descarga @babel/standalone pineado para transpilar).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BABEL_VER="7.26.4"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

command -v node >/dev/null 2>&1 || { echo "build-panel: falta node" >&2; exit 1; }
[ -f panel/app.jsx ] || { echo "build-panel: falta panel/app.jsx (fuente)" >&2; exit 1; }

echo "[build-panel] descargando @babel/standalone@${BABEL_VER}…"
curl -fsSL "https://unpkg.com/@babel/standalone@${BABEL_VER}/babel.min.js" -o "$TMP/babel.js"

echo "[build-panel] transpilando panel/app.jsx…"
node -e '
const fs=require("fs"); const Babel=require(process.argv[1]+"/babel.js");
const src=fs.readFileSync("panel/app.jsx","utf8").replace(/^\/\/[^\n]*\n/,"");
const out=Babel.transform(src,{presets:[["react"]],compact:false,comments:true});
fs.writeFileSync(process.argv[1]+"/compiled.js", out.code);
' "$TMP"

echo "[build-panel] inyectando JS compilado + CSP en panel/index.html…"
python3 - "$TMP/compiled.js" <<'PY'
import re, sys, hashlib, base64
compiled = open(sys.argv[1]).read().rstrip()
html = open('panel/index.html').read()
inline = "\n" + compiled + "\n"
# reemplaza el script inline (el unico <script> sin src=)
html = re.sub(r'<script>\n[\s\S]*?\n</script>',
              lambda _: "<script>" + inline + "</script>", html, count=1)
digest = base64.b64encode(hashlib.sha256(inline.encode()).digest()).decode()
html = re.sub(r"('sha256-)[^']+(')", lambda m: m.group(1) + digest + m.group(2), html, count=1)
open('panel/index.html', 'w').write(html)
print("  CSP sha256:", digest[:24], "…")
PY

echo "[build-panel] listo. Verifica con: python3 -m unittest tests.test_panel_contract"
