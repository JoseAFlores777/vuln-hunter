#!/usr/bin/env bash
#
# vuln-hunter :: intel-cache.sh
# Cache con TTL para consultas a APIs oficiales de vulnerabilidades.
# Respeta el rate limit de NVD (5 req/30s sin API key, 50 con key) cacheando
# respuestas por clave. Lo usa threat-intel-scout para no re-consultar lo mismo.
#
# Uso:
#   intel-cache.sh get   <clave>                 -> imprime el valor cacheado o vacio (y exit 1 si expiro/no existe)
#   intel-cache.sh put   <clave> < datos_stdin   -> guarda en cache
#   intel-cache.sh fetch <clave> <url>            -> get; si miss, hace curl (solo https a fuentes oficiales), guarda y devuelve
#   intel-cache.sh purge                          -> limpia entradas expiradas
#
# SEGURIDAD: `fetch` solo acepta https a un allowlist de hosts oficiales
# (NVD/OSV/EPSS/CISA/GitHub/MSRC). No reenvia argumentos arbitrarios a curl.
#
# Variables:
#   VH_CACHE_DIR (def .vuln-hunter/cache)
#   VH_CACHE_TTL segundos (def 21600 = 6h)
#   NVD_API_KEY  (opcional; si esta, se anade el header apiKey en fetch a NVD)
set -uo pipefail

CACHE_DIR="${VH_CACHE_DIR:-.vuln-hunter/cache}"
TTL="${VH_CACHE_TTL:-21600}"
mkdir -p "$CACHE_DIR"
chmod 700 "$CACHE_DIR" 2>/dev/null || true

# Solo se consultan fuentes OFICIALES (CLAUDE.md regla 5). Host allowlist para
# cerrar SSRF: aunque un nombre de paquete malicioso influya la URL, no se puede
# pivotar a un host arbitrario.
ALLOWED_HOSTS_RE='^https://(services\.nvd\.nist\.gov|api\.osv\.dev|api\.first\.org|www\.cisa\.gov|api\.github\.com|api\.msrc\.microsoft\.com)(/|$)'

url_allowed() {
  case "$1" in
    https://*) ;;                       # solo https
    *) return 1 ;;
  esac
  printf '%s' "$1" | grep -Eq "$ALLOWED_HOSTS_RE"
}

# Rechaza rutas de cache que sean symlink (un repo auditado no debe poder
# pre-sembrar la ruta para que escribamos fuera de la cache).
reject_symlink() {
  if [ -L "$1" ]; then
    echo "[intel-cache] ruta de cache es un symlink; abortando: $1" >&2
    exit 1
  fi
}

keyfile() {
  # clave -> ruta de archivo (hash para evitar caracteres invalidos)
  local k="$1"
  local h
  h="$(printf '%s' "$k" | sha256sum | cut -d' ' -f1)"
  printf '%s/%s.json' "$CACHE_DIR" "$h"
}

now() { date +%s; }

is_fresh() {
  local f="$1"
  [ -f "$f" ] || return 1
  local mtime age
  mtime="$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null)"
  age=$(( $(now) - mtime ))
  [ "$age" -lt "$TTL" ]
}

cmd="${1:-}"; shift || true

case "$cmd" in
  get)
    f="$(keyfile "$1")"
    if is_fresh "$f"; then cat "$f"; exit 0; else exit 1; fi
    ;;
  put)
    f="$(keyfile "$1")"
    reject_symlink "$f"
    cat > "$f"
    ;;
  fetch)
    key="$1"; url="$2"; shift 2
    f="$(keyfile "$key")"
    reject_symlink "$f"
    if is_fresh "$f"; then cat "$f"; exit 0; fi
    # Valida la URL ANTES de tocar la red: solo https a fuentes oficiales.
    if ! url_allowed "$url"; then
      echo "[intel-cache] URL rechazada (no es https a una fuente oficial): $url" >&2
      exit 1
    fi
    # cache miss: consulta. Anade API key de NVD si aplica.
    extra=()
    if [[ "$url" == https://services.nvd.nist.gov/* && -n "${NVD_API_KEY:-}" ]]; then
      extra=(-H "apiKey: ${NVD_API_KEY}")
    fi
    # NOTA: NO se reenvian args arbitrarios del caller a curl (eran superficie de
    # inyeccion de flags). `--` impide que la URL se interprete como opcion;
    # --proto =https y sin -L evitan downgrade/redirect a otros hosts.
    if command -v curl >/dev/null 2>&1; then
      if curl -fsS --proto '=https' --proto-redir '=https' --max-redirs 0 "${extra[@]}" -- "$url" -o "$f"; then
        cat "$f"
      else
        echo "[intel-cache] fallo la consulta a $url" >&2
        rm -f "$f"; exit 1
      fi
    else
      echo "[intel-cache] curl no esta instalado" >&2; exit 1
    fi
    ;;
  purge)
    find "$CACHE_DIR" -type f -name '*.json' | while read -r f; do
      is_fresh "$f" || rm -f "$f"
    done
    echo "[intel-cache] purga de entradas expiradas completada"
    ;;
  *)
    echo "uso: intel-cache.sh {get|put|fetch|purge} ..." >&2; exit 2
    ;;
esac
