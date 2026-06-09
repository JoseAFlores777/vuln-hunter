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
#   intel-cache.sh fetch <clave> <url> [curl_args...]  -> get; si miss, hace curl, guarda y devuelve
#   intel-cache.sh purge                          -> limpia entradas expiradas
#
# Variables:
#   VH_CACHE_DIR (def .vuln-hunter/cache)
#   VH_CACHE_TTL segundos (def 21600 = 6h)
#   NVD_API_KEY  (opcional; si esta, se anade el header apiKey en fetch a NVD)
set -uo pipefail

CACHE_DIR="${VH_CACHE_DIR:-.vuln-hunter/cache}"
TTL="${VH_CACHE_TTL:-21600}"
mkdir -p "$CACHE_DIR"

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
    cat > "$f"
    ;;
  fetch)
    key="$1"; url="$2"; shift 2
    f="$(keyfile "$key")"
    if is_fresh "$f"; then cat "$f"; exit 0; fi
    # cache miss: consulta. Anade API key de NVD si aplica.
    extra=()
    if [[ "$url" == *"nvd.nist.gov"* && -n "${NVD_API_KEY:-}" ]]; then
      extra=(-H "apiKey: ${NVD_API_KEY}")
    fi
    if command -v curl >/dev/null 2>&1; then
      if curl -fsSL "${extra[@]}" "$@" "$url" -o "$f"; then
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
