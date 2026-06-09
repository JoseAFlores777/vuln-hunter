#!/usr/bin/env bash
# vuln-hunter :: release.sh <X.Y.Z>
# Crea y empuja el tag vX.Y.Z. El workflow Release (GitHub Actions) corre tests,
# sincroniza la version del tag en los manifests y publica el GitHub Release.
#
# NO commitea en local (asi no choca con el hook guard-commit). Solo empuja un tag:
# es la unica accion que necesitas para releasear.
#
# Uso:
#   scripts/release.sh 1.3.0
set -eu

V="${1:-}"
[ -n "$V" ] || { echo "uso: scripts/release.sh X.Y.Z"; exit 2; }
echo "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "version invalida: $V (usa X.Y.Z)"; exit 2; }

branch="$(git branch --show-current)"
[ "$branch" = "main" ] || { echo "estas en '$branch'; releasea desde main"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "arbol sucio; commitea o limpia antes de releasear"; exit 1; }
if git rev-parse "v$V" >/dev/null 2>&1; then echo "el tag v$V ya existe"; exit 1; fi

# asegura estar al dia con el remoto para no taggear un main viejo
git fetch origin main --quiet || true

git tag -a "v$V" -m "vuln-hunter v$V"
git push origin "v$V"
echo "tag v$V empujado. CI sincroniza los manifests y publica el release:"
echo "  https://github.com/JoseAFlores777/vuln-hunter/releases/tag/v$V"
