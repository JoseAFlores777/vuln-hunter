#!/usr/bin/env bash
# vuln-hunter :: release.sh <X.Y.Z>
# Sincroniza la version en los manifests, COMMITEA ese sync en main, y empuja main
# + el tag vX.Y.Z. Asi el tag ya lleva la version correcta y el workflow Release
# (GitHub Actions) solo VALIDA y publica: el CI nunca escribe en main.
#
# Lo ejecuta la PERSONA en su terminal (no Claude): commitea el sync de release a
# main de forma deliberada. (El hook guard-commit de Claude Code solo corre dentro
# de sesiones de Claude, no aqui.)
#
# Uso:
#   scripts/release.sh 1.3.0
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"

V="${1:-}"
[ -n "$V" ] || { echo "uso: scripts/release.sh X.Y.Z"; exit 2; }
echo "$V" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "version invalida: $V (usa X.Y.Z)"; exit 2; }

branch="$(git branch --show-current)"
[ "$branch" = "main" ] || { echo "estas en '$branch'; releasea desde main"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "arbol sucio; commitea o limpia antes de releasear"; exit 1; }
if git rev-parse "v$V" >/dev/null 2>&1; then echo "el tag v$V ya existe"; exit 1; fi

# asegura estar al dia con el remoto para no taggear un main viejo
git fetch origin main --quiet || true

# sincroniza los manifests a la version ANTES de taggear, y commitea ese sync.
python3 "$HERE/bump-version.py" "$V"
if [ -n "$(git status --porcelain .claude-plugin)" ]; then
  git add .claude-plugin/plugin.json .claude-plugin/marketplace.json
  git commit -m "chore(release): v$V sync manifests"
  git push origin main
fi

git tag -a "v$V" -m "vuln-hunter v$V"
git push origin "v$V"
echo "tag v$V empujado (con los manifests ya en $V). CI valida y publica el release:"
echo "  https://github.com/JoseAFlores777/vuln-hunter/releases/tag/v$V"
