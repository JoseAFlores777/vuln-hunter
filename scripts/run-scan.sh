#!/usr/bin/env bash
#
# vuln-hunter :: run-scan.sh
# Wrapper de escaneo SAST/SCA por stack. Lo usa el sast-analyst / verify-engineer.
# Uso:  run-scan.sh <stack> <path> [out_dir]
#   stack: django | python | nextjs | react | angular | dotnet | common
# Genera SARIF/JSON en out_dir (por defecto .vuln-hunter/out).
# No falla el script si una herramienta no esta instalada: lo reporta y sigue.
set -uo pipefail

STACK="${1:-common}"
TARGET="${2:-.}"
OUT="${3:-.vuln-hunter/out}"
mkdir -p "$OUT"

have() { command -v "$1" >/dev/null 2>&1; }
note() { printf '[vuln-hunter] %s\n' "$1"; }

run() {  # run <nombre> <comando...>
  local name="$1"; shift
  if have "$1"; then
    note "ejecutando: $name"
    "$@" || note "$name termino con hallazgos o advertencias (continuo)"
  else
    note "OMITIDO ($name): '$1' no esta instalado"
  fi
}

case "$STACK" in
  django|python)
    run "bandit"    bandit -r "$TARGET" -f sarif -o "$OUT/bandit.sarif"
    run "semgrep"   semgrep --config p/python --config p/django --sarif -o "$OUT/semgrep.sarif" "$TARGET"
    run "pip-audit" pip-audit -f json -o "$OUT/pip-audit.json"
    run "gitleaks"  gitleaks detect --source "$TARGET" --report-path "$OUT/gitleaks.json" --no-banner
    ;;
  nextjs|react|angular)
    run "eslint"   npx --yes eslint "$TARGET" --plugin security -f json -o "$OUT/eslint.json"
    run "semgrep"  semgrep --config p/javascript --config p/typescript --sarif -o "$OUT/semgrep.sarif" "$TARGET"
    run "npm-audit" npm audit --json
    run "gitleaks"  gitleaks detect --source "$TARGET" --report-path "$OUT/gitleaks.json" --no-banner
    ;;
  dotnet)
    note "para .NET, compila con analizadores como error:"
    note "  dotnet build -warnaserror"
    run "dotnet-vuln" dotnet list "$TARGET" package --vulnerable --include-transitive
    run "semgrep"  semgrep --config p/csharp --sarif -o "$OUT/semgrep.sarif" "$TARGET"
    run "gitleaks" gitleaks detect --source "$TARGET" --report-path "$OUT/gitleaks.json" --no-banner
    ;;
  common|*)
    run "semgrep"  semgrep --config p/owasp-top-ten --sarif -o "$OUT/semgrep-owasp.sarif" "$TARGET"
    run "trivy"    trivy fs --format sarif --output "$OUT/trivy.sarif" "$TARGET"
    run "gitleaks" gitleaks detect --source "$TARGET" --report-path "$OUT/gitleaks.json" --no-banner
    ;;
esac

note "salidas en: $OUT"
