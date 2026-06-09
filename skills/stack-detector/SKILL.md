---
name: stack-detector
description: Detecta y clasifica los stacks de un proyecto o monorepo (Python/Django, Next.js/React/TS, Angular, .NET/C#) por archivos marcadores y delimita el subarbol de cada paquete, para hacer scoping por paquete al escanear. Usa este skill cuando haya que identificar que herramientas SAST/SCA corresponden a cada parte del repo.
---

# Stack Detector (scoping de monorepo)

Identifica cada paquete/subproyecto del repo y le asigna su stack y sus
escaneres, para que cada herramienta corra solo sobre el subarbol correcto. Esto
evita falsos positivos cross-paquete y acelera los escaneos.

## Marcadores por stack
| Stack | Archivos marcadores | Escaneres a usar |
|---|---|---|
| `django` | `manage.py`, `requirements.txt`, `pyproject.toml` con Django, `settings.py` | `bandit`, `semgrep:p/django`, `semgrep:p/python`, `pip-audit`, `gitleaks` |
| `python` (no Django) | `requirements.txt`, `pyproject.toml`, `*.py` | `bandit`, `semgrep:p/python`, `pip-audit`, `gitleaks` |
| `nextjs` | `next.config.js/ts/mjs`, `package.json` con `next` | `eslint:security`, `semgrep:p/javascript`, `semgrep:p/typescript`, `npm audit`, `gitleaks` |
| `react` | `package.json` con `react` (sin `next`) | `eslint:security`, `semgrep:p/javascript`, `npm audit`, `gitleaks` |
| `angular` | `angular.json` | `eslint:security`, `semgrep:p/typescript`, `npm audit`, `gitleaks` |
| `dotnet` | `*.csproj`, `*.sln` | Security Code Scan + Roslyn (`dotnet build -warnaserror`), `semgrep:p/csharp`, `dotnet list package --vulnerable`, `gitleaks` |

Multi-lenguaje (siempre, sobre la raiz): `semgrep:p/owasp-top-ten`, `trivy fs`,
`gitleaks detect`. CodeQL si esta disponible en el entorno.

## Procedimiento
1. Recorre el repo (respetando `.gitignore`) buscando los marcadores; un mismo
   repo puede tener varios paquetes de stacks distintos (caso monorepo).
2. Para cada paquete, fija su `path` (subarbol), su `stack` y su lista de
   `scanners`.
3. Escribe el resultado en `.vuln-hunter/stacks.json`:
```json
{
  "packages": [
    { "path": "apps/example-app", "stack": "django",  "scanners": ["bandit","semgrep:p/django","pip-audit","gitleaks"] },
    { "path": "apps/example-web", "stack": "nextjs",  "scanners": ["eslint:security","semgrep:p/typescript","npm audit","gitleaks"] },
    { "path": "services/example-api", "stack": "dotnet",  "scanners": ["security-code-scan","semgrep:p/csharp","dotnet-vulnerable","gitleaks"] }
  ],
  "root_scanners": ["semgrep:p/owasp-top-ten","trivy","gitleaks"]
}
```
4. Si un paquete mezcla stacks (p. ej. un front Angular dentro de un proyecto
   .NET), registra ambos.

## Notas
- Prefiere SARIF como salida comun de los escaneres (`-f sarif` / `--sarif`).
- No ejecutes los escaneres aqui; este skill solo clasifica y delimita scope.
