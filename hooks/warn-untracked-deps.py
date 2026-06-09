#!/usr/bin/env python3
"""
vuln-hunter :: warn-untracked-deps.py
Hook PreToolUse (Write|Edit) — DEFENSA EN PROFUNDIDAD del contrato de
trazabilidad del fixer (ver docs/adr/0002-fixer-traceability-contract.md).

Avisa (NO bloquea) cuando se va a modificar un manifest/lockfile de dependencias
sin que exista un finding SCA en el ledger que lo respalde. Asi el usuario nunca
ve una dependencia movida "sin razon": o hay un hallazgo que lo explica, o sale
una advertencia determinista pidiendo crearlo (threat-intel-scout).

Contrato del hook: exit 0 SIEMPRE (es advisory). El mensaje va a stderr; el
flujo continua. No es un bloqueo: la decision de subir la dep sigue siendo del
fixer/usuario, pero queda registrada la advertencia.
"""
import json
import os
import sys

LEDGER = ".vuln-hunter/ledger.json"

# Archivos que declaran/fijan dependencias de terceros.
MANIFESTS = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "pipfile",
    "pipfile.lock", "poetry.lock", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "packages.config", "go.mod", "go.sum", "gemfile", "gemfile.lock",
    "composer.json", "composer.lock",
}
MANIFEST_SUFFIXES = (".csproj", ".vbproj", ".fsproj")


def is_manifest(path):
    base = os.path.basename(path or "").lower()
    if base in MANIFESTS:
        return True
    if base.startswith("requirements") and base.endswith(".txt"):
        return True
    return base.endswith(MANIFEST_SUFFIXES)


def has_sca_finding():
    """True si el ledger ya tiene al menos un finding de dependencias (SCA)."""
    try:
        with open(LEDGER) as fh:
            L = json.load(fh)
    except Exception:
        return False
    for f in L.get("findings", []):
        if not isinstance(f, dict):
            continue
        if f.get("source") in ("sca", "threat-intel"):
            return True
        if f.get("intel"):
            return True
    return False


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    path = (data.get("tool_input", {}) or {}).get("file_path", "") or ""
    if is_manifest(path) and not has_sca_finding():
        print(
            "vuln-hunter (aviso, no bloqueo): vas a modificar un manifest/lockfile "
            f"de dependencias ('{os.path.basename(path)}') pero el ledger no tiene "
            "ningun finding SCA que lo respalde.\n"
            "Contrato de trazabilidad (ADR 0002): un bump de dependencia debe nacer "
            "de un hallazgo. Corre /vuln-hunter:watch (threat-intel-scout) para crear "
            "el finding SCA antes de subir la dependencia, o asegurate de que el "
            "cambio corresponde a un VULN-id del plan.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
