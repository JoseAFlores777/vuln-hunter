#!/usr/bin/env python3
"""
vuln-hunter :: guard-commit-and-exec.py
Hook PreToolUse para Bash.

Tres salvaguardas:

1) APROBACION DEL PATCHER POR HASH DEL DIFF (mejorada). Bloquea `git commit` /
   `git push` salvo que se cumplan TODAS estas condiciones:
     a. la branch actual empieza por "vuln-hunter/"
     b. existe el archivo de aprobacion ".vuln-hunter/APPROVED"
     c. el contenido de ese archivo == hash SHA-256 del `git diff HEAD` ACTUAL.
        Asi la aprobacion es POR CAMBIO concreto: si el diff cambia despues de
        aprobar, el hash deja de coincidir y se bloquea. Corrige el fallo de la
        version anterior, donde un unico `touch APPROVED` autorizaba cualquier
        commit posterior.

2) BARRERA DE EJECUCION OFENSIVA. Bloquea comandos con forma de ataque
   (shell inverso, descarga|ejecucion, brute-force). El analisis es CONCEPTUAL.

3) GATE DE DESPLIEGUE. Si el comando parece un deploy y existe
   ".vuln-hunter/deploy-blocked", bloquea (lo escribe el flujo de threat-intel
   cuando hay un CVE en KEV en produccion).

Contrato: exit code 2 = BLOQUEA (unico codigo que deniega de forma fiable). 0 = permite.
"""
import hashlib
import json
import os
import re
import subprocess
import sys

COMMIT_RE = re.compile(r"\bgit\s+(commit|push)\b")
DEPLOY_RE = re.compile(r"\b(deploy|release|publish)\b", re.IGNORECASE)
APPROVAL_FILE = ".vuln-hunter/APPROVED"
DEPLOY_BLOCK_FILE = ".vuln-hunter/deploy-blocked"
BRANCH_PREFIX = "vuln-hunter/"

OFFENSIVE_EXEC = [
    re.compile(r"\bnc\b.{0,30}-e\b", re.IGNORECASE),
    re.compile(r"(curl|wget)\b.{0,120}\|\s*(sh|bash)\b", re.IGNORECASE),
    re.compile(r"/dev/tcp/", re.IGNORECASE),
    re.compile(r"msfvenom|meterpreter", re.IGNORECASE),
    re.compile(r"\b(hydra|medusa|hashcat|john)\b", re.IGNORECASE),
]


def sh(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ""


def current_branch():
    return sh(["git", "branch", "--show-current"]).strip()


def current_diff_hash():
    diff = sh(["git", "diff", "HEAD"])
    return hashlib.sha256(diff.encode("utf-8", "replace")).hexdigest()


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        print("vuln-hunter: no se pudo leer la entrada del hook", file=sys.stderr)
        return 0

    cmd = (data.get("tool_input", {}) or {}).get("command", "") or ""

    # --- 2: ejecucion ofensiva ---
    for pat in OFFENSIVE_EXEC:
        if pat.search(cmd):
            print(
                "BLOQUEADO por vuln-hunter: comando con forma ofensiva (shell "
                "inverso / descarga-ejecucion / brute-force). El trabajo es "
                "defensivo; la explotabilidad se demuestra de forma CONCEPTUAL.",
                file=sys.stderr,
            )
            return 2

    # --- 3: gate de despliegue ---
    if DEPLOY_RE.search(cmd) and os.path.exists(DEPLOY_BLOCK_FILE):
        reason = ""
        try:
            with open(DEPLOY_BLOCK_FILE) as fh:
                reason = fh.read().strip()
        except Exception:
            pass
        print(
            "BLOQUEADO por vuln-hunter (gate de despliegue): hay dependencias de "
            "produccion con CVE en CISA KEV o EPSS alto.\n" + reason +
            "\nParchea y vuelve a correr /vuln-hunter:watch --gate antes de desplegar.",
            file=sys.stderr,
        )
        return 2

    # --- 1: aprobacion del patcher por hash del diff ---
    if COMMIT_RE.search(cmd):
        branch = current_branch()
        if not branch.startswith(BRANCH_PREFIX):
            print(
                f"BLOQUEADO por vuln-hunter: el patcher solo commitea en una branch "
                f"'{BRANCH_PREFIX}*'. Branch actual: '{branch or '(desconocida)'}'.",
                file=sys.stderr,
            )
            return 2
        if not os.path.exists(APPROVAL_FILE):
            print(
                "BLOQUEADO por vuln-hunter: falta la aprobacion humana. Revisa el "
                "diff y, si estas de acuerdo, aprueba ESTE diff exacto con:\n"
                "  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/approve-diff.py\n"
                "(genera .vuln-hunter/APPROVED con el hash del diff actual).",
                file=sys.stderr,
            )
            return 2
        try:
            with open(APPROVAL_FILE) as fh:
                approved_hash = fh.read().strip()
        except Exception:
            approved_hash = ""
        actual_hash = current_diff_hash()
        if approved_hash != actual_hash:
            print(
                "BLOQUEADO por vuln-hunter: la aprobacion no corresponde al diff "
                "actual (el codigo cambio despues de aprobar). Vuelve a revisar y "
                "re-aprueba con:\n"
                "  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/approve-diff.py\n"
                f"  aprobado: {approved_hash[:12]}...  actual: {actual_hash[:12]}...",
                file=sys.stderr,
            )
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
