#!/usr/bin/env python3
"""
vuln-hunter :: approve-diff.py
Gesto de aprobacion HUMANA del patch.

Lo ejecuta la PERSONA (no un agente) tras revisar el diff. Calcula el hash
SHA-256 del INDICE STAGED (`git diff --cached HEAD`) actual y lo escribe en
.vuln-hunter/APPROVED. El hook guard-commit-and-exec.py solo deja commitear si el
indice staged en el momento del commit sigue teniendo ese mismo hash: la
aprobacion se ata a lo que REALMENTE se commitea (el indice), no al working tree.

IMPORTANTE: stagea con `git add` EXACTAMENTE los cambios revisados ANTES de
aprobar. La aprobacion cubre el indice staged; si despues stageas/desestageas algo
(o usas `git commit -a`), el hash deja de coincidir y el commit se vuelve a
bloquear.

Uso:
    python3 scripts/approve-diff.py          # aprueba el indice staged actual
    python3 scripts/approve-diff.py --show    # solo muestra el hash, no aprueba
    python3 scripts/approve-diff.py --revoke  # elimina la aprobacion
"""
import hashlib
import os
import subprocess
import sys

APPROVAL_DIR = ".vuln-hunter"
APPROVAL_FILE = os.path.join(APPROVAL_DIR, "APPROVED")


def diff_hash() -> str:
    diff = subprocess.run(
        ["git", "diff", "--cached", "HEAD"], capture_output=True, text=True
    ).stdout
    return hashlib.sha256(diff.encode("utf-8", "replace")).hexdigest()


def main() -> int:
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    os.makedirs(APPROVAL_DIR, exist_ok=True)

    if arg == "--revoke":
        if os.path.exists(APPROVAL_FILE):
            os.remove(APPROVAL_FILE)
            print("vuln-hunter: aprobacion revocada.")
        else:
            print("vuln-hunter: no habia aprobacion que revocar.")
        return 0

    h = diff_hash()
    if not h or h == hashlib.sha256(b"").hexdigest():
        print(
            "vuln-hunter: el indice staged esta vacio; no hay nada que aprobar. "
            "Stagea primero el fix con `git add <archivos>` y vuelve a aprobar.",
            file=sys.stderr,
        )
        return 1

    if arg == "--show":
        print(f"hash del indice staged actual: {h}")
        return 0

    with open(APPROVAL_FILE, "w") as fh:
        fh.write(h)
    print(
        "vuln-hunter: indice staged APROBADO.\n"
        f"  hash: {h[:16]}...\n"
        "  El commit en la branch vuln-hunter/* quedara permitido SOLO mientras el\n"
        "  indice staged no cambie. Si stageas/desestageas mas (o usas commit -a),\n"
        "  vuelve a ejecutar este script."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
