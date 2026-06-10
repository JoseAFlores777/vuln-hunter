#!/usr/bin/env python3
"""
vuln-hunter :: guard-commit-and-exec.py
Hook PreToolUse para Bash.

Tres salvaguardas. NINGUNA es una barrera absoluta: un denylist de comandos shell
SIEMPRE es evadible (alias, wrappers, codificacion). La barrera PRINCIPAL del kit
es el allowlist de `tools:` por agente y la aprobacion HUMANA del diff. Este hook
es DEFENSA EN PROFUNDIDAD; aqui priorizamos fallar-cerrado y cubrir los bypass
obvios, no la cobertura total.

1) APROBACION DEL PATCHER POR HASH DEL INDICE STAGED. Bloquea `git commit` /
   `git push` (y otros subcomandos que producen commits) salvo que se cumplan
   TODAS estas condiciones:
     a. la branch actual empieza por "vuln-hunter/"
     b. existe el archivo de aprobacion ".vuln-hunter/APPROVED"
     c. su contenido == hash SHA-256 de `git diff --cached HEAD` ACTUAL (el INDICE
        staged, que es lo que REALMENTE se commitea — no el working tree).
   El parser de git tokeniza el comando (shlex) en vez de regexear la posicion del
   subcomando, asi `git -C dir commit`, `git -c k=v commit`, `commit-tree`, y los
   comandos compuestos no esquivan el gate. Se BLOQUEA tambien:
     - cualquier commit/push con redireccion de repo (`-C`/`--git-dir`/`--work-tree`)
       en vez de intentar seguirla (seguir el redirect es a su vez superficie de bypass).
     - `git commit -a/--all/--patch` y pathspecs, que re-stagean en el momento del
       commit y por tanto divergen del indice aprobado.

2) BARRERA DE EJECUCION OFENSIVA (best-effort). Bloquea comandos con forma de
   ataque (shell inverso, descarga|ejecucion, brute-force). Evadible por diseno;
   el control real es el allowlist `tools:` de cada agente.

3) GATE DE DESPLIEGUE. Si el comando parece un deploy y existe
   ".vuln-hunter/deploy-blocked", bloquea. Ese archivo lo escribe de forma
   DETERMINISTA scripts/deploy-gate.py a partir del ledger (CVE en KEV en prod).

Contrato: exit code 2 = BLOQUEA (unico codigo que deniega de forma fiable). 0 = permite.
Entrada ilegible -> se DENIEGA (fail-closed), porque es un hook de seguridad.
"""
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys

BRANCH_PREFIX = "vuln-hunter/"

# Subcomandos de git que producen un commit / avanzan una ref.
COMMIT_SUBCMDS = {
    "commit", "commit-tree", "push", "merge", "am",
    "cherry-pick", "revert", "rebase",
}
# Opciones globales de git que consumen un argumento aparte.
GLOBAL_OPTS_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--exec-path", "--namespace"}
# Opciones globales que REDIRIGEN el contexto del repo (las bloqueamos en commits).
REDIRECT_OPTS = {"-C", "--git-dir", "--work-tree"}
# Separadores de comando shell (tokens) que delimitan segmentos.
SHELL_SEPARATORS = {";", "&", "|", "&&", "||", "(", ")", "<", ">", "\n"}

DEPLOY_RE = re.compile(
    r"\b(deploy|release|publish|rollout|provision)\b"
    r"|\bkubectl\s+(apply|rollout|set\s+image|create)\b"
    r"|\bhelm\s+(install|upgrade)\b"
    r"|\b(docker|podman)\s+push\b"
    r"|\b(terraform|pulumi)\s+(apply|up)\b"
    r"|\bansible-playbook\b"
    r"|\baws\s+(ecs|lambda|s3|cloudformation)\b"
    r"|\bgcloud\s+(run|app|functions)\s+deploy\b"
    r"|\baz\s+(webapp|functionapp|containerapp)\b"
    r"|\b(serverless|sls|sam|cdk)\s+deploy\b"
    r"|\b(vercel|netlify|heroku|flyctl|fly)\s+(deploy|push|release)\b",
    re.IGNORECASE,
)

# Ejecucion ofensiva (best-effort, denylist). Anclamos los nombres de herramienta
# de fuerza bruta a una posicion de INVOCACION para no bloquear `git commit -m "john ..."`.
_CMD_START = r"(?:^|[;&|`]|&&|\|\||\$\(|\bsudo\s+)\s*"
OFFENSIVE_EXEC = [
    re.compile(r"\bnc\b.{0,30}-e\b", re.IGNORECASE),
    re.compile(r"\bncat\b.{0,30}(-e|--exec)\b", re.IGNORECASE),
    re.compile(r"(curl|wget)\b[^\n;|&]{0,200}\|\s*(sh|bash|python|perl|ruby)\b", re.IGNORECASE),
    re.compile(r"/dev/tcp/", re.IGNORECASE),
    re.compile(r"\b(sh|bash)\b\s+-i\b", re.IGNORECASE),
    re.compile(r"\bpython\d?\b.{0,80}(pty\.spawn|socket\.socket.{0,80}connect)", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bperl\b.{0,80}Socket::INET", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bphp\b.{0,80}fsockopen", re.IGNORECASE | re.DOTALL),
    re.compile(r"msfvenom|meterpreter", re.IGNORECASE),
    re.compile(_CMD_START + r"(?:sudo\s+)?(hydra|medusa|hashcat|john)\b", re.IGNORECASE),
]


def project_root():
    """Ancla deterministica para los archivos de estado y las llamadas a git.
    No dependemos del CWD implicito del proceso del hook."""
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env and os.path.isdir(env):
        return env
    cur = os.getcwd()
    while True:
        if os.path.isdir(os.path.join(cur, ".vuln-hunter")):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        if top:
            return top
    except Exception:
        pass
    return os.getcwd()


ROOT = project_root()
APPROVAL_FILE = os.path.join(ROOT, ".vuln-hunter", "APPROVED")
DEPLOY_BLOCK_FILE = os.path.join(ROOT, ".vuln-hunter", "deploy-blocked")


def git(args):
    """Corre git anclado a ROOT (`git -C ROOT ...`) para no depender del CWD."""
    try:
        return subprocess.run(
            ["git", "-C", ROOT] + args,
            capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception:
        return ""


def current_branch():
    return git(["branch", "--show-current"]).strip()


def staged_diff_hash():
    """Hash del INDICE staged (lo que de verdad se commitea), no del working tree."""
    diff = git(["diff", "--cached", "HEAD"])
    return hashlib.sha256(diff.encode("utf-8", "replace")).hexdigest()


def tokenize(cmd):
    """Tokeniza el comando separando los operadores shell aunque esten pegados.
    Solo para INSPECCION (no se ejecuta), asi que normalizar espacios es seguro.
    Devuelve None si es inparseable (caller actua conservador)."""
    norm = re.sub(r"([;&|()<>])", r" \1 ", cmd)
    try:
        return shlex.split(norm, posix=True)
    except ValueError:
        return None


def git_invocations(cmd):
    """Lista de (subcomando, redirigido, args) por cada invocacion `git ...` del
    comando (incluye comandos compuestos). None si el comando es inparseable."""
    toks = tokenize(cmd)
    if toks is None:
        return None
    out = []
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t == "git" or t.endswith("/git"):
            j = i + 1
            redirected = False
            while j < n:
                tk = toks[j]
                if tk in GLOBAL_OPTS_WITH_ARG:
                    if tk in REDIRECT_OPTS:
                        redirected = True
                    j += 2
                    continue
                if tk.startswith("--git-dir") or tk.startswith("--work-tree"):
                    redirected = True
                    j += 1
                    continue
                if tk.startswith("-"):  # otra opcion global (--no-pager, -p, ...)
                    j += 1
                    continue
                break
            sub = toks[j] if j < n else ""
            # args hasta el siguiente separador shell
            args = []
            k = j + 1
            while k < n and toks[k] not in SHELL_SEPARATORS:
                args.append(toks[k])
                k += 1
            out.append((sub, redirected, args))
            i = j + 1
            continue
        i += 1
    return out


def commit_restages_index(args):
    """True si los args de `git commit` re-stagean en el momento del commit
    (`-a/--all/--patch` o pathspecs), divergiendo del indice aprobado."""
    OPTS_WITH_VALUE = {"-m", "-F", "-C", "-c", "--author", "--date", "--message",
                       "--file", "--reuse-message", "--reedit-message", "--fixup", "--squash",
                       "--gpg-sign", "-S", "--template", "-t"}
    i, n = 0, len(args)
    while i < n:
        a = args[i]
        if a in ("-a", "--all", "-A", "--patch", "-p", "--interactive", "-i", "--include", "--only"):
            return True
        if a == "--":
            # todo lo que sigue es pathspec
            return i + 1 < n
        if a.startswith("-"):
            # opcion con valor pegado (--message=...) o suelta
            if "=" in a:
                i += 1
                continue
            if a in OPTS_WITH_VALUE:
                i += 2
                continue
            i += 1
            continue
        # token que no empieza por '-' y no es valor de opcion -> pathspec
        return True
    return False


def deny(msg):
    print(msg, file=sys.stderr)
    return 2


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        return deny(
            "vuln-hunter: no se pudo leer/parsear la entrada del hook; se DENIEGA "
            "por seguridad (fail-closed)."
        )

    cmd = (data.get("tool_input", {}) or {}).get("command", "") or ""

    # --- 2: ejecucion ofensiva (best-effort) ---
    for pat in OFFENSIVE_EXEC:
        if pat.search(cmd):
            return deny(
                "BLOQUEADO por vuln-hunter: comando con forma ofensiva (shell "
                "inverso / descarga-ejecucion / brute-force). El trabajo es "
                "defensivo; la explotabilidad se demuestra de forma CONCEPTUAL."
            )

    # --- 3: gate de despliegue ---
    if DEPLOY_RE.search(cmd) and os.path.exists(DEPLOY_BLOCK_FILE):
        reason = ""
        try:
            with open(DEPLOY_BLOCK_FILE) as fh:
                reason = fh.read().strip()
        except Exception:
            pass
        return deny(
            "BLOQUEADO por vuln-hunter (gate de despliegue): hay dependencias de "
            "produccion con CVE en CISA KEV o EPSS alto.\n" + reason +
            "\nParchea y vuelve a correr /vuln-hunter:watch --gate antes de desplegar."
        )

    # --- 1: aprobacion del patcher por hash del indice staged ---
    invs = git_invocations(cmd)
    if invs is None:
        # Inparseable: si menciona git, lo tratamos como intento de commit (conservador).
        commit_like = [("commit", False, [])] if re.search(r"\bgit\b", cmd) else []
    else:
        commit_like = [(s, r, a) for (s, r, a) in invs if s in COMMIT_SUBCMDS]

    if commit_like:
        for sub, redirected, args in commit_like:
            if redirected:
                return deny(
                    "BLOQUEADO por vuln-hunter: un commit/push no puede redirigir el "
                    "repo con -C/--git-dir/--work-tree (evade el gate de aprobacion)."
                )
            if sub == "commit" and commit_restages_index(args):
                return deny(
                    "BLOQUEADO por vuln-hunter: `git commit` con -a/--all/--patch o "
                    "pathspecs re-stagea en el momento del commit y diverge del indice "
                    "aprobado. Stagea con `git add` lo exacto, aprueba, y commitea sin "
                    "esos flags."
                )

        branch = current_branch()
        if not branch.startswith(BRANCH_PREFIX):
            return deny(
                f"BLOQUEADO por vuln-hunter: el patcher solo commitea en una branch "
                f"'{BRANCH_PREFIX}*'. Branch actual: '{branch or '(desconocida)'}'."
            )
        if not os.path.exists(APPROVAL_FILE):
            return deny(
                "BLOQUEADO por vuln-hunter: falta la aprobacion humana. Stagea el fix "
                "(`git add`), revisa el diff y, si estas de acuerdo, aprueba ESTE indice "
                "exacto con:\n"
                "  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/approve-diff.py\n"
                "(genera .vuln-hunter/APPROVED con el hash del indice staged)."
            )
        try:
            with open(APPROVAL_FILE) as fh:
                approved_hash = fh.read().strip()
        except Exception:
            approved_hash = ""
        actual_hash = staged_diff_hash()
        if approved_hash != actual_hash:
            return deny(
                "BLOQUEADO por vuln-hunter: la aprobacion no corresponde al indice "
                "staged actual (cambio despues de aprobar). Re-stagea lo exacto y "
                "re-aprueba con:\n"
                "  python3 ${CLAUDE_PLUGIN_ROOT}/scripts/approve-diff.py\n"
                f"  aprobado: {approved_hash[:12]}...  actual: {actual_hash[:12]}..."
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
