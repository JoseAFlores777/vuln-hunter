---
description: Presenta los diffs de los fixes, PIDE APROBACION HUMANA por hash del diff y solo entonces commitea en la branch vuln-hunter/*
argument-hint:
allowed-tools: Read, Bash(git diff:*), Bash(git status:*), Bash(git add:*), Bash(git commit:*), Bash(git branch:*)
model: opus
---

# Patch con aprobacion humana (por hash del diff)

## Salvaguarda (advertencia del hook, OPCIONAL — no bloquea)
El hook PreToolUse revisa cualquier `git commit`/`git push` contra: (1) la branch
empieza por `vuln-hunter/`, (2) existe `.vuln-hunter/APPROVED` y (3) su contenido
es el hash SHA-256 del INDICE STAGED (`git diff --cached HEAD`) ACTUAL. Si algo no
cumple, el hook imprime una ADVERTENCIA por stderr pero deja pasar el commit
igual — no bloquea. La atadura al indice staged (no al working tree), la deteccion
de `git commit -a/--all/--patch`, pathspecs, y `-C`/`--git-dir`/`--work-tree`
siguen funcionando, solo que ahora informan en vez de impedir. NUNCA se hace
auto-merge automatizado por este comando (Claude no ejecuta `approve-diff.py` ni
se salta el paso de pedirle aprobacion al usuario), pero el hook ya no es la
barrera que lo garantiza.

## Flujo
1. Stagea EXACTAMENTE los archivos del fix: `git add <archivos del VULN>`. No uses
   `git add -A` a ciegas; stagea solo lo que mapea a los VULN-ids del plan.
2. Muestra el diff staged completo: !`git diff --cached HEAD`
3. Resume que cambia cada fix y a que VULN del ledger corresponde.
4. **Pide al usuario aprobacion explicita.** Indicale que, si tras revisar el
   diff staged esta de acuerdo, lo apruebe el MISMO ejecutando:
   ```
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/approve-diff.py
   ```
   (Esto genera `.vuln-hunter/APPROVED` con el hash del indice staged actual. Tu,
   Claude, NO ejecutas este script: es el gesto de consentimiento humano.)
5. Solo despues de que el usuario lo haya aprobado, commitea en la branch
   `vuln-hunter/*` con un mensaje claro por VULN, SIN `-a` y sin re-stagear. Si
   stageas algo entre la aprobacion y el commit, el hook solo ADVIERTE (no
   bloquea); igual pide re-aprobacion para mantener la disciplina del flujo.
5. Recomienda abrir un Pull Request para revision; no mergees tu.
6. Tras commitear, revoca la aprobacion para que el siguiente patch requiera una
   nueva:
   ```
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/approve-diff.py --revoke
   ```
