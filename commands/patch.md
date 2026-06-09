---
description: Presenta los diffs de los fixes, PIDE APROBACION HUMANA por hash del diff y solo entonces commitea en la branch vuln-hunter/*
argument-hint:
allowed-tools: Read, Bash(git diff:*), Bash(git status:*), Bash(git add:*), Bash(git commit:*), Bash(git branch:*)
model: opus
---

# Patch con aprobacion humana (por hash del diff)

## Salvaguarda (impuesta por hook)
El hook PreToolUse bloquea cualquier `git commit`/`git push` salvo que: (1) la
branch empiece por `vuln-hunter/`, (2) exista `.vuln-hunter/APPROVED` y (3) su
contenido sea el hash SHA-256 del `git diff HEAD` ACTUAL. Es decir, la aprobacion
cubre UN diff concreto: si el codigo cambia despues de aprobar, el commit se
vuelve a bloquear. NUNCA se hace auto-merge.

## Flujo
1. Muestra el diff completo de los fixes: !`git diff HEAD`
2. Resume que cambia cada fix y a que VULN del ledger corresponde.
3. **Pide al usuario aprobacion explicita.** Indicale que, si tras revisar el
   diff esta de acuerdo, lo apruebe el MISMO ejecutando:
   ```
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/approve-diff.py
   ```
   (Esto genera `.vuln-hunter/APPROVED` con el hash del diff actual. Tu, Claude,
   NO ejecutas este script: es el gesto de consentimiento humano.)
4. Solo despues de que el usuario lo haya aprobado, commitea en la branch
   `vuln-hunter/*` con un mensaje claro por VULN. Si editaste algo entre la
   aprobacion y el commit, el hook bloqueara: pide re-aprobacion.
5. Recomienda abrir un Pull Request para revision; no mergees tu.
6. Tras commitear, revoca la aprobacion para que el siguiente patch requiera una
   nueva:
   ```
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/approve-diff.py --revoke
   ```
