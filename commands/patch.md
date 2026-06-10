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
contenido sea el hash SHA-256 del INDICE STAGED (`git diff --cached HEAD`) ACTUAL.
La aprobacion se ata a lo que REALMENTE se commitea (el indice staged), no al
working tree: si stageas/desestageas algo despues de aprobar, el commit se vuelve
a bloquear. El hook ademas RECHAZA `git commit -a/--all/--patch`, pathspecs en el
commit, y commits con `-C`/`--git-dir`/`--work-tree` (todos re-stagean o redirigen
el repo y romperian la atadura al indice aprobado). NUNCA se hace auto-merge.

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
   stageas algo entre la aprobacion y el commit, el hook bloqueara: pide
   re-aprobacion.
5. Recomienda abrir un Pull Request para revision; no mergees tu.
6. Tras commitear, revoca la aprobacion para que el siguiente patch requiera una
   nueva:
   ```
   python3 ${CLAUDE_PLUGIN_ROOT}/scripts/approve-diff.py --revoke
   ```
