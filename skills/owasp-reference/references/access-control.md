# Broken Access Control (OWASP-2025 A01 / OWASP-2021 A01) — CWE-862, CWE-639

## IDOR (todos los stacks)
Vulnerable: endpoint que usa un ID del cliente sin verificar ownership/rol.
Fix: verificacion server-side de propiedad y rol en CADA endpoint; nunca confiar
en IDs ni en logica de autorizacion del cliente.

## Django
- Vistas sin `@login_required` / `PermissionRequiredMixin` / checks de objeto.
- Querysets que no filtran por el usuario actual (`.filter(owner=request.user)`).

## .NET
- Falta de `[Authorize(Roles=...)]`; comprobacion de ownership ausente en el
  controller/handler.

## Next.js — CVE-2025-29927 (bypass de middleware)
No confiar SOLO en el middleware para autorizar (un header
`x-middleware-subrequest` permitia saltarselo en versiones afectadas). Fix:
actualizar Next.js a la version parcheada y aplicar controles tambien a nivel de
ruta/route handler; stripear el header en el proxy/CDN.
