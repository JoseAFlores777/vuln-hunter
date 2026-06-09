# Authentication / JWT-OIDC (OWASP-2025 A07 / OWASP-2021 A07) — CWE-287, CWE-345

## Validacion de JWT (Keycloak / OIDC)
Errores tipicos: no fijar el algoritmo (algorithm confusion), no validar `aud`,
`iss` ni `exp`, no usar JWKS con rotacion de claves (`kid`).
Fix:
- Fijar `algorithms: ['RS256']` (no aceptar `none` ni HS/RS confusion).
- Validar `issuer` y `audience`, y `exp` con tolerancia de reloj ~30s.
- Cachear JWKS y respetar rotacion por `kid`.

## Angular (cliente publico)
- Authorization Code + PKCE; deshabilitar Implicit Flow y Direct Access Grants.
- Sin client secret en el front; sin logica de authz solo en cliente.

## .NET (resource server)
- Validar el token en cada request (middleware de autenticacion JWT bien
  configurado: Authority, Audience, ValidateIssuer/Audience/Lifetime = true).
