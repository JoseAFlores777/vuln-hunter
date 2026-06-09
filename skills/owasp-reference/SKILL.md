---
name: owasp-reference
description: Referencia de OWASP Top 10 (2021 y 2025) para mapear hallazgos, suprimir falsos positivos por conocimiento de framework, y elegir el patron de fix de causa raiz. Usa este skill al clasificar vulnerabilidades, al decidir si un hallazgo es ruido (frameworks que auto-mitigan) y al proponer correcciones por stack (Django, Angular+.NET, Next.js).
---

# OWASP Reference (Top 10 2021 + 2025)

Mapea cada hallazgo a su categoria en AMBAS taxonomias y aplica conocimiento de
framework para no generar ruido. El detalle por categoria esta en
`references/` y se carga bajo demanda.

## Top 10:2021
A01 Broken Access Control · A02 Cryptographic Failures · A03 Injection ·
A04 Insecure Design · A05 Security Misconfiguration · A06 Vulnerable & Outdated
Components · A07 Identification & Authentication Failures · A08 Software & Data
Integrity Failures · A09 Security Logging & Monitoring Failures · A10 SSRF.

## Top 10:2025 (final ene-2026)
A01 Broken Access Control (absorbe SSRF) · A02 Security Misconfiguration ·
A03 **Software Supply Chain Failures** (nueva) · A04 Cryptographic Failures ·
A05 Injection · A06 Insecure Design · A07 Authentication Failures ·
A08 Software or Data Integrity Failures · A09 Security Logging & Alerting
Failures · A10 **Mishandling of Exceptional Conditions** (nueva).

## Supresion de ruido por framework (no reportar salvo excepcion)
- **React / Angular auto-escapan**: no hay XSS salvo `dangerouslySetInnerHTML`
  (React) o `bypassSecurityTrustHtml` / binding directo a `innerHTML` (Angular).
- **Django auto-escapa plantillas**: el riesgo es `mark_safe(input)`,
  `| safe`, o `format_html` mal usado. `django.conf.settings` es server-side,
  no input de usuario.
- **ORM parametriza por defecto**: SQLi solo en `raw()`, `extra()`, `RawSQL`,
  `cursor.execute(f"...")`, o `FromSqlRaw` concatenado en EF.
- Lenguajes memory-safe (Python/JS/C#): no apliquen issues de memoria nativa.

## Como usar el detalle
Para el patron de fix y los ejemplos por stack de una categoria, abre el archivo
correspondiente en `references/` (p. ej. `references/injection.md`,
`references/access-control.md`, `references/auth-jwt.md`,
`references/ssrf-supply-chain.md`).
