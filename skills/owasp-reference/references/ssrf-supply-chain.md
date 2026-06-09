# SSRF + Supply Chain + Integridad

## SSRF (OWASP-2025 dentro de A01 / OWASP-2021 A10) — CWE-918
Vulnerable: fetch server-side con URL controlada por el usuario (server actions
de Next.js, vistas Django, controllers .NET).
Fix: allowlist de hosts/esquemas; bloquear rangos privados y endpoints de
metadata (169.254.169.254); no seguir redirecciones a destinos no permitidos.

## Software Supply Chain Failures (OWASP-2025 A03) — componentes vulnerables
Detectar con SCA: `pip-audit`, `npm audit`, `dotnet list package --vulnerable`,
`trivy fs`, OWASP Dependency-Check. Fix: actualizar a la version parcheada
minima; fijar versiones (lockfiles); revisar integridad de paquetes.

## Software/Data Integrity (OWASP-2025 A08 / 2021 A08) — deserializacion insegura
Vulnerable: `pickle.loads(input)`, `yaml.load` inseguro (Python);
`BinaryFormatter`, `JavaScriptSerializer`, `TypeNameHandling.All` (Newtonsoft).
Fix: usar formatos/serializadores seguros (`json`, `yaml.safe_load`,
System.Text.Json sin polimorfismo no controlado); validar firmas/integridad.

## Mishandling of Exceptional Conditions (OWASP-2025 A10) — CWE-209, CWE-755
Vulnerable: stack traces y mensajes detallados al usuario; "fail open".
Fix: manejo de errores que falla de forma segura (deny by default), logging
server-side sin filtrar datos sensibles, mensajes genericos al cliente.
