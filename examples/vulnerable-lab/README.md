# Laboratorio de vulnerabilidades plantadas (vuln-hunter)

Repo MINIMO con vulnerabilidades PLANTADAS A PROPOSITO para validar el plugin:
medir cuantas encuentra y cuantas inventa. **No uses este codigo en produccion.**

## Vulnerabilidades plantadas (ground truth)
| # | Archivo | Tipo | OWASP 2025 | CWE | Quien debe detectarla |
|---|---|---|---|---|---|
| 1 | django_app/views.py | SQLi raw f-string | A05 Injection | CWE-89 | sast-analyst |
| 2 | django_app/views.py | Secreto hardcodeado | A02 Misconfig | CWE-798 | sast-analyst |
| 3 | django_app/views.py | DEBUG=True | A02 Misconfig | CWE-489 | sast-analyst |
| 4 | django_app/requirements.txt | Django 3.2.4 / requests 2.19.1 / PyYAML 5.1 con CVEs | A03 Supply Chain | varias | threat-intel-scout |
| 5 | next_app/page.jsx | XSS dangerouslySetInnerHTML | A05 Injection | CWE-79 | sast-analyst |
| 6 | next_app/page.jsx | Secreto en NEXT_PUBLIC_ | A02 Misconfig | CWE-200 | sast-analyst |
| 7 | next_app/package.json | next 13.4.0 / lodash 4.17.4 con CVEs | A03 Supply Chain | varias | threat-intel-scout |
| 8 | dotnet_app/UserRepo.cs | SQLi concatenacion | A05 Injection | CWE-89 | sast-analyst |
| 9 | dotnet_app/packages.config | Newtonsoft.Json 9.0.1 con CVE | A03 Supply Chain | varias | threat-intel-scout |

## Controles negativos (NO deben marcarse)
- django_app/views.py :: safe_search_users() — query parametrizada correcta.

## Como validar
1. `/vuln-hunter:detect examples/vulnerable-lab`
2. `/vuln-hunter:hunt examples/vulnerable-lab --dry-run`
3. Compara el ledger contra esta tabla: cuenta verdaderos positivos (de 9),
   falsos negativos (plantadas no encontradas) y falsos positivos (incluido el
   control negativo). Ese numero te dice si el plugin es util o teatro.
