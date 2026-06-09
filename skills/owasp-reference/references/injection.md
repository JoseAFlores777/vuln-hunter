# Injection (OWASP-2025 A05 / OWASP-2021 A03) — CWE-89, CWE-79, CWE-78

## Django + MySQL (SQLi)
Patron vulnerable:
- `cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{term}%'")`
- `.raw()`, `.extra()`, `RawSQL` con input concatenado.
Fix de causa raiz (parametrizar):
- `cursor.execute("SELECT * FROM users WHERE name LIKE %s", [f"%{term}%"])`
- Preferir el ORM (`Model.objects.filter(name__icontains=term)`).
Cheat Sheet: SQL Injection Prevention; Query Parameterization.

## .NET / C# (SQLi)
Vulnerable: concatenacion en ADO.NET o `context.Users.FromSqlRaw($"... {input}")`.
Fix: parametros (`SqlParameter`), LINQ tipado, o `FromSqlInterpolated` con
parametros reales. Roslyn CA2100 lo detecta; tratar como error en CI.

## XSS (todos)
React/Angular auto-escapan. Vulnerable solo con `dangerouslySetInnerHTML`,
`bypassSecurityTrustHtml`, binding a `innerHTML`, o `mark_safe(input)` en Django.
Fix: no inyectar HTML crudo; si es imprescindible, sanitizar con libreria
probada (DOMPurify) y encoding contextual.

## Command injection
Vulnerable: `os.system`, `subprocess(..., shell=True)` con input; `Process` con
string concatenado en .NET.
Fix: pasar argumentos como lista/array, sin shell; validar contra allowlist.
