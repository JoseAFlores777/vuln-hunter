# LAB vuln-hunter — vulnerabilidades PLANTADAS a proposito (no usar en prod)
from django.db import connection
from django.http import JsonResponse

SECRET_KEY = "django-insecure-hardcoded-1234567890"   # PLANTADA: secreto en codigo (A02/A05)
DEBUG = True                                            # PLANTADA: debug en prod (A02)

def search_users(request):
    term = request.GET.get("q", "")
    # PLANTADA: SQL injection via f-string en raw query (A03/A05 Injection, CWE-89)
    with connection.cursor() as cur:
        cur.execute(f"SELECT id, username FROM auth_user WHERE username LIKE '%{term}%'")
        rows = cur.fetchall()
    return JsonResponse({"results": rows})

def safe_search_users(request):
    term = request.GET.get("q", "")
    # CORRECTO (control negativo): parametrizado, no debe marcarse como vuln
    with connection.cursor() as cur:
        cur.execute("SELECT id, username FROM auth_user WHERE username LIKE %s", [f"%{term}%"])
        return JsonResponse({"results": cur.fetchall()})
