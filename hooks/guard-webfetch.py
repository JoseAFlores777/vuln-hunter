#!/usr/bin/env python3
"""
vuln-hunter :: guard-webfetch.py
Hook PreToolUse para WebFetch.

threat-intel-scout debe LEER solo fuentes oficiales (CLAUDE.md regla 5) y NUNCA
buscar/descargar exploits. El allowlist `tools:` no puede acotar WebFetch a hosts
concretos, asi que ese limite era solo texto del prompt. Este hook lo hace real:

  - Si la llamada WebFetch viene del subagente threat-intel-scout (lo dice el campo
    agent_type/agent_id de la entrada del hook), EXIGE que el host este en el
    allowlist de fuentes oficiales/avisos de vendor. Si no, BLOQUEA.
  - Para CUALQUIER otro contexto (loop principal u otros agentes), NO interfiere:
    permite (fail-open). Asi no rompe el WebFetch normal del usuario.

Si la entrada es ilegible o no trae agent_type, se PERMITE (no podemos atribuir la
llamada al agente acotado, y bloquear a ciegas romperia el uso general).

Contrato: exit 2 = BLOQUEA. 0 = permite.
"""
import json
import sys
from urllib.parse import urlparse

SCOPED_AGENT = "threat-intel-scout"

# Fuentes oficiales de vulnerabilidades + avisos de vendor que el agente consulta
# (las que threat-intel-scout.md lista). Extiende esta lista si una fuente oficial
# legitima queda fuera. NO se incluye el apex `github.com`: permitiria raw/gist
# (contenido controlable por atacante); solo `api.github.com` (GitHub Advisories API).
ALLOWED_HOSTS = {
    "nvd.nist.gov", "services.nvd.nist.gov",
    "osv.dev", "api.osv.dev",
    "first.org", "api.first.org",
    "cisa.gov", "www.cisa.gov",
    "api.github.com",                           # GitHub Security Advisories (API, no apex)
    "msrc.microsoft.com", "api.msrc.microsoft.com",
    "djangoproject.com", "www.djangoproject.com",
    "nodejs.org", "nextjs.org",
    "oracle.com", "www.oracle.com",             # Oracle Critical Patch Update
    "security-tracker.debian.org",
}


def host_allowed(host):
    host = (host or "").lower()
    if host in ALLOWED_HOSTS:
        return True
    return any(host.endswith("." + d) for d in ALLOWED_HOSTS)


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0  # no podemos atribuir; no rompemos el uso general

    agent = str(data.get("agent_type") or data.get("agent_id") or "")
    if SCOPED_AGENT not in agent:
        return 0  # solo acotamos al threat-intel-scout

    ti = data.get("tool_input", {}) or {}
    url = ti.get("url") or ""
    scheme = (urlparse(url).scheme or "").lower()
    host = urlparse(url).hostname or ""

    if scheme != "https" or not host_allowed(host):
        print(
            "BLOQUEADO por vuln-hunter: threat-intel-scout solo consulta fuentes "
            "OFICIALES por https (NVD, OSV, FIRST/EPSS, CISA KEV, GitHub Advisories, "
            "MSRC, avisos de vendor). Host pedido: '" + (host or "(ninguno)") + "'. "
            "La confirmacion de una vuln es por version afectada en el aviso oficial, "
            "no por buscar PoCs/exploits.",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
