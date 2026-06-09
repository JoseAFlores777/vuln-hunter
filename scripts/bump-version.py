#!/usr/bin/env python3
"""
vuln-hunter :: bump-version.py
Fuente unica de la version del plugin. Mantiene SINCRONIZADOS los tres campos de
version que Claude Code y el marketplace leen:

  .claude-plugin/plugin.json      -> "version"
  .claude-plugin/marketplace.json -> "metadata"."version"
  .claude-plugin/marketplace.json -> "plugins"[*]."version"

Uso:
  python3 scripts/bump-version.py 1.3.0      # fija la version (X.Y.Z) en todos
  python3 scripts/bump-version.py --check 1.3.0   # verifica que todos == 1.3.0
  python3 scripts/bump-version.py --check          # verifica consistencia interna
  python3 scripts/bump-version.py --print          # imprime la version actual

Lo usan: release.yml (sincroniza al tag) y ci.yml (valida consistencia).
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN = os.path.join(ROOT, ".claude-plugin", "plugin.json")
MARKET = os.path.join(ROOT, ".claude-plugin", "marketplace.json")
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _load(path):
    with open(path) as fh:
        return json.load(fh)


def _save(path, data):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def collect_versions():
    """Devuelve [(etiqueta, valor)] de cada campo de version."""
    plugin = _load(PLUGIN)
    market = _load(MARKET)
    out = [("plugin.json:version", plugin.get("version"))]
    out.append(("marketplace.json:metadata.version", (market.get("metadata") or {}).get("version")))
    for i, p in enumerate(market.get("plugins") or []):
        out.append((f"marketplace.json:plugins[{i}].version", p.get("version")))
    return out


def set_version(v):
    plugin = _load(PLUGIN)
    market = _load(MARKET)
    plugin["version"] = v
    market.setdefault("metadata", {})["version"] = v
    for p in market.get("plugins") or []:
        p["version"] = v
    _save(PLUGIN, plugin)
    _save(MARKET, market)


def cmd_check(target=None):
    vs = collect_versions()
    vals = [val for _, val in vs]
    ok = True
    if target is not None:
        for label, val in vs:
            if val != target:
                print(f"MISMATCH {label} = {val!r} (esperado {target!r})", file=sys.stderr)
                ok = False
    else:
        if len(set(vals)) != 1:
            for label, val in vs:
                print(f"  {label} = {val!r}", file=sys.stderr)
            print("INCONSISTENCIA: los campos de version no coinciden entre si", file=sys.stderr)
            ok = False
    if ok:
        print(f"version OK: {vals[0]}")
    return 0 if ok else 1


def main(argv):
    if not argv:
        print(__doc__.strip().split("\n\n")[0])
        return 2
    if argv[0] == "--print":
        print(_load(PLUGIN).get("version"))
        return 0
    if argv[0] == "--check":
        target = argv[1] if len(argv) > 1 else None
        if target and not SEMVER.match(target):
            print(f"version invalida: {target} (usa X.Y.Z)", file=sys.stderr)
            return 2
        return cmd_check(target)
    # fijar version
    v = argv[0]
    if not SEMVER.match(v):
        print(f"version invalida: {v} (usa X.Y.Z)", file=sys.stderr)
        return 2
    set_version(v)
    print(f"version fijada en {v} (plugin.json + marketplace.json)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
