#!/usr/bin/env python3
"""
vuln-hunter :: activity.py
Logger append-only de eventos para el panel vivo. Escribe una linea JSON por
evento en .vuln-hunter/activity.jsonl. No depende del LLM ni del ledger: es el
timeline que consume panel/index.html.

Uso:
    python3 scripts/activity.py <type> [clave=valor ...]
    # ej: python3 scripts/activity.py stage:start stage=SAST agent=sast-analyst

Ruta de salida: $VULN_ACTIVITY o .vuln-hunter/activity.jsonl
"""
import json
import os
import sys
from datetime import datetime

EVENT_TYPES = {
    "run:start", "run:done",
    "stage:start", "stage:end",
    "finding:new", "deploy:blocked",
}


def parse_fields(args):
    """Convierte ['k=v', 'k2=v2'] en {'k':'v','k2':'v2'}. Ignora tokens sin '='."""
    fields = {}
    for a in args:
        if "=" not in a:
            continue
        k, v = a.split("=", 1)
        fields[k] = v
    return fields


def append_event(event_type, fields, path):
    """Append de un evento como linea JSON. Devuelve 0 ok, 2 si el tipo es invalido."""
    if event_type not in EVENT_TYPES:
        print(f"vuln-hunter activity: tipo desconocido '{event_type}'", file=sys.stderr)
        return 2
    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "type": event_type}
    rec.update(fields)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return 0


def main(argv):
    if len(argv) < 2:
        print("uso: activity.py <type> [clave=valor ...]", file=sys.stderr)
        return 2
    event_type = argv[1]
    path = os.environ.get("VULN_ACTIVITY", ".vuln-hunter/activity.jsonl")
    return append_event(event_type, parse_fields(argv[2:]), path)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
