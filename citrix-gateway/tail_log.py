#!/usr/bin/env python3
"""
Tail en tiempo real del honeypot.log con formato legible.
Uso: python3 tail_log.py [--creds-only]
"""
import sys
import json
import time

CREDS_ONLY = "--creds-only" in sys.argv

COLORS = {
    "CREDENTIAL_CAPTURE": "\033[91m",  # rojo
    "proxy_error":        "\033[93m",  # amarillo
    "startup":            "\033[92m",  # verde
    "request":            "\033[0m",   # normal
}
RESET = "\033[0m"
BOLD  = "\033[1m"

def fmt(line):
    line = line.strip()
    if not line:
        return
    try:
        ev = json.loads(line)
    except Exception:
        print(line)
        return

    kind = ev.get("event", "?")

    if CREDS_ONLY and kind != "CREDENTIAL_CAPTURE":
        return

    color = COLORS.get(kind, "\033[0m")
    ts = ev.get("ts", "")[:19].replace("T", " ")

    if kind == "CREDENTIAL_CAPTURE":
        print(f"{BOLD}{color}[{ts}] *** CREDS CAPTURED ***{RESET}")
        print(f"  Path    : {ev.get('path')}")
        print(f"  IP      : {ev.get('ip')}")
        print(f"  UA      : {ev.get('ua', '')[:80]}")
        print(f"  Username: {BOLD}{ev.get('username')}{RESET}")
        print(f"  Password: {BOLD}{ev.get('password')}{RESET}")
        if ev.get("extra_fields"):
            print(f"  Extra   : {ev.get('extra_fields')}")
        print()
    elif kind == "request":
        method = ev.get("method", "GET")
        path   = ev.get("path", "")
        ip     = ev.get("ip", "")
        ua     = (ev.get("ua") or "")[:60]
        print(f"{color}[{ts}] {method:5s} {path:<55} {ip:<16} {ua}{RESET}")
    else:
        print(f"{color}[{ts}] {kind}: {json.dumps(ev, ensure_ascii=False)}{RESET}")

import subprocess
log_path = __file__.replace("tail_log.py", "honeypot.log")

try:
    proc = subprocess.Popen(["tail", "-F", "-n", "50", log_path],
                            stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        fmt(line)
except KeyboardInterrupt:
    pass
