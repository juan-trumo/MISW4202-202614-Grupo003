"""Verifica que los 7 servicios estén healthy (Parte 1).

Los servicios internos no publican puertos, así que su estado se lee del healthcheck de Docker
Compose; los BFF, policy y audit también se consultan por HTTP desde el host.
"""

import json
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ["auth", "consent", "quote", "policy", "audit", "bff-cliente", "bff-socio"]
HOST_URLS = {
    "bff-cliente": "http://localhost:8001/health",
    "bff-socio": "http://localhost:8002/health",
    "policy": "http://127.0.0.1:5004/health",
    "audit": "http://127.0.0.1:5005/health",
}


def compose_status() -> dict[str, str]:
    out = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.experiment.yml",
         "ps", "--format", "json"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.strip()
    if not out:
        return {}
    # Según la versión, compose devuelve un arreglo JSON o un objeto JSON por línea.
    if out.startswith("["):
        rows = json.loads(out)
    else:
        rows = [json.loads(line) for line in out.splitlines()]
    return {r["Service"]: r.get("Health") or r.get("State", "?") for r in rows}


def http_ok(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            return resp.status == 200
    except OSError:
        return False


def main() -> int:
    status = compose_status()
    ok = True
    for service in EXPECTED:
        health = status.get(service, "no existe")
        line = f"{service:<12} compose={health}"
        good = health == "healthy"
        if service in HOST_URLS:
            reachable = http_ok(HOST_URLS[service])
            line += f"  http={'200' if reachable else 'FALLA'} ({HOST_URLS[service]})"
            good = good and reachable
        print(("OK   " if good else "FAIL ") + line)
        ok = ok and good
    print("\nLos 7 servicios están healthy." if ok else "\nHay servicios sin responder.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
