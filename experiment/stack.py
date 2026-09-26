"""Control del stack de docker compose desde el arnés y las pruebas e2e."""

from __future__ import annotations

import subprocess
import time
import urllib.request
from pathlib import Path

from experiment.envfile import ROOT

COMPOSE = ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.experiment.yml"]
AUDIT_HEALTH = "http://127.0.0.1:5005/health"


def compose(*args: str, env_file: Path | None = None) -> subprocess.CompletedProcess:
    cmd = list(COMPOSE)
    if env_file is not None:
        cmd += ["--env-file", str(env_file)]
    return subprocess.run(cmd + list(args), cwd=ROOT, capture_output=True, text=True, check=True)


def http_ok(url: str, timeout_s: float = 2) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as resp:
            return resp.status == 200
    except OSError:
        return False


def wait_http_ok(url: str, timeout_s: float = 60) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if http_ok(url):
            return
        time.sleep(1)
    raise TimeoutError(f"{url} no respondió 200 en {timeout_s} s")
