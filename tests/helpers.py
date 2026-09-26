"""Constantes y utilidades compartidas por las pruebas e2e."""

from __future__ import annotations

import urllib.request
import uuid
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent
BFF_CLIENTE = "http://localhost:8001"
BFF_SOCIO = "http://localhost:8002"
AUDIT = "http://127.0.0.1:5005"  # solo observación (docker-compose.experiment.yml)
POLICY = "http://127.0.0.1:5004"

# Servicios protegidos alcanzables para probar la validación del JWT (TC-AU-03..05). Ninguno
# acepta un token de cliente (solo consent:write). La Parte 4 añade /policies.
PROTECTED_ENDPOINTS = [
    pytest.param(f"{AUDIT}/events", id="audit-events"),
    pytest.param(f"{BFF_SOCIO}/quotes", id="quotes"),
]


def load_env() -> dict[str, str]:
    """Lee .env (o .env.example) para usar los mismos secretos de desarrollo que el stack."""
    path = ROOT / ".env" if (ROOT / ".env").exists() else ROOT / ".env.example"
    env = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            env[key.strip()] = value.strip()
    return env


def reachable(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2):
            return True
    except OSError:
        return False


def new_cid() -> str:
    return f"e2e-{uuid.uuid4()}"


def get_token(bff: str, client_id: str, secret: str, cid: str | None = None, **extra):
    return requests.post(
        f"{bff}/auth/token",
        json={"client_id": client_id, "client_secret": secret, **extra},
        headers={"X-Correlation-ID": cid or new_cid()},
        timeout=10,
    )


def audit_events(cid: str) -> list[dict]:
    resp = requests.get(f"{AUDIT}/events", params={"correlation_id": cid}, timeout=5)
    resp.raise_for_status()
    return resp.json()
