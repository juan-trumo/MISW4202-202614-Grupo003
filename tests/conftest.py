"""Fixtures e2e: hablan con docker compose como lo haría un cliente o un socio real.

Requieren el stack arriba (make up / tasks.ps1 up). Si los BFF no responden, se omiten.
"""

from __future__ import annotations

import json

import pytest

from tests.helpers import AUDIT, BFF_CLIENTE, BFF_SOCIO, ROOT, get_token, load_env, reachable


def pytest_collection_modifyitems(config, items):
    if reachable(f"{BFF_SOCIO}/health") and reachable(f"{AUDIT}/health"):
        return
    skip = pytest.mark.skip(reason="stack no disponible: ejecuta tasks.ps1 up / make up")
    for item in items:
        if item.path.parent == ROOT / "tests":
            item.add_marker(skip)


@pytest.fixture(scope="session")
def env() -> dict[str, str]:
    return load_env()


@pytest.fixture(scope="session")
def secrets(env) -> dict[str, str]:
    return json.loads(env["SEED_SECRETS"])


@pytest.fixture
def token_for(secrets):
    """token_for('socio-a') -> access_token, vía el BFF que corresponde al actor."""

    def _get(client_id: str, **extra) -> str:
        bff = BFF_CLIENTE if client_id.startswith("cliente-") else BFF_SOCIO
        resp = get_token(bff, client_id, secrets[client_id], **extra)
        assert resp.status_code == 200, resp.text
        return resp.json()["access_token"]

    return _get
