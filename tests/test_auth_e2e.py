"""TC-AU-01..05 y TC-C-06 contra docker compose (§11)."""

import base64
import json
import time

import jwt
import pytest
import requests

from tests.helpers import (
    BFF_CLIENTE,
    BFF_SOCIO,
    PROTECTED_ENDPOINTS,
    audit_events,
    get_token,
    new_cid,
)

EVENT = {
    "ts": "2026-09-25T12:00:00+00:00",
    "service": "e2e",
    "actor": "e2e",
    "action": "e2e.test",
    "resource": "/e2e",
    "decision": "ALLOW",
    "reason": "e2e",
}


def _claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def _call(url: str, token: str) -> requests.Response:
    return requests.post(url, json=EVENT, headers={"Authorization": f"Bearer {token}"}, timeout=10)


def test_TC_AU_01_credencial_valida_socio(env, secrets):
    cid = new_cid()
    resp = get_token(BFF_SOCIO, "socio-a", secrets["socio-a"], cid=cid)
    assert resp.status_code == 200
    assert resp.headers["X-Correlation-ID"] == cid
    body = resp.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == int(env["TOKEN_TTL"])
    claims = _claims(body["access_token"])
    assert claims["scopes"] == ["finance:read", "policy:issue"]
    assert claims["partner_uuid"] == env["PARTNER_A_UUID"]
    assert (claims["iss"], claims["aud"]) == ("solventa-auth", "solventa-internal")
    assert claims["exp"] - claims["iat"] == int(env["TOKEN_TTL"])
    assert [e["decision"] for e in audit_events(cid)] == ["ALLOW"]


def test_TC_AU_01_credencial_valida_cliente(secrets):
    resp = get_token(BFF_CLIENTE, "cliente-001", secrets["cliente-001"])
    assert resp.status_code == 200
    claims = _claims(resp.json()["access_token"])
    assert claims["scopes"] == ["consent:write"]
    assert claims["customer_id"] == "C-001"


@pytest.mark.parametrize("client_id,secret", [("socio-a", "incorrecto"), ("intruso", "x")])
def test_TC_AU_02_secreto_invalido_401_y_evento_deny(client_id, secret):
    cid = new_cid()
    resp = get_token(BFF_SOCIO, client_id, secret, cid=cid)
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid_credentials", "detail": "Credenciales inválidas",
                           "correlation_id": cid}
    events = audit_events(cid)
    assert len(events) == 1
    assert events[0]["decision"] == "DENY"
    assert events[0]["reason"] == "invalid_credentials"
    assert events[0]["service"] == "auth-service"


@pytest.mark.parametrize("url", PROTECTED_ENDPOINTS)
def test_TC_AU_03_token_expirado_401(url, token_for):
    token = token_for("socio-a", ttl=1)
    time.sleep(2.2)
    resp = _call(url, token)
    assert resp.status_code == 401
    assert resp.json()["error"] == "token_expired"


@pytest.mark.parametrize("url", PROTECTED_ENDPOINTS)
def test_TC_AU_04_scope_ausente_403(url, token_for):
    resp = _call(url, token_for("cliente-001"))
    assert resp.status_code == 403
    assert resp.json()["error"] == "insufficient_scope"


@pytest.mark.parametrize("url", PROTECTED_ENDPOINTS)
def test_TC_AU_05_firma_alterada_401(url, token_for):
    header, payload, signature = token_for("socio-a").split(".")
    resp = _call(url, f"{header}.{payload}.{signature[:-6]}AAAAAA")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


@pytest.mark.parametrize("url", PROTECTED_ENDPOINTS)
def test_TC_AU_05_claims_alterados_con_firma_original_401(url, token_for):
    """Un socio se añade un scope editando el payload: la firma ya no corresponde."""
    header, payload, signature = token_for("socio-a").split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["scopes"].append("audit:write")
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    resp = _call(url, f"{header}.{forged}.{signature}")
    assert resp.status_code == 401
    assert resp.json()["error"] == "invalid_token"


@pytest.mark.parametrize("method,path", [("post", "/consents"), ("get", "/consents/x"),
                                         ("post", "/consents/x/revoke")])
def test_TC_C_06_bff_socio_no_expone_consentimientos(method, path, token_for):
    resp = requests.request(method, f"{BFF_SOCIO}{path}",
                            headers={"Authorization": f"Bearer {token_for('socio-a')}"},
                            timeout=10)
    assert resp.status_code == 404
    assert resp.json()["error"] == "not_found"
