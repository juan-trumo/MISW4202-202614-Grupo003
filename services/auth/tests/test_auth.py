"""Unitarias de auth-service (TC-AU-01, TC-AU-02 y reglas de emisión)."""

import json

import jwt
import pytest

from common.jwt_utils import verify_token
from common.testing import FakeAudit, load_service_app

PARTNER_A = "6f1c2a3e-8b4d-4c7a-9e21-5d3f7a9b0c11"
PARTNER_B = "a7d94e2b-1c5f-4b8e-8f63-2e9c0d4b7a55"
SECRETS = {"cliente-001": "dev-c1", "socio-a": "dev-sa", "socio-b": "dev-sb", "svc-quote": "dev-q"}


@pytest.fixture(scope="module")
def auth(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    mp.setenv("DATA_DIR", str(tmp_path_factory.mktemp("auth")))
    mp.setenv("SEED_SECRETS", json.dumps(SECRETS))
    mp.setenv("PARTNER_A_UUID", PARTNER_A)
    mp.setenv("PARTNER_B_UUID", PARTNER_B)
    mp.setenv("TOKEN_TTL", "300")
    mp.setenv("CONSENT_MODE", "lookup")
    mp.setenv("EXPERIMENT_MODE", "1")
    module = load_service_app("auth")
    module.app.testing = True
    yield module
    mp.undo()


@pytest.fixture
def client(auth):
    fake = FakeAudit()
    auth.app.extensions["solventa"].audit = fake
    return auth.app.test_client(), fake


def _token(client, client_id, secret, **extra):
    return client.post("/token", json={"client_id": client_id, "client_secret": secret, **extra})


def test_TC_AU_01_socio_recibe_token_con_scopes_minimos(auth, client):
    http, audit = client
    resp = _token(http, "socio-a", "dev-sa")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 300
    claims = verify_token(body["access_token"], auth.PUBLIC_PEM)
    assert claims["scopes"] == ["finance:read", "policy:issue"]
    assert claims["partner_uuid"] == PARTNER_A and claims["actor_type"] == "partner"
    assert "consents" not in claims  # modo lookup
    assert audit.events[-1]["decision"] == "ALLOW"


def test_TC_AU_01_cliente_recibe_customer_id(auth, client):
    http, _ = client
    claims = verify_token(_token(http, "cliente-001", "dev-c1").get_json()["access_token"],
                          auth.PUBLIC_PEM)
    assert claims["customer_id"] == "C-001"
    assert claims["scopes"] == ["consent:write"]
    assert "partner_uuid" not in claims


@pytest.mark.parametrize("client_id,secret", [("socio-a", "mal"), ("no-existe", "dev-sa")])
def test_TC_AU_02_credencial_invalida_401_y_deny(client, client_id, secret):
    http, audit = client
    resp = _token(http, client_id, secret)
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "invalid_credentials"
    assert audit.events[-1]["decision"] == "DENY"
    assert audit.events[-1]["reason"] == "invalid_credentials"
    assert audit.events[-1]["actor"] == client_id


def test_credencial_invalida_con_auditoria_caida_da_503(client):
    http, audit = client
    audit.down = True
    assert _token(http, "socio-a", "mal").status_code == 503


def test_emision_valida_con_auditoria_caida_no_entrega_token(client):
    http, audit = client
    audit.down = True
    resp = _token(http, "socio-a", "dev-sa")
    assert resp.status_code == 503
    assert "access_token" not in resp.get_json()


def test_body_invalido_da_400_auditado(client):
    http, audit = client
    assert http.post("/token", data="x", content_type="text/plain").status_code == 400
    assert audit.events[-1]["reason"] == "invalid_request"


def test_ttl_solo_en_experiment_mode_y_nunca_mayor(auth, client, monkeypatch):
    http, _ = client
    assert _token(http, "socio-a", "dev-sa", ttl=1).get_json()["expires_in"] == 1
    assert _token(http, "socio-a", "dev-sa", ttl=301).status_code == 400
    assert _token(http, "socio-a", "dev-sa", ttl="5").status_code == 400
    monkeypatch.setenv("EXPERIMENT_MODE", "0")
    assert _token(http, "socio-a", "dev-sa", ttl=1).get_json()["expires_in"] == 300


def test_modo_claim_incrusta_consentimientos_activos(auth, client, monkeypatch):
    http, _ = client
    monkeypatch.setattr(auth, "CONSENT_MODE", "claim")
    monkeypatch.setattr(auth, "_active_consents", lambda partner: ["C-001", "C-003"])
    token = _token(http, "socio-a", "dev-sa").get_json()["access_token"]
    assert jwt.decode(token, options={"verify_signature": False})["consents"] == ["C-001", "C-003"]
    # Los clientes y servicios no llevan claim consents.
    token = _token(http, "cliente-001", "dev-c1").get_json()["access_token"]
    assert "consents" not in jwt.decode(token, options={"verify_signature": False})


def test_modo_claim_sin_consent_service_falla_cerrado(auth, client, monkeypatch):
    http, audit = client
    monkeypatch.setattr(auth, "CONSENT_MODE", "claim")
    monkeypatch.setattr(auth, "CONSENT_URL", "http://127.0.0.1:9")
    resp = _token(http, "socio-a", "dev-sa")
    assert resp.status_code == 503
    assert resp.get_json()["error"] == "consent_unavailable"
    assert audit.events[-1]["decision"] == "DENY"


def test_secretos_se_guardan_con_hash(auth):
    with auth.Session() as session:
        row = session.get(auth.Credential, "socio-a")
    assert row.secret_hash.startswith("pbkdf2_sha256$")
    assert "dev-sa" not in row.secret_hash


def test_keys_public_expone_solo_la_publica(auth, client):
    http, _ = client
    body = http.get("/keys/public").data
    assert b"BEGIN PUBLIC KEY" in body and b"PRIVATE" not in body
