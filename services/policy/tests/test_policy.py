"""Unitarias de policy-service: HMAC antes del INSERT, orden de validaciones y anti-replay."""

import json
import uuid

import pytest

from common.hmac_utils import sign_payload
from common.jwt_utils import issue_token, load_or_create_private_key, public_pem_from_private
from common.testing import FakeAudit, load_service_app

PARTNER_A = "6f1c2a3e-8b4d-4c7a-9e21-5d3f7a9b0c11"
PARTNER_B = "a7d94e2b-1c5f-4b8e-8f63-2e9c0d4b7a55"
KEYS = {PARTNER_A: "key-a", PARTNER_B: "key-b"}


@pytest.fixture(scope="module")
def policy(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    data_dir = tmp_path_factory.mktemp("policy")
    mp.setenv("DATA_DIR", str(data_dir))
    mp.setenv("AUTH_URL", "http://127.0.0.1:9")
    mp.setenv("EXPERIMENT_MODE", "1")
    mp.setenv("PARTNER_HMAC_KEYS", json.dumps(KEYS))
    mp.setenv("SERVICE_CLIENT_ID", "svc-policy")
    mp.setenv("SEED_SECRETS", '{"svc-policy": "x"}')
    module = load_service_app("policy")
    private = load_or_create_private_key(data_dir / "k.pem")
    module.app.extensions["solventa"].public_key = lambda: public_pem_from_private(private)
    module.app.testing = True
    module.private = private
    yield module
    mp.undo()


@pytest.fixture
def ctx(policy):
    audit = FakeAudit()
    policy.app.extensions["solventa"].audit = audit
    return policy.app.test_client(), audit


def _payload(partner=PARTNER_A, **changes):
    return {
        "partner_uuid": partner,
        "quote_id": "Q-1",
        "holder_id": "C-001",
        "holder_name": "Ana Gómez",
        "premium": "125000.00",
        "coverage": "50000000.00",
        "currency": "COP",
        "issued_at": "2026-09-25T12:00:00Z",
        "nonce": str(uuid.uuid4()),
        **changes,
    }


def _headers(policy, signature=None, partner=PARTNER_A, scopes=("finance:read", "policy:issue"),
             actor_type="partner"):
    token = issue_token(policy.private, sub="socio-a", actor_type=actor_type, scopes=list(scopes),
                        ttl=60, partner_uuid=partner)
    headers = {"Authorization": f"Bearer {token}"}
    if signature is not None:
        headers["X-Signature"] = signature
    return headers


def _count(http):
    return http.get("/policies/count").get_json()["count"]


def _issue(http, policy, payload, signature):
    return http.post("/policies", json=payload, headers=_headers(policy, signature))


def test_TC_I_01_payload_integro_se_persiste(policy, ctx):
    http, audit = ctx
    payload = _payload()
    before = _count(http)
    resp = _issue(http, policy, payload, sign_payload("key-a", payload))
    assert resp.status_code == 201 and resp.get_json()["policy_id"]
    assert _count(http) == before + 1
    assert audit.events[-1]["decision"] == "ALLOW"
    counts = http.get("/policies/count").get_json()
    assert counts["integrity_verified"] == counts["count"]


@pytest.mark.parametrize("field,value", [("premium", "1.00"), ("coverage", "1.00"),
                                         ("holder_name", "Otro"), ("holder_id", "C-999")])
def test_TC_I_02_a_04_alteracion_tras_firmar_422_sin_insert(policy, ctx, field, value):
    http, audit = ctx
    payload = _payload()
    signature = sign_payload("key-a", payload)
    before = _count(http)
    resp = _issue(http, policy, {**payload, field: value}, signature)
    assert resp.status_code == 422
    assert resp.get_json()["error"] == "integrity_failed"
    assert _count(http) == before
    assert audit.events[-1]["decision"] == "DENY"


def test_TC_I_05_sin_firma_400(policy, ctx):
    http, _ = ctx
    before = _count(http)
    resp = _issue(http, policy, _payload(), None)
    assert resp.status_code == 400 and resp.get_json()["error"] == "missing_signature"
    assert _count(http) == before


def test_TC_I_06_firma_de_otro_socio_422(policy, ctx):
    http, _ = ctx
    payload = _payload()
    before = _count(http)
    resp = _issue(http, policy, payload, sign_payload("key-b", payload))
    assert resp.status_code == 422
    assert _count(http) == before


def test_TC_I_07_partner_del_body_distinto_403(policy, ctx):
    http, _ = ctx
    payload = _payload(partner=PARTNER_B)
    before = _count(http)
    resp = _issue(http, policy, payload, sign_payload("key-b", payload))
    assert resp.status_code == 403 and resp.get_json()["error"] == "partner_mismatch"
    assert _count(http) == before


def test_TC_I_08_campo_extra_400(policy, ctx):
    http, _ = ctx
    payload = _payload()
    signature = sign_payload("key-a", payload)
    before = _count(http)
    resp = _issue(http, policy, {**payload, "discount": "50.00"}, signature)
    assert resp.status_code == 400 and resp.get_json()["error"] == "unknown_field"
    assert _count(http) == before


def test_replay_mismo_nonce_409(policy, ctx):
    http, _ = ctx
    payload = _payload()
    signature = sign_payload("key-a", payload)
    assert _issue(http, policy, payload, signature).status_code == 201
    before = _count(http)
    resp = _issue(http, policy, payload, signature)
    assert resp.status_code == 409 and resp.get_json()["error"] == "replay_detected"
    assert _count(http) == before


def test_firma_valida_con_formato_invalido_400(policy, ctx):
    http, _ = ctx
    payload = _payload(premium="125000")  # sin 2 decimales, aunque la firma sea correcta
    before = _count(http)
    resp = _issue(http, policy, payload, sign_payload("key-a", payload))
    assert resp.status_code == 400 and resp.get_json()["error"] == "invalid_request"
    assert _count(http) == before


def test_campo_faltante_400(policy, ctx):
    http, _ = ctx
    payload = _payload()
    payload.pop("nonce")
    resp = _issue(http, policy, payload, sign_payload("key-a", payload))
    assert resp.status_code == 400 and resp.get_json()["error"] == "invalid_request"


def test_auditoria_caida_no_inserta(policy, ctx):
    http, audit = ctx
    payload = _payload()
    before = _count(http)
    audit.down = True
    resp = _issue(http, policy, payload, sign_payload("key-a", payload))
    assert resp.status_code == 503 and resp.get_json()["error"] == "audit_unavailable"
    assert _count(http) == before


def test_cliente_no_emite(policy, ctx):
    http, _ = ctx
    resp = http.post("/policies", json=_payload(),
                     headers=_headers(policy, scopes=("consent:write",), actor_type="customer",
                                      partner=None))
    assert resp.status_code == 403 and resp.get_json()["error"] == "insufficient_scope"


def test_count_oculto_sin_experiment_mode(policy, ctx, monkeypatch):
    http, _ = ctx
    monkeypatch.setenv("EXPERIMENT_MODE", "0")
    assert http.get("/policies/count").status_code == 404
