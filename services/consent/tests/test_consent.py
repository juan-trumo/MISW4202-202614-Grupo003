"""Unitarias de consent-service: propiedad, revocación, decisión de acceso y auditoría."""

import pytest

from common.jwt_utils import issue_token, load_or_create_private_key, public_pem_from_private
from common.testing import FakeAudit, load_service_app

PARTNER_A = "6f1c2a3e-8b4d-4c7a-9e21-5d3f7a9b0c11"
PARTNER_B = "a7d94e2b-1c5f-4b8e-8f63-2e9c0d4b7a55"


@pytest.fixture(scope="module")
def consent(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    data_dir = tmp_path_factory.mktemp("consent")
    mp.setenv("DATA_DIR", str(data_dir))
    mp.setenv("AUTH_URL", "http://127.0.0.1:9")
    mp.setenv("SERVICE_CLIENT_ID", "svc-consent")
    mp.setenv("SEED_SECRETS", '{"svc-consent": "x"}')
    module = load_service_app("consent")
    private = load_or_create_private_key(data_dir / "k.pem")
    module.app.extensions["solventa"].public_key = lambda: public_pem_from_private(private)
    module.app.testing = True
    module.private = private
    yield module
    mp.undo()


@pytest.fixture
def ctx(consent):
    audit = FakeAudit()
    consent.app.extensions["solventa"].audit = audit
    return consent.app.test_client(), audit


def _h(consent, sub="cliente-001", customer_id="C-001", scopes=("consent:write",),
       actor_type="customer"):
    token = issue_token(consent.private, sub=sub, actor_type=actor_type, scopes=list(scopes),
                        ttl=60, customer_id=customer_id)
    return {"Authorization": f"Bearer {token}"}


def _svc(consent):
    return _h(consent, sub="svc-quote", customer_id=None, scopes=("consent:read",),
              actor_type="service")


def _create(http, consent, purpose="quotation", partner=PARTNER_A, **kw):
    return http.post("/consents", json={"purpose": purpose, "granted_to": partner},
                     headers=_h(consent, **kw))


def _check(http, consent, customer, partner=PARTNER_A, purpose="quotation"):
    resp = http.get("/consents/check", headers=_svc(consent),
                    query_string={"customer_id": customer, "purpose": purpose,
                                  "partner_uuid": partner})
    assert resp.status_code == 200
    return resp.get_json()


def test_crear_toma_customer_id_del_token(consent, ctx):
    http, audit = ctx
    resp = _create(http, consent, sub="cliente-002", customer_id="C-002")
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["customer_id"] == "C-002" and body["status"] == "ACTIVE"
    assert audit.events[-1]["decision"] == "ALLOW"


def test_no_se_puede_crear_para_otro_cliente(consent, ctx):
    http, _ = ctx
    resp = http.post("/consents", headers=_h(consent),
                     json={"purpose": "quotation", "granted_to": PARTNER_A, "customer_id": "C-9"})
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "unknown_field"


def test_granted_to_debe_ser_uuid(consent, ctx):
    http, _ = ctx
    assert _create(http, consent, partner="socio-a").status_code == 400


def test_solo_el_dueno_ve_y_revoca(consent, ctx):
    http, audit = ctx
    consent_id = _create(http, consent, sub="cliente-003", customer_id="C-003").get_json()["id"]
    other = _h(consent, sub="cliente-004", customer_id="C-004")
    assert http.get(f"/consents/{consent_id}", headers=other).status_code == 404
    assert http.post(f"/consents/{consent_id}/revoke", headers=other).status_code == 404
    assert audit.events[-1]["decision"] == "DENY"
    owner = _h(consent, sub="cliente-003", customer_id="C-003")
    assert http.get(f"/consents/{consent_id}", headers=owner).get_json()["status"] == "ACTIVE"


def test_revocar_es_inmediato_e_idempotente(consent, ctx):
    http, _ = ctx
    owner = {"sub": "cliente-005", "customer_id": "C-005"}
    consent_id = _create(http, consent, **owner).get_json()["id"]
    assert _check(http, consent, "C-005") == {"allowed": True, "reason": "consent_active"}
    first = http.post(f"/consents/{consent_id}/revoke", headers=_h(consent, **owner)).get_json()
    assert first["status"] == "REVOKED" and first["revoked_at"]
    second = http.post(f"/consents/{consent_id}/revoke", headers=_h(consent, **owner)).get_json()
    assert second["revoked_at"] == first["revoked_at"]
    assert _check(http, consent, "C-005") == {"allowed": False, "reason": "consent_revoked"}


def test_decisiones_de_check(consent, ctx):
    http, audit = ctx
    owner = {"sub": "cliente-010", "customer_id": "C-010"}
    assert _check(http, consent, "C-010")["reason"] == "consent_not_found"
    _create(http, consent, purpose="marketing", **owner)
    assert _check(http, consent, "C-010")["reason"] == "purpose_mismatch"
    assert _check(http, consent, "C-010", partner=PARTNER_B)["reason"] == "consent_not_found"
    _create(http, consent, **owner)
    assert _check(http, consent, "C-010")["allowed"] is True
    assert _check(http, consent, "C-010", partner=PARTNER_B)["reason"] == "partner_mismatch"
    assert audit.events[-1]["decision"] == "DENY"


def test_check_exige_consent_read(consent, ctx):
    http, _ = ctx
    resp = http.get("/consents/check?customer_id=C-001&purpose=quotation&partner_uuid=x",
                    headers=_h(consent))
    assert resp.status_code == 403


def test_active_lista_clientes_con_consentimiento_activo(consent, ctx):
    http, _ = ctx
    _create(http, consent, sub="cliente-020", customer_id="C-020", partner=PARTNER_B)
    resp = http.get("/consents/active", headers=_svc(consent),
                    query_string={"partner_uuid": PARTNER_B, "purpose": "quotation"})
    assert "C-020" in resp.get_json()


def test_auditoria_caida_no_crea_ni_revoca(consent, ctx):
    http, audit = ctx
    owner = {"sub": "cliente-030", "customer_id": "C-030"}
    consent_id = _create(http, consent, **owner).get_json()["id"]
    audit.down = True
    assert _create(http, consent, **owner).status_code == 503
    assert http.post(f"/consents/{consent_id}/revoke",
                     headers=_h(consent, **owner)).status_code == 503
    audit.down = False
    assert _check(http, consent, "C-030")["allowed"] is True  # la revocación no se aplicó
