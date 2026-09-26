"""Unitarias de quote-service: modos lookup y claim, caché y falla cerrada."""

import time

import pytest

from common.errors import ApiError
from common.jwt_utils import issue_token, load_or_create_private_key, public_pem_from_private
from common.testing import FakeAudit, load_service_app

PARTNER_A = "6f1c2a3e-8b4d-4c7a-9e21-5d3f7a9b0c11"


@pytest.fixture(scope="module")
def quote(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    data_dir = tmp_path_factory.mktemp("quote")
    mp.setenv("AUTH_URL", "http://127.0.0.1:9")
    mp.setenv("CONSENT_URL", "http://127.0.0.1:9")
    mp.setenv("CONSENT_MODE", "lookup")
    mp.setenv("CONSENT_CACHE_TTL", "0")
    mp.setenv("SERVICE_CLIENT_ID", "svc-quote")
    mp.setenv("SEED_SECRETS", '{"svc-quote": "x"}')
    module = load_service_app("quote")
    private = load_or_create_private_key(data_dir / "k.pem")
    module.app.extensions["solventa"].public_key = lambda: public_pem_from_private(private)
    module.app.testing = True
    module.private = private
    yield module
    mp.undo()


@pytest.fixture
def ctx(quote, monkeypatch):
    audit = FakeAudit()
    quote.app.extensions["solventa"].audit = audit
    quote.CACHE.clear()
    calls = []
    decisions = {"C-001": (True, "consent_active"), "C-002": (False, "consent_revoked")}

    def fake_check(customer_id, partner_uuid):
        calls.append((customer_id, partner_uuid))
        return decisions.get(customer_id, (False, "consent_not_found"))

    monkeypatch.setattr(quote, "check_with_owner", fake_check)
    return quote.app.test_client(), audit, calls, decisions


def _h(quote, scopes=("finance:read", "policy:issue"), consents=None, actor_type="partner",
       partner_uuid=PARTNER_A):
    token = issue_token(quote.private, sub="socio-a", actor_type=actor_type, scopes=list(scopes),
                        ttl=60, partner_uuid=partner_uuid, consents=consents)
    return {"Authorization": f"Bearer {token}"}


def _quote(http, headers, customer="C-001", **extra):
    return http.post("/quotes", json={"customer_id": customer, "product": "auto", **extra},
                     headers=headers)


def test_lookup_con_consentimiento_activo_cotiza(quote, ctx):
    http, audit, calls, _ = ctx
    resp = _quote(http, _h(quote))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["partner_uuid"] == PARTNER_A and body["customer_id"] == "C-001"
    assert body["premium"] == quote.financial_premium("C-001")
    assert calls == [("C-001", PARTNER_A)]
    assert audit.events[-1]["decision"] == "ALLOW"


def test_lookup_rechazo_usa_el_motivo_del_dueno(quote, ctx):
    http, audit, _, _ = ctx
    resp = _quote(http, _h(quote), customer="C-002")
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "consent_revoked"
    assert audit.events[-1]["reason"] == "consent_revoked"


def test_partner_uuid_del_body_no_se_acepta(quote, ctx):
    http, _, calls, _ = ctx
    resp = _quote(http, _h(quote), partner_uuid="otro")
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "unknown_field"
    assert calls == []


def test_cliente_no_puede_cotizar(quote, ctx):
    http, _, _, _ = ctx
    resp = _quote(http, _h(quote, scopes=("consent:write",), actor_type="customer",
                           partner_uuid=None))
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "insufficient_scope"


def test_cache_cero_consulta_siempre(quote, ctx):
    http, _, calls, _ = ctx
    _quote(http, _h(quote))
    _quote(http, _h(quote))
    assert len(calls) == 2


def test_cache_ttl_reutiliza_y_la_revocacion_se_nota_al_expirar(quote, ctx, monkeypatch):
    http, _, calls, decisions = ctx
    monkeypatch.setattr(quote, "CONSENT_CACHE_TTL", 0.3)
    assert _quote(http, _h(quote)).status_code == 200
    decisions["C-001"] = (False, "consent_revoked")  # se revoca en el dueño
    assert _quote(http, _h(quote)).status_code == 200  # la caché aún autoriza
    assert len(calls) == 1
    time.sleep(0.35)
    resp = _quote(http, _h(quote))
    assert resp.status_code == 403 and resp.get_json()["error"] == "consent_revoked"


def test_claim_usa_solo_el_token(quote, ctx, monkeypatch):
    http, _, calls, _ = ctx
    monkeypatch.setattr(quote, "CONSENT_MODE", "claim")
    assert _quote(http, _h(quote, consents=["C-001"])).status_code == 200
    resp = _quote(http, _h(quote, consents=[]))
    assert resp.status_code == 403 and resp.get_json()["error"] == "consent_not_found"
    assert calls == []  # nunca consulta a consent-service


def test_consent_service_caido_falla_cerrado(quote, ctx, monkeypatch):
    http, audit, _, _ = ctx

    def down(*_):
        raise ApiError(503, "consent_unavailable", "caído")

    monkeypatch.setattr(quote, "check_with_owner", down)
    resp = _quote(http, _h(quote))
    assert resp.status_code == 503
    assert audit.events[-1]["decision"] == "DENY"


def test_auditoria_caida_no_entrega_datos(quote, ctx):
    http, audit, _, _ = ctx
    audit.down = True
    resp = _quote(http, _h(quote))
    assert resp.status_code == 503
    assert "premium" not in resp.get_json()


def test_prima_es_determinista_y_decimal(quote):
    premium = quote.financial_premium("C-001")
    assert premium == quote.financial_premium("C-001")
    assert premium.count(".") == 1 and len(premium.split(".")[1]) == 2
