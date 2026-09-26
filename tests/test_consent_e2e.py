"""TC-C-01..05 contra docker compose (§11). El stack por defecto corre en modo lookup, caché 0.

Las BD persisten entre corridas: cada prueba usa un cliente o socio que otras no tocan y
revoca al final lo que creó, para que el resultado no dependa de corridas anteriores.
"""

import pytest
import requests

from tests.helpers import BFF_CLIENTE, BFF_SOCIO, audit_events, new_cid


@pytest.fixture(scope="module", autouse=True)
def lookup_mode_only(env):
    if env.get("CONSENT_MODE", "lookup") != "lookup" or env.get("CONSENT_CACHE_TTL", "0") != "0":
        pytest.skip("TC-C-01..05 esperan CONSENT_MODE=lookup y CONSENT_CACHE_TTL=0")


@pytest.fixture
def consents(token_for):
    """Crea consentimientos vía bff-cliente y los revoca al terminar la prueba."""
    created: list[tuple[str, str]] = []

    def _create(client_id: str, partner_uuid: str, purpose: str = "quotation") -> str:
        token = token_for(client_id)
        resp = requests.post(f"{BFF_CLIENTE}/consents",
                             json={"purpose": purpose, "granted_to": partner_uuid},
                             headers={"Authorization": f"Bearer {token}"}, timeout=10)
        assert resp.status_code == 201, resp.text
        created.append((resp.json()["id"], token))
        return resp.json()["id"]

    yield _create
    for consent_id, token in created:
        requests.post(f"{BFF_CLIENTE}/consents/{consent_id}/revoke",
                      headers={"Authorization": f"Bearer {token}"}, timeout=10)


def quote(token: str, customer_id: str, cid: str | None = None) -> requests.Response:
    return requests.post(f"{BFF_SOCIO}/quotes",
                         json={"customer_id": customer_id, "product": "auto"},
                         headers={"Authorization": f"Bearer {token}",
                                  "X-Correlation-ID": cid or new_cid()},
                         timeout=10)


def test_TC_C_01_consentimiento_activo_cotiza(env, consents, token_for):
    consents("cliente-001", env["PARTNER_A_UUID"])
    cid = new_cid()
    resp = quote(token_for("socio-a"), "C-001", cid)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["partner_uuid"] == env["PARTNER_A_UUID"]
    assert body["customer_id"] == "C-001"
    decisions = {(e["service"], e["decision"]) for e in audit_events(cid)}
    assert decisions == {("consent-service", "ALLOW"), ("quote-service", "ALLOW")}


def test_TC_C_02_otro_proposito_403_purpose_mismatch(env, consents, token_for):
    consents("cliente-002", env["PARTNER_B_UUID"], purpose="marketing")
    resp = quote(token_for("socio-b"), "C-002")
    assert resp.status_code == 403
    assert resp.json()["error"] == "purpose_mismatch"


def test_TC_C_03_socio_b_con_consentimiento_solo_de_a(env, consents, token_for):
    consents("cliente-003", env["PARTNER_A_UUID"])
    cid = new_cid()
    resp = quote(token_for("socio-b"), "C-003", cid)
    assert resp.status_code == 403
    assert resp.json()["error"] == "partner_mismatch"
    deny = [e for e in audit_events(cid) if e["service"] == "quote-service"]
    assert deny[0]["decision"] == "DENY" and deny[0]["actor"] == "socio-b"


def test_TC_C_04_revocado_403_consent_revoked(env, consents, token_for):
    consent_id = consents("cliente-004", env["PARTNER_A_UUID"])
    partner_token = token_for("socio-a")
    assert quote(partner_token, "C-004").status_code == 200
    revoke = requests.post(f"{BFF_CLIENTE}/consents/{consent_id}/revoke",
                           headers={"Authorization": f"Bearer {token_for('cliente-004')}"},
                           timeout=10)
    assert revoke.status_code == 200 and revoke.json()["status"] == "REVOKED"
    # Mismo token del socio, sin esperar: en lookup con caché 0 la revocación es inmediata.
    resp = quote(partner_token, "C-004")
    assert resp.status_code == 403
    assert resp.json()["error"] == "consent_revoked"


def test_TC_C_05_sin_consentimiento_403_consent_not_found(token_for):
    resp = quote(token_for("socio-a"), "C-999")
    assert resp.status_code == 403
    assert resp.json()["error"] == "consent_not_found"


def test_cliente_no_puede_ver_consentimiento_ajeno(env, consents, token_for):
    consent_id = consents("cliente-005", env["PARTNER_A_UUID"])
    resp = requests.get(f"{BFF_CLIENTE}/consents/{consent_id}",
                        headers={"Authorization": f"Bearer {token_for('cliente-001')}"},
                        timeout=10)
    assert resp.status_code == 404
