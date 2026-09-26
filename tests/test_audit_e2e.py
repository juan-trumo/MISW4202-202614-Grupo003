"""TC-AD-01 y TC-AD-02 contra docker compose (§11).

TC-AD-02 detiene (stop) o congela (pause) audit-service y lo restaura al terminar, aunque la
prueba falle. Con pause, las conexiones quedan colgadas y se ejercita el timeout de 2 s.
"""

import time

import pytest
import requests

from experiment.audit_probe import run_audit_coverage
from experiment.partner_client import partners_from_env, policy_count
from experiment.stack import AUDIT_HEALTH, compose, wait_http_ok
from tests.helpers import BFF_CLIENTE, BFF_SOCIO


def test_TC_AD_01_cada_request_protegido_tiene_su_evento(env):
    result = run_audit_coverage(env)
    wrong_status = [p for p in result["probes"] if not p["status_ok"]]
    missing = [p for p in result["probes"] if not p["audited"]]
    assert wrong_status == [], wrong_status
    assert missing == [], missing
    assert result["coverage"] == 1.0
    decisions = {d for p in result["probes"] for d in p["decisions"]}
    assert decisions == {"ALLOW", "DENY"}  # se auditan permitidos y denegados


class AuditOutage:
    def __init__(self) -> None:
        self.mode: str | None = None

    def down(self, mode: str) -> None:
        compose(mode, "audit")
        self.mode = mode

    def restore(self) -> None:
        if self.mode is not None:
            compose("unpause" if self.mode == "pause" else "start", "audit")
            self.mode = None
        wait_http_ok(AUDIT_HEALTH, timeout_s=90)


@pytest.fixture
def audit_outage():
    """Tumba audit-service a pedido de la prueba y siempre lo restaura al final."""
    outage = AuditOutage()
    yield outage
    outage.restore()


@pytest.fixture
def prepared(env, secrets, token_for):
    """Consentimiento activo C-005 → A y tokens obtenidos ANTES de tumbar audit."""
    a, _ = partners_from_env(env)
    customer = token_for("cliente-005")
    consent = requests.post(f"{BFF_CLIENTE}/consents",
                            json={"purpose": "quotation", "granted_to": a.partner_uuid},
                            headers={"Authorization": f"Bearer {customer}"}, timeout=10).json()
    a.token(refresh=True)
    yield {"partner": a, "customer": customer, "consent_id": consent["id"]}
    requests.post(f"{BFF_CLIENTE}/consents/{consent['id']}/revoke",
                  headers={"Authorization": f"Bearer {customer}"}, timeout=10)


def _quote(token: str) -> requests.Response:
    return requests.post(f"{BFF_SOCIO}/quotes", json={"customer_id": "C-005", "product": "auto"},
                         headers={"Authorization": f"Bearer {token}"}, timeout=15)


@pytest.mark.parametrize("mode", ["stop", "pause"])
def test_TC_AD_02_audit_caido_falla_cerrado(mode, env, secrets, prepared, audit_outage):
    a = prepared["partner"]
    assert _quote(a.token()).status_code == 200  # sanidad: con audit arriba funciona
    before = policy_count()["count"]

    audit_outage.down(mode)

    started = time.monotonic()
    quote = _quote(a.token())
    assert quote.status_code == 503
    assert quote.json()["error"] == "audit_unavailable"
    assert "premium" not in quote.json()

    payload = a.build_payload(holder_id="C-005")
    policy = a.issue(payload, a.sign(payload))
    elapsed = time.monotonic() - started
    assert policy.status_code == 503
    assert policy.json()["error"] == "audit_unavailable"

    tampered = a.build_payload(holder_id="C-005")
    signature = a.sign(tampered)
    tampered["premium"] = "1.00"
    assert a.issue(tampered, signature).status_code == 503  # ni el rechazo sale sin auditar

    revoke = requests.post(f"{BFF_CLIENTE}/consents/{prepared['consent_id']}/revoke",
                           headers={"Authorization": f"Bearer {prepared['customer']}"},
                           timeout=15)
    assert revoke.status_code == 503

    token = requests.post(f"{BFF_SOCIO}/auth/token",
                          json={"client_id": "socio-a", "client_secret": secrets["socio-a"]},
                          timeout=15)
    assert token.status_code == 503 and "access_token" not in token.json()

    assert policy_count()["count"] == before  # 0 pólizas guardadas sin auditar
    if mode == "pause":
        assert elapsed >= 2  # esperó el AUDIT_TIMEOUT_S antes de rechazar

    # Con audit de vuelta: la revocación intentada durante la caída no se aplicó y el
    # servicio se recupera sin reiniciar nada más.
    audit_outage.restore()
    consent = requests.get(f"{BFF_CLIENTE}/consents/{prepared['consent_id']}",
                           headers={"Authorization": f"Bearer {prepared['customer']}"},
                           timeout=10)
    assert consent.json()["status"] == "ACTIVE"
    assert _quote(a.token()).status_code == 200
