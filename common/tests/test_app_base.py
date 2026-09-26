"""require_scope, correlation-id, formato de error y falla cerrada de auditoría."""

import requests

from common.audit_client import AuditClient
from common.errors import ApiError
from common.jwt_utils import ServiceTokenProvider


def _post(client, token=None, cid=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cid:
        headers["X-Correlation-ID"] = cid
    return client.post("/protected", headers=headers)


def test_health(protected_app):
    app, _ = protected_app
    resp = app.test_client().get("/health")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok", "service": "test-service"}


def test_scope_correcto_pasa_sin_auditar_en_el_decorador(protected_app, make_token):
    app, audit = protected_app
    resp = _post(app.test_client(), make_token(), cid="abc-123")
    assert resp.status_code == 200
    assert resp.headers["X-Correlation-ID"] == "abc-123"
    assert audit.events == []  # el ALLOW lo audita el endpoint, no el decorador


def test_sin_token_da_401_y_audita_deny(protected_app):
    app, audit = protected_app
    resp = _post(app.test_client())
    body = resp.get_json()
    assert resp.status_code == 401
    assert body["error"] == "invalid_token"
    assert body["correlation_id"] == resp.headers["X-Correlation-ID"]
    assert audit.events[0]["decision"] == "DENY"
    assert audit.events[0]["reason"] == "invalid_token"


def test_scope_ausente_da_403_insufficient_scope(protected_app, make_token):
    app, audit = protected_app
    resp = _post(app.test_client(), make_token(scopes_=("consent:write",), sub="cliente-001"))
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "insufficient_scope"
    assert audit.events[0]["claims"]["sub"] == "cliente-001"


def test_auditoria_caida_convierte_el_rechazo_en_503(protected_app):
    app, audit = protected_app
    audit.down = True
    resp = _post(app.test_client())
    assert resp.status_code == 503
    assert resp.get_json()["error"] == "audit_unavailable"


def test_correlation_id_invalido_se_reemplaza(protected_app):
    app, _ = protected_app
    malicious = 'a b";DROP<script>'
    resp = app.test_client().get("/health", headers={"X-Correlation-ID": malicious})
    assert resp.headers["X-Correlation-ID"] != malicious
    assert len(resp.headers["X-Correlation-ID"]) == 36  # uuid4 nuevo


def test_ruta_inexistente_usa_formato_de_error(protected_app):
    app, _ = protected_app
    resp = app.test_client().get("/consents")
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "not_found"


def test_audit_client_falla_cerrado_si_no_hay_servicio(protected_app):
    app, _ = protected_app
    client = AuditClient("x", "http://127.0.0.1:9", ServiceTokenProvider(lambda: ("t", 60)), 0.5)
    with app.test_request_context("/"):
        try:
            client.record(action="a", resource="r", decision="ALLOW", reason="ok")
        except ApiError as err:
            assert (err.status, err.code) == (503, "audit_unavailable")
        else:
            raise AssertionError("debió fallar cerrado")


def test_audit_client_falla_cerrado_por_timeout(protected_app, monkeypatch):
    app, _ = protected_app

    def slow_post(*args, **kwargs):
        raise requests.Timeout("más de AUDIT_TIMEOUT_S")

    monkeypatch.setattr("common.audit_client.requests.post", slow_post)
    client = AuditClient("x", "http://audit:5005", ServiceTokenProvider(lambda: ("t", 60)), 2)
    with app.test_request_context("/"):
        try:
            client.record(action="a", resource="r", decision="DENY", reason="x")
        except ApiError as err:
            assert err.code == "audit_unavailable"
        else:
            raise AssertionError("debió fallar cerrado")


def test_evento_tiene_campos_de_7_4(protected_app):
    app, _ = protected_app
    client = AuditClient("svc", "http://audit", ServiceTokenProvider(lambda: ("t", 60)))
    with app.test_request_context("/", headers={"X-Correlation-ID": "cid-1"}):
        app.preprocess_request()
        event = client.build_event(
            action="policy.issue", resource="/policies", decision="DENY",
            reason="integrity_failed", claims={"sub": "socio-a", "actor_type": "partner",
                                               "partner_uuid": "P-A"},
        )
    assert set(event) == {"ts", "correlation_id", "service", "actor", "actor_type",
                          "partner_uuid", "action", "resource", "decision", "reason"}
    assert event["correlation_id"] == "cid-1"
    assert event["actor"] == "socio-a"
