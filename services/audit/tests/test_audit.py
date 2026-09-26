"""Unitarias de audit-service: autorización, validación, consulta y append-only."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from common.jwt_utils import issue_token, load_or_create_private_key, public_pem_from_private
from common.testing import load_service_app

EVENT = {
    "ts": "2026-09-25T12:00:00+00:00",
    "correlation_id": "cid-audit-1",
    "service": "quote-service",
    "actor": "socio-a",
    "actor_type": "partner",
    "partner_uuid": "6f1c2a3e-8b4d-4c7a-9e21-5d3f7a9b0c11",
    "action": "quote.create",
    "resource": "/quotes",
    "decision": "ALLOW",
    "reason": "consent_active",
}


@pytest.fixture(scope="module")
def audit(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    data_dir = tmp_path_factory.mktemp("audit")
    mp.setenv("DATA_DIR", str(data_dir))
    mp.setenv("EXPERIMENT_MODE", "1")
    module = load_service_app("audit")
    private = load_or_create_private_key(data_dir / "k.pem")
    module.app.extensions["solventa"].public_key = lambda: public_pem_from_private(private)
    module.app.testing = True
    module.private = private
    yield module
    mp.undo()


def _auth(audit, scopes=("audit:write",), sub="svc-quote"):
    token = issue_token(audit.private, sub=sub, actor_type="service", scopes=list(scopes), ttl=60)
    return {"Authorization": f"Bearer {token}"}


def test_evento_valido_se_registra_con_submitted_by(audit):
    http = audit.app.test_client()
    resp = http.post("/events", json=EVENT, headers=_auth(audit))
    assert resp.status_code == 201
    events = http.get("/events?correlation_id=cid-audit-1").get_json()
    assert events[-1]["submitted_by"] == "svc-quote"
    assert events[-1]["decision"] == "ALLOW"


def test_sin_audit_write_se_rechaza(audit):
    http = audit.app.test_client()
    resp = http.post("/events", json=EVENT, headers=_auth(audit, scopes=("consent:write",)))
    assert resp.status_code == 403
    assert http.post("/events", json=EVENT).status_code == 401


@pytest.mark.parametrize("change", [{"extra": "x"}, {"decision": "MAYBE"}, {"ts": "ayer"},
                                    {"actor": None}])
def test_eventos_invalidos_se_rechazan(audit, change):
    body = {**EVENT, **change}
    if change.get("actor", "") is None:
        body.pop("actor")
    resp = audit.app.test_client().post("/events", json=body, headers=_auth(audit))
    assert resp.status_code == 400


def test_stats_cuenta_por_servicio(audit):
    http = audit.app.test_client()
    http.post("/events", json={**EVENT, "decision": "DENY", "reason": "consent_revoked"},
              headers=_auth(audit))
    stats = http.get("/stats").get_json()
    assert stats["total"] == stats["allow"] + stats["deny"]
    assert stats["by_service"]["quote-service"]["deny"] >= 1


def test_tabla_es_append_only(audit):
    audit.app.test_client().post("/events", json=EVENT, headers=_auth(audit))
    with audit.Session() as session:
        for sql in ("UPDATE audit_event SET decision='ALLOW'", "DELETE FROM audit_event"):
            with pytest.raises(IntegrityError):
                session.execute(text(sql))
            session.rollback()


def test_consultas_ocultas_sin_experiment_mode(audit, monkeypatch):
    monkeypatch.setenv("EXPERIMENT_MODE", "0")
    http = audit.app.test_client()
    assert http.get("/events").status_code == 404
    assert http.get("/stats").status_code == 404
