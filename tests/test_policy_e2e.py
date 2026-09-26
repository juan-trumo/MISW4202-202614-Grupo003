"""TC-I-01..08 contra docker compose (§11), con el mismo cliente que usa el arnés."""

import pytest

from experiment.partner_client import TAMPER_SCENARIOS, partners_from_env, policy_count
from tests.helpers import audit_events, new_cid


@pytest.fixture(scope="module")
def partners(env):
    return partners_from_env(env)


def test_TC_I_01_payload_integro_201_y_conteo_sube(partners):
    a, _ = partners
    payload = a.build_payload()
    before = policy_count()["count"]
    cid = new_cid()
    resp = a.issue(payload, a.sign(payload), cid=cid)
    assert resp.status_code == 201, resp.text
    assert policy_count()["count"] == before + 1
    events = audit_events(cid)
    assert [(e["service"], e["decision"], e["reason"]) for e in events] == [
        ("policy-service", "ALLOW", "integrity_verified")
    ]


@pytest.mark.parametrize("scenario", TAMPER_SCENARIOS, ids=[s.case_id for s in TAMPER_SCENARIOS])
def test_TC_I_02_a_08_alterado_se_rechaza_sin_persistir(partners, scenario):
    a, b = partners
    sent, signature = scenario.build(a, b)
    before = policy_count()["count"]
    cid = new_cid()
    resp = a.issue(sent, signature, cid=cid)
    assert resp.status_code == scenario.expected_status, resp.text
    assert resp.json()["error"] == scenario.expected_error
    assert policy_count()["count"] == before
    events = audit_events(cid)
    assert [e["decision"] for e in events] == ["DENY"]
    assert events[0]["reason"] == scenario.expected_error


def test_replay_del_mismo_mensaje_409(partners):
    a, _ = partners
    payload = a.build_payload()
    signature = a.sign(payload)
    assert a.issue(payload, signature).status_code == 201
    before = policy_count()["count"]
    resp = a.issue(payload, signature)
    assert resp.status_code == 409 and resp.json()["error"] == "replay_detected"
    assert policy_count()["count"] == before


def test_todas_las_polizas_guardadas_tienen_integridad_verificada():
    counts = policy_count()
    assert counts["integrity_verified"] == counts["count"]
