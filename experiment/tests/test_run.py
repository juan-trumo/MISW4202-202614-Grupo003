"""Unitarias del arnés: cálculos de meets_target y verdict, salidas y registro de requests."""

import csv

import pytest

from experiment import run
from experiment.recording import target_service

LOOKUP = {"CONSENT_MODE": "lookup", "TOKEN_TTL": "900", "CONSENT_CACHE_TTL": "0"}
CLAIM = {"CONSENT_MODE": "claim", "TOKEN_TTL": "900", "CONSENT_CACHE_TTL": "0"}


def _reps(*values):
    return [{"rep": i, "customer_id": f"C-00{i}", "propagation_s": v,
             "denied_code": 403 if v is not None else None, "denied_error": "consent_revoked",
             "polls": 1, "reauths": 0, "errors": []} for i, v in enumerate(values, start=1)]


def test_resumen_cumple_solo_si_todas_las_reps_estan_bajo_la_meta():
    ok = run.summarize_config("C4", LOOKUP, _reps(0.02, 0.03, 0.05))
    assert (ok["min"], ok["median"], ok["max"]) == (0.02, 0.03, 0.05)
    assert ok["meets_target"] is True and ok["cache_ttl"] == 0

    over = run.summarize_config("C3", CLAIM, _reps(890.1, 899.9, 300.2))
    assert over["meets_target"] is False and over["cache_ttl"] is None

    borderline = run.summarize_config("C2", CLAIM, _reps(300.0))
    assert borderline["meets_target"] is True  # la meta es <= 300 s


def test_repeticion_sin_rechazo_no_cumple_y_se_cuenta():
    summary = run.summarize_config("C3", CLAIM, _reps(10.0, None))
    assert summary["unobserved"] == 1
    assert summary["meets_target"] is False
    assert summary["max"] == 10.0


def test_veredicto_a_evalua_solo_lookup():
    seg02 = [run.summarize_config("C3", CLAIM, _reps(900.0)),
             run.summarize_config("C4", LOOKUP, _reps(0.1))]
    audit = {"meets_target": True}
    verdict = run.verdict(seg02, audit, {"meets_target": True})
    assert verdict["a"] is True
    assert verdict["sensitivity_claim"] == {"C3": False}
    assert run.verdict(seg02[:1], audit, None)["a"] is None  # sin lookup no hay veredicto (a)


def test_csv_tiene_una_fila_por_repeticion(tmp_path):
    seg02 = [run.summarize_config("C4", LOOKUP, _reps(0.1, None))]
    path = tmp_path / "r.csv"
    run.write_csv(seg02, path)
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert len(rows) == 2
    assert rows[0]["rep_meets_target"] == "True" and rows[1]["rep_meets_target"] == "False"


def test_grafica_se_genera(tmp_path):
    seg02 = [run.summarize_config("C1", CLAIM, _reps(58.0, 59.5)),
             run.summarize_config("C3", CLAIM, _reps(None))]
    path = tmp_path / "p.png"
    run.plot_propagation(seg02, path)
    assert path.stat().st_size > 10_000


@pytest.mark.parametrize("url,service", [
    ("http://localhost:8002/auth/token", "auth-service"),
    ("http://localhost:8001/consents/abc/revoke", "consent-service"),
    ("http://localhost:8002/quotes", "quote-service"),
    ("http://localhost:8002/policies", "policy-service"),
    ("http://127.0.0.1:5004/policies/count", None),  # observación: no es tráfico de negocio
    ("http://127.0.0.1:5005/events", None),
])
def test_target_service(url, service):
    assert target_service(url) == service


def test_args_validan_reps_y_configs():
    with pytest.raises(SystemExit):
        run.parse_args(["--reps", "6"])
    with pytest.raises(SystemExit):
        run.parse_args(["--configs", "C9"])
    assert run.parse_args(["--configs", "c1,c4"]).configs == ["C1", "C4"]
