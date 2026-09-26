"""Unitarias de report.py: el texto se condiciona a los datos y no inventa números."""

import copy

import pytest

from experiment import report, run

TARGET = 300


def _cfg(name, mode, ttl, cache, values):
    env = {"CONSENT_MODE": mode, "TOKEN_TTL": str(ttl), "CONSENT_CACHE_TTL": str(cache)}
    reps = [{"rep": i, "customer_id": f"C-00{i}", "propagation_s": v, "denied_code": 403,
             "denied_error": "consent_revoked", "polls": 1, "reauths": 0, "errors": []}
            for i, v in enumerate(values, start=1)]
    return run.summarize_config(name, env, reps)


def _results(**overrides):
    seg02 = [
        _cfg("C1", "claim", 60, 0, [60.2, 60.3]),
        _cfg("C2", "claim", 300, 0, [300.1, 300.2]),
        _cfg("C3", "claim", 900, 0, [900.1, 899.8]),
        _cfg("C4", "lookup", 900, 0, [0.03, 0.04]),
        _cfg("C5", "lookup", 900, 60, [59.9, 60.1]),
    ]
    audit = {"requests": 800, "events": 800, "coverage": 1.0, "meets_target": True,
             "by_service": {"quote-service": {"requests": 500, "events": 500}},
             "missing": [], "samples": [{"service": "quote-service", "status": 200,
                                         "correlation_id": "c1-r1-abc"}]}
    seg08 = {"tampered_sent": 35, "rejected": 35, "rows_added": 0, "validation_rate": 1.0,
             "intact_accepted": True, "meets_target": True,
             "cases": [{"case_id": "TC-I-02", "name": "prima alterada", "status": 422,
                        "error": "integrity_failed", "rejected": True, "as_expected": True}]}
    results = {
        "run_id": "20260926T000000Z-abc123", "git_commit": "0123456789abcdef",
        "git_dirty": False, "started_at": "2026-09-26T00:00:00+00:00",
        "parameters": {"configs": ["C1", "C2", "C3", "C4", "C5"], "reps": 5, "poll_s": 5.0},
        "seg02": seg02, "audit": audit, "seg08": seg08,
    }
    results.update(overrides)
    results["verdict"] = run.verdict(results["seg02"], results["audit"], results["seg08"])
    return results


EFFORT = {"total": 12.5, "by_member": {"Ana": 7.5, "Luis": 5.0}, "rows": 3, "invalid": 0,
          "exists": True}
NO_EFFORT = {"total": 0.0, "by_member": {}, "rows": 0, "invalid": 0, "exists": True}


def _build(results, effort=EFFORT, tmp_path=None):
    return report.build_report(results, effort, report.ROOT / "results" / "results.json")


def test_hipotesis_confirmada_con_numeros_del_json():
    text = _build(_results())
    assert "La hipótesis quedó **confirmada**" in text
    assert "800 de 800 (100.0 %)" in text
    assert "35 de 35" in text
    assert "12.5 horas" in text and "Ana: 7.5 h" in text
    # C3 viola la meta pero es punto de sensibilidad, no fallo del diseño.
    assert "C3 viola la meta, como se esperaba" in text
    assert "C2 queda en el límite" in text
    assert "c1-r1-abc" in text


def test_fallo_en_lookup_se_reporta_con_cambio_y_costo():
    results = _results()
    results["seg02"][4] = _cfg("C5", "lookup", 900, 60, [59.9, None])
    results["verdict"] = run.verdict(results["seg02"], results["audit"], results["seg08"])
    text = _build(results)
    assert "**confirmada parcialmente**" in text
    assert "1 repetición sin rechazo" in text
    assert "reducir CONSENT_CACHE_TTL" in text
    # La decisión favorable de revocación no se lista si (a) no se cumplió.
    assert "Revocar acceso" not in text.split("### 2.")[1].split("### 3.")[0]


def test_auditoria_e_integridad_fallidas():
    results = _results()
    results["audit"] = {**results["audit"], "events": 798, "coverage": 798 / 800,
                        "meets_target": False,
                        "missing": [{"service": "policy-service", "correlation_id": "x"}]}
    seg08 = copy.deepcopy(results["seg08"])
    seg08.update(rejected=34, rows_added=1, meets_target=False)
    seg08["cases"][0].update(status=201, error=None, rejected=False, as_expected=False)
    results["seg08"] = seg08
    results["verdict"] = run.verdict(results["seg02"], results["audit"], results["seg08"])
    text = _build(results)
    assert "2 requests sin evento" in text and "policy-service: 1" in text
    assert "TC-I-02 (HTTP 201)" in text
    assert "❌ no cumple" in text


def test_sin_horas_queda_pendiente_y_no_inventa():
    text = _build(_results(), NO_EFFORT)
    assert "**PENDIENTE**" in text
    assert "horas**" not in text


def test_corrida_parcial_y_sucia_se_advierte():
    results = _results(git_dirty=True, parameters={"configs": ["C1", "C4"], "reps": 1,
                                                   "poll_s": 5.0})
    text = _build(results)
    assert "Corrida **parcial** (C1, C4; 1 repetición)" in text
    assert "en esta corrida parcial" in text
    assert "git_dirty: true" in text


def test_load_effort_suma_y_descarta_filas_invalidas(tmp_path):
    path = tmp_path / "effort.csv"
    path.write_text("fecha,integrante,tarea,horas\n"
                    "2026-09-20,Ana,auth,2.5\n"
                    "2026-09-21,Ana,tests,\"1,5\"\n"
                    "2026-09-21,Luis,policy,3\n"
                    "2026-09-22,,sin nombre,2\n"
                    "2026-09-22,Luis,x,abc\n", encoding="utf-8")
    effort = report.load_effort(path)
    assert effort["total"] == pytest.approx(7.0)
    assert effort["by_member"] == {"Ana": 4.0, "Luis": 3.0}
    assert effort["invalid"] == 2


def test_main_sin_results_falla_con_mensaje(tmp_path, capsys):
    code = report.main(["--results", str(tmp_path / "no.json"), "--out", str(tmp_path / "o.md")])
    assert code == 1
    assert "Corre primero el experimento" in capsys.readouterr().out
