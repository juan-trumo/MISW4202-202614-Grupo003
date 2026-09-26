"""Cliente de socio para SEG-08: firma payloads de emisión y genera variantes alteradas.

Modelo de amenaza (D2): el socio firma con su clave HMAC y un intermediario comprometido altera
el mensaje DESPUÉS de firmado. Cada escenario reproduce una alteración de §11 (TC-I-02..08).

Uso:
    python experiment/partner_client.py          # corre todos los escenarios y resume
"""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.hmac_utils import SIGNATURE_HEADER, sign_payload  # noqa: E402
from experiment.envfile import load_env  # noqa: E402

BFF_SOCIO = "http://localhost:8002"
POLICY_OBSERVER = "http://127.0.0.1:5004"  # solo con docker-compose.experiment.yml
TIMEOUT = 10


@dataclass
class Partner:
    client_id: str
    secret: str
    partner_uuid: str
    hmac_key: str
    bff_url: str = BFF_SOCIO
    _token: str | None = field(default=None, repr=False)

    def token(self, refresh: bool = False) -> str:
        if self._token is None or refresh:
            resp = requests.post(
                f"{self.bff_url}/auth/token",
                json={"client_id": self.client_id, "client_secret": self.secret},
                timeout=TIMEOUT,
            )
            resp.raise_for_status()
            self._token = resp.json()["access_token"]
        return self._token

    def build_payload(
        self,
        holder_id: str = "C-001",
        holder_name: str = "Ana Gómez",
        premium: str = "125000.00",
        coverage: str = "50000000.00",
    ) -> dict:
        return {
            "partner_uuid": self.partner_uuid,
            "quote_id": str(uuid.uuid4()),
            "holder_id": holder_id,
            "holder_name": holder_name,
            "premium": premium,
            "coverage": coverage,
            "currency": "COP",
            "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "nonce": str(uuid.uuid4()),
        }

    def sign(self, payload: dict) -> str:
        return sign_payload(self.hmac_key, payload)

    def issue(self, payload: dict, signature: str | None, cid: str | None = None):
        headers = {"Authorization": f"Bearer {self.token()}"}
        if signature is not None:
            headers[SIGNATURE_HEADER] = signature
        if cid:
            headers["X-Correlation-ID"] = cid
        return requests.post(f"{self.bff_url}/policies", json=payload, headers=headers,
                             timeout=TIMEOUT)


def partners_from_env(env: dict[str, str] | None = None) -> tuple[Partner, Partner]:
    env = env or load_env()
    secrets = json.loads(env["SEED_SECRETS"])
    keys = json.loads(env["PARTNER_HMAC_KEYS"])
    a, b = env["PARTNER_A_UUID"], env["PARTNER_B_UUID"]
    return (
        Partner("socio-a", secrets["socio-a"], a, keys[a]),
        Partner("socio-b", secrets["socio-b"], b, keys[b]),
    )


def policy_count(observer_url: str = POLICY_OBSERVER) -> dict:
    resp = requests.get(f"{observer_url}/policies/count", timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()


# --- Escenarios de alteración -------------------------------------------------------------
# Cada uno devuelve (payload_enviado, firma_enviada). La firma se calcula SIEMPRE sobre el
# payload original y la alteración ocurre después, como la haría un intermediario.


@dataclass(frozen=True)
class Scenario:
    case_id: str
    name: str
    expected_status: int
    expected_error: str
    build: Callable[[Partner, Partner], tuple[dict, str | None]]


def _tamper(field_name: str, value: str) -> Callable[[Partner, Partner], tuple[dict, str | None]]:
    def build(a: Partner, _b: Partner):
        payload = a.build_payload()
        signature = a.sign(payload)
        return {**payload, field_name: value}, signature

    return build


def _no_signature(a: Partner, _b: Partner):
    return a.build_payload(), None


def _signed_with_other_key(a: Partner, b: Partner):
    payload = a.build_payload()
    return payload, b.sign(payload)


def _other_partner_in_body(a: Partner, b: Partner):
    payload = {**a.build_payload(), "partner_uuid": b.partner_uuid}
    return payload, b.sign(payload)


def _extra_field(a: Partner, _b: Partner):
    payload = a.build_payload()
    signature = a.sign(payload)
    return {**payload, "discount": "50.00"}, signature


TAMPER_SCENARIOS: list[Scenario] = [
    Scenario("TC-I-02", "prima alterada", 422, "integrity_failed", _tamper("premium", "1.00")),
    Scenario("TC-I-03", "cobertura alterada", 422, "integrity_failed",
             _tamper("coverage", "900000000.00")),
    Scenario("TC-I-04", "tomador alterado", 422, "integrity_failed",
             _tamper("holder_name", "Tomador Falso")),
    Scenario("TC-I-05", "sin X-Signature", 400, "missing_signature", _no_signature),
    Scenario("TC-I-06", "firmado con clave de B y token de A", 422, "integrity_failed",
             _signed_with_other_key),
    Scenario("TC-I-07", "partner_uuid del body distinto al del token", 403, "partner_mismatch",
             _other_partner_in_body),
    Scenario("TC-I-08", "campo extra inyectado", 400, "unknown_field", _extra_field),
]


def run_integrity_suite(a: Partner, b: Partner, repetitions: int = 1) -> dict:
    """Envía un payload íntegro y todos los alterados; mide rechazos y filas nuevas."""
    before = policy_count()["count"]
    payload = a.build_payload()
    intact = a.issue(payload, a.sign(payload))
    after_intact = policy_count()["count"]

    results = []
    for _ in range(repetitions):
        for scenario in TAMPER_SCENARIOS:
            sent, signature = scenario.build(a, b)
            resp = a.issue(sent, signature)
            error = resp.json().get("error") if resp.status_code >= 400 else None
            results.append({
                "case_id": scenario.case_id,
                "name": scenario.name,
                "status": resp.status_code,
                "error": error,
                "rejected": resp.status_code >= 400,
                "as_expected": (resp.status_code, error)
                == (scenario.expected_status, scenario.expected_error),
            })
    after = policy_count()
    total = after["count"]
    return {
        "intact_status": intact.status_code,
        "intact_rows_added": after_intact - before,
        "tampered_sent": len(results),
        "rejected": sum(r["rejected"] for r in results),
        "rows_added": after["count"] - after_intact,
        "validation_rate": after["integrity_verified"] / total if total else 1.0,
        "cases": results,
    }


def main() -> int:
    a, b = partners_from_env()
    summary = run_integrity_suite(a, b)
    print(f"Payload íntegro: HTTP {summary['intact_status']}, "
          f"filas nuevas {summary['intact_rows_added']}")
    for case in summary["cases"]:
        mark = "OK  " if case["as_expected"] else "FAIL"
        print(f"{mark} {case['case_id']} {case['name']:<45} HTTP {case['status']} {case['error']}")
    print(f"\nAlterados enviados: {summary['tampered_sent']} · rechazados: {summary['rejected']} · "
          f"filas nuevas por alterados: {summary['rows_added']} · "
          f"validation_rate: {summary['validation_rate']:.2f}")
    ok = summary["rows_added"] == 0 and all(c["as_expected"] for c in summary["cases"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
