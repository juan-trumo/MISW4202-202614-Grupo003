"""Medición de audit_coverage (D4, TC-AD-01).

Envía una batería de requests a los servicios protegidos, permitidos y denegados, cada uno con
su propio X-Correlation-ID, y comprueba que el servicio destino dejó al menos un evento en
audit-service con ese correlation_id:

    audit_coverage = requests con evento del servicio destino / requests enviados

Uso:
    python experiment/audit_probe.py
"""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from experiment.envfile import load_env  # noqa: E402
from experiment.partner_client import BFF_SOCIO, TIMEOUT, partners_from_env  # noqa: E402

BFF_CLIENTE = "http://localhost:8001"
AUDIT_OBSERVER = "http://127.0.0.1:5005"  # solo con docker-compose.experiment.yml
CUSTOMER = "cliente-005"
CUSTOMER_ID = "C-005"


def audit_events(cid: str) -> list[dict]:
    resp = requests.get(f"{AUDIT_OBSERVER}/events", params={"correlation_id": cid},
                        timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def new_cid(prefix: str = "probe") -> str:
    return f"{prefix}-{uuid.uuid4()}"


def _bearer(token: str | None) -> dict:
    return {"Authorization": f"Bearer {token}"} if token else {}


def _token(bff: str, client_id: str, secret: str) -> str:
    resp = requests.post(f"{bff}/auth/token",
                         json={"client_id": client_id, "client_secret": secret}, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json()["access_token"]


@dataclass
class Probe:
    name: str
    service: str  # servicio protegido que DEBE auditar este request
    expected_status: int
    send: Callable[[str], requests.Response]


def build_probes(env: dict[str, str]) -> list[Probe]:
    secrets = json.loads(env["SEED_SECRETS"])
    a, b = partners_from_env(env)
    customer_token = _token(BFF_CLIENTE, CUSTOMER, secrets[CUSTOMER])
    other_customer = _token(BFF_CLIENTE, "cliente-004", secrets["cliente-004"])
    state: dict[str, str] = {}

    def post(url, cid, token=None, body=None, extra=None):
        headers = {"X-Correlation-ID": cid, **_bearer(token), **(extra or {})}
        return requests.post(url, json=body, headers=headers, timeout=TIMEOUT)

    def get(url, cid, token=None):
        return requests.get(url, headers={"X-Correlation-ID": cid, **_bearer(token)},
                            timeout=TIMEOUT)

    def create_consent(cid):
        resp = post(f"{BFF_CLIENTE}/consents", cid, customer_token,
                    {"purpose": "quotation", "granted_to": a.partner_uuid})
        state["consent_id"] = resp.json().get("id", "")
        return resp

    def quote(partner_token):
        return lambda cid: post(f"{BFF_SOCIO}/quotes", cid, partner_token,
                                {"customer_id": CUSTOMER_ID, "product": "auto"})

    def policy(tampered: bool, signed: bool = True):
        def send(cid):
            payload = a.build_payload(holder_id=CUSTOMER_ID)
            signature = a.sign(payload) if signed else None
            if tampered:
                payload["premium"] = "1.00"
            return a.issue(payload, signature, cid=cid)
        return send

    return [
        Probe("token válido", "auth-service", 200,
              lambda cid: post(f"{BFF_SOCIO}/auth/token", cid, body={
                  "client_id": a.client_id, "client_secret": a.secret})),
        Probe("token con secreto inválido", "auth-service", 401,
              lambda cid: post(f"{BFF_SOCIO}/auth/token", cid, body={
                  "client_id": a.client_id, "client_secret": "incorrecto"})),
        Probe("crear consentimiento", "consent-service", 201, create_consent),
        Probe("leer consentimiento propio", "consent-service", 200,
              lambda cid: get(f"{BFF_CLIENTE}/consents/{state['consent_id']}", cid,
                              customer_token)),
        Probe("leer consentimiento ajeno", "consent-service", 404,
              lambda cid: get(f"{BFF_CLIENTE}/consents/{state['consent_id']}", cid,
                              other_customer)),
        Probe("cotizar con consentimiento", "quote-service", 200, quote(a.token())),
        Probe("cotizar con otro socio", "quote-service", 403, quote(b.token())),
        Probe("cotizar sin token", "quote-service", 401, quote(None)),
        Probe("cotizar con token de cliente", "quote-service", 403, quote(customer_token)),
        Probe("emitir íntegro", "policy-service", 201, policy(tampered=False)),
        Probe("emitir alterado", "policy-service", 422, policy(tampered=True)),
        Probe("emitir sin firma", "policy-service", 400, policy(tampered=False, signed=False)),
        Probe("emitir con token inválido", "policy-service", 401,
              lambda cid: post(f"{BFF_SOCIO}/policies", cid, "no-es-un-jwt", {})),
        Probe("revocar consentimiento", "consent-service", 200,
              lambda cid: post(f"{BFF_CLIENTE}/consents/{state['consent_id']}/revoke", cid,
                               customer_token)),
        Probe("cotizar tras revocar", "quote-service", 403, quote(a.token())),
    ]


def run_audit_coverage(env: dict[str, str] | None = None) -> dict:
    env = env or load_env()
    results = []
    for probe in build_probes(env):
        cid = new_cid()
        resp = probe.send(cid)
        events = audit_events(cid)
        results.append({
            "name": probe.name,
            "service": probe.service,
            "correlation_id": cid,
            "status": resp.status_code,
            "status_ok": resp.status_code == probe.expected_status,
            "events": len(events),
            "audited": any(e["service"] == probe.service for e in events),
            "decisions": sorted({e["decision"] for e in events if e["service"] == probe.service}),
        })
    audited = sum(r["audited"] for r in results)
    return {
        "requests": len(results),
        "events": audited,
        "total_events": sum(r["events"] for r in results),
        "coverage": audited / len(results),
        "meets_target": audited == len(results),
        "probes": results,
    }


def main() -> int:
    # En Windows, sin esto los acentos salen mal al redirigir o en Git Bash.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    summary = run_audit_coverage()
    for probe in summary["probes"]:
        mark = "OK  " if probe["audited"] and probe["status_ok"] else "FAIL"
        print(f"{mark} {probe['name']:<32} HTTP {probe['status']}  {probe['service']:<16} "
              f"{','.join(probe['decisions']) or 'SIN EVENTO'}")
    print(f"\nRequests: {summary['requests']} · con evento: {summary['events']} · "
          f"audit_coverage: {summary['coverage']:.2%}")
    return 0 if summary["meets_target"] else 1


if __name__ == "__main__":
    sys.exit(main())
