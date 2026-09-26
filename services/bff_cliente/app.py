"""bff-cliente :8001 — Solventa, experimento de seguridad.

Tácticas: limitar exposición (única entrada del canal cliente; solo rutas de token y
consentimiento; los servicios internos no publican puertos). Crea el X-Correlation-ID si no
llega y reenvía Authorization sin tocarlo. No valida tokens ni tiene lógica de negocio: cada
servicio interno valida por sí mismo. ASR: SEG-02.
"""

import os
from urllib.parse import quote

from common.app_base import create_app
from common.bff import forward

AUTH_URL = os.environ.get("AUTH_URL", "http://auth:5001")
CONSENT_URL = os.environ.get("CONSENT_URL", "http://consent:5002")

app = create_app("bff-cliente", verify_tokens=False, audit_enabled=False)


@app.post("/auth/token")
def token():
    return forward(AUTH_URL, "/token")


@app.post("/consents")
def create_consent():
    return forward(CONSENT_URL, "/consents")


@app.get("/consents/<consent_id>")
def get_consent(consent_id: str):
    return forward(CONSENT_URL, f"/consents/{quote(consent_id, safe='')}")


@app.post("/consents/<consent_id>/revoke")
def revoke_consent(consent_id: str):
    return forward(CONSENT_URL, f"/consents/{quote(consent_id, safe='')}/revoke")
