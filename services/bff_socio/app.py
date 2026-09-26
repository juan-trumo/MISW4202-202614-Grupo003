"""bff-socio :8002 — Solventa, experimento de seguridad.

Tácticas: limitar exposición (única entrada del canal socio; solo token, cotización y emisión;
NO expone rutas de consentimiento, por eso /consents responde 404). Crea el X-Correlation-ID si
no llega y reenvía Authorization y X-Signature sin tocarlos; el cuerpo viaja byte a byte para
no romper el HMAC. No valida tokens ni tiene lógica de negocio. ASR: SEG-02, SEG-08.
"""

import os

from common.app_base import create_app
from common.bff import forward

AUTH_URL = os.environ.get("AUTH_URL", "http://auth:5001")
QUOTE_URL = os.environ.get("QUOTE_URL", "http://quote:5003")
POLICY_URL = os.environ.get("POLICY_URL", "http://policy:5004")

app = create_app("bff-socio", verify_tokens=False, audit_enabled=False)


@app.post("/auth/token")
def token():
    return forward(AUTH_URL, "/token")


@app.post("/quotes")
def create_quote():
    return forward(QUOTE_URL, "/quotes")


@app.post("/policies")
def create_policy():
    return forward(POLICY_URL, "/policies")
