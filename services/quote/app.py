"""quote-service :5003 — Solventa, experimento de seguridad.

Tácticas: autorizar actores (finance:read; partner_uuid sale solo del claim firmado, nunca del
body); revocar acceso (antes de usar datos financieros verifica el consentimiento según
CONSENT_MODE y CONSENT_CACHE_TTL, el punto de sensibilidad de SEG-02); mantener auditoría con
falla cerrada (se audita ANTES de leer los datos financieros). ASR: SEG-02.

- lookup: consulta consent-service (el dueño del dato) en cada uso; solo cachea autorizaciones,
  así que un consentimiento revocado deja de valer en <= CONSENT_CACHE_TTL segundos.
- claim: solo mira el claim `consents` del token; la revocación se nota cuando el token expira.
"""

import hashlib
import os
import threading
import time
import uuid
from decimal import Decimal

import requests
from flask import g, jsonify, request

from common import scopes
from common.app_base import create_app, env_float
from common.audit_client import ALLOW, DENY, audit_event
from common.correlation import outbound_headers
from common.errors import ApiError

CONSENT_MODE = os.environ.get("CONSENT_MODE", "lookup")
CONSENT_CACHE_TTL = env_float("CONSENT_CACHE_TTL", 0)
CONSENT_URL = os.environ.get("CONSENT_URL", "http://consent:5002")
PURPOSE = "quotation"
ACTION = "quote.create"
QUOTE_FIELDS = {"customer_id", "product"}

if CONSENT_MODE not in ("lookup", "claim"):
    raise RuntimeError(f"CONSENT_MODE inválido: {CONSENT_MODE}")

app = create_app("quote-service")


class ConsentCache:
    """Caché en memoria de autorizaciones ALLOW por (customer, purpose, partner) con TTL."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str, str], float] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: tuple[str, str, str]) -> bool:
        with self._lock:
            expires_at = self._entries.get(key)
            if expires_at is None:
                return False
            if time.monotonic() >= expires_at:
                del self._entries[key]
                return False
            return True

    def remember(self, key: tuple[str, str, str], ttl: float) -> None:
        if ttl > 0:
            with self._lock:
                self._entries[key] = time.monotonic() + ttl

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


CACHE = ConsentCache()


def check_with_owner(customer_id: str, partner_uuid: str) -> tuple[bool, str]:
    """Modo lookup: pregunta a consent-service con el token del servicio (consent:read)."""
    token_provider = app.extensions["solventa"].service_token
    try:
        resp = requests.get(
            f"{CONSENT_URL}/consents/check",
            params={"customer_id": customer_id, "purpose": PURPOSE, "partner_uuid": partner_uuid},
            headers=outbound_headers(token_provider.get()),
            timeout=2,
        )
    except requests.RequestException:
        resp = None
    if resp is None or resp.status_code != 200:
        raise ApiError(503, "consent_unavailable", "No se pudo verificar el consentimiento")
    data = resp.json()
    return bool(data.get("allowed")), str(data.get("reason", "consent_not_found"))


def authorize(customer_id: str, partner_uuid: str, claims: dict) -> tuple[bool, str]:
    if CONSENT_MODE == "claim":
        if customer_id in (claims.get("consents") or []):
            return True, "consent_in_claim"
        return False, "consent_not_found"
    key = (customer_id, PURPOSE, partner_uuid)
    if CACHE.is_allowed(key):
        return True, "consent_cached"
    allowed, reason = check_with_owner(customer_id, partner_uuid)
    if allowed:
        CACHE.remember(key, CONSENT_CACHE_TTL)
    return allowed, reason


def financial_premium(customer_id: str) -> str:
    """Mock determinista de los datos financieros de Open Finance. Solo sale la prima."""
    digest = hashlib.sha256(customer_id.encode("utf-8")).digest()
    monthly_income = Decimal(2_000_000 + int.from_bytes(digest[:4], "big") % 8_000_000)
    debt_ratio = Decimal(digest[4] % 60) / Decimal(100)
    premium = monthly_income * Decimal("0.02") * (1 + debt_ratio)
    return str(premium.quantize(Decimal("0.01")))


def _deny(status: int, code: str, detail: str) -> ApiError:
    audit_event(action=ACTION, resource=request.path, decision=DENY, reason=code, claims=g.claims)
    return ApiError(status, code, detail)


@app.post("/quotes")
@scopes.require_scope(scopes.FINANCE_READ, action=ACTION)
def create_quote():
    partner_uuid = g.claims.get("partner_uuid")
    if g.claims.get("actor_type") != "partner" or not partner_uuid:
        raise _deny(403, "insufficient_scope", "Solo un socio puede cotizar")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise _deny(400, "invalid_request", "Se espera JSON {customer_id, product}")
    unknown = sorted(set(body) - QUOTE_FIELDS)
    if unknown:
        raise _deny(400, "unknown_field", f"Campos no permitidos: {', '.join(unknown)}")
    customer_id, product = body.get("customer_id"), body.get("product")
    if not (isinstance(customer_id, str) and 0 < len(customer_id) <= 64):
        raise _deny(400, "invalid_request", "customer_id es obligatorio")
    if not (isinstance(product, str) and 0 < len(product) <= 64):
        raise _deny(400, "invalid_request", "product es obligatorio")

    try:
        allowed, reason = authorize(customer_id, partner_uuid, g.claims)
    except ApiError as err:
        raise _deny(err.status, err.code, err.detail) from None
    if not allowed:
        raise _deny(403, reason, "El consentimiento no autoriza este uso de datos")

    # Se audita antes de tocar los datos: si la auditoría falla, no se leen (falla cerrada).
    audit_event(action=ACTION, resource=request.path, decision=ALLOW, reason=reason,
                claims=g.claims)
    return jsonify({
        "quote_id": str(uuid.uuid4()),
        "premium": financial_premium(customer_id),
        "customer_id": customer_id,
        "partner_uuid": partner_uuid,
        "product": product,
    })
