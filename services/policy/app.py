"""policy-service :5004 — Solventa, experimento de seguridad.

Tácticas: verificar integridad del mensaje (HMAC-SHA256 sobre el payload canónico, verificado
ANTES de abrir la transacción e insertar); autorizar actores (policy:issue; el partner_uuid del
body debe igualar al del token y la clave HMAC se elige por el partner del token, nunca por el
body); separar entidades (único dueño de policy.db); mantener auditoría con falla cerrada.
ASR: SEG-08.

Cualquier rechazo se audita como DENY y no produce INSERT: 0 pólizas alteradas persistidas.
Limitación declarada: HMAC con clave compartida da integridad y autenticidad, no no-repudio.
"""

import os
import re
import uuid
from datetime import datetime
from pathlib import Path

from flask import g, jsonify, request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from common import scopes
from common.app_base import create_app, experiment_mode
from common.audit_client import ALLOW, DENY, audit_event
from common.errors import ApiError
from common.hmac_utils import (
    SIGNATURE_HEADER,
    load_partner_keys,
    missing_fields,
    unknown_fields,
    verify_signature,
)

from models import Policy, init_db

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
PARTNER_KEYS = load_partner_keys(os.environ.get("PARTNER_HMAC_KEYS"))
ACTION = "policy.issue"
DECIMAL_RE = re.compile(r"^\d{1,15}\.\d{2}$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
MAX_TEXT = 128

Session = init_db(DATA_DIR)
app = create_app("policy-service")


def _deny(status: int, code: str, detail: str) -> ApiError:
    audit_event(action=ACTION, resource=request.path, decision=DENY, reason=code, claims=g.claims)
    return ApiError(status, code, detail)


def _format_errors(payload: dict) -> str | None:
    """Validación de formato (§7.3). Se hace después del HMAC: la integridad va primero."""
    for field, value in payload.items():
        if not isinstance(value, str) or not value or len(value) > MAX_TEXT:
            return f"{field} debe ser texto no vacío de hasta {MAX_TEXT} caracteres"
    if not DECIMAL_RE.match(payload["premium"]):
        return 'premium debe ser un decimal con 2 decimales, p. ej. "125000.00"'
    if not CURRENCY_RE.match(payload["currency"]):
        return "currency debe ser un código ISO de 3 letras"
    try:
        datetime.fromisoformat(payload["issued_at"].replace("Z", "+00:00"))
        uuid.UUID(payload["nonce"])
    except ValueError:
        return "issued_at debe ser ISO-8601 y nonce un uuid"
    return None


@app.post("/policies")
@scopes.require_scope(scopes.POLICY_ISSUE, action=ACTION)
def issue_policy():
    token_partner = g.claims.get("partner_uuid")
    if g.claims.get("actor_type") != "partner" or not token_partner:
        raise _deny(403, "insufficient_scope", "Solo un socio puede emitir pólizas")
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise _deny(400, "invalid_request", "Se espera un objeto JSON")

    # 1. Autorización: el socio solo emite a su nombre.
    if str(payload.get("partner_uuid", "")).lower() != token_partner.lower():
        raise _deny(403, "partner_mismatch", "partner_uuid del body no coincide con el del token")
    # 2. Superficie del mensaje: ni campos de más ni de menos.
    unknown = unknown_fields(payload)
    if unknown:
        raise _deny(400, "unknown_field", f"Campos no permitidos: {', '.join(unknown)}")
    missing = missing_fields(payload)
    if missing:
        raise _deny(400, "invalid_request", f"Faltan campos: {', '.join(missing)}")
    # 3. Integridad: HMAC con la clave del socio del TOKEN, antes de tocar la BD.
    signature = request.headers.get(SIGNATURE_HEADER, "").strip()
    if not signature:
        raise _deny(400, "missing_signature", f"Falta el header {SIGNATURE_HEADER}")
    key = PARTNER_KEYS.get(token_partner)
    if key is None or not verify_signature(key, payload, signature):
        raise _deny(422, "integrity_failed", "La firma no corresponde al payload")
    # 4. Formato y anti-replay.
    problem = _format_errors(payload)
    if problem:
        raise _deny(400, "invalid_request", problem)
    with Session() as session:
        if session.scalar(select(Policy.id).where(Policy.nonce == payload["nonce"])):
            raise _deny(409, "replay_detected", "nonce ya utilizado")

    audit_event(action=ACTION, resource=request.path, decision=ALLOW, reason="integrity_verified",
                claims=g.claims)
    policy = Policy(**payload, signature=signature.lower(), integrity_verified=True)
    try:
        with Session.begin() as session:
            session.add(policy)
    except IntegrityError:
        # Dos emisiones concurrentes con el mismo nonce: la restricción UNIQUE decide.
        raise _deny(409, "replay_detected", "nonce ya utilizado") from None
    return jsonify({"policy_id": policy.id}), 201


@app.get("/policies/count")
def count_policies():
    if not experiment_mode():
        raise ApiError(404, "not_found", "Disponible solo con EXPERIMENT_MODE=1")
    with Session() as session:
        total = session.scalar(select(func.count()).select_from(Policy))
        verified = session.scalar(
            select(func.count()).select_from(Policy).where(Policy.integrity_verified.is_(True))
        )
    return jsonify({"count": total, "integrity_verified": verified})
