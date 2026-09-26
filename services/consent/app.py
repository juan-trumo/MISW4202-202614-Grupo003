"""consent-service :5002 — Solventa, experimento de seguridad.

Tácticas: separar entidades (único dueño y escritor de consent.db); revocar acceso (ACTIVE →
REVOKED, efectivo en la siguiente consulta); autorizar actores (consent:write solo para el
cliente dueño, cuyo customer_id sale del token; consent:read solo para servicios); mantener
auditoría con falla cerrada en cada operación. ASR: SEG-02.
"""

import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from flask import g, jsonify, request
from sqlalchemy import select

from common import scopes
from common.app_base import create_app
from common.audit_client import ALLOW, DENY, audit_event
from common.errors import ApiError

from models import ACTIVE, REVOKED, Consent, init_db

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
PURPOSE_RE = re.compile(r"^[a-z][a-z_]{1,63}$")
CREATE_FIELDS = {"purpose", "granted_to"}

Session = init_db(DATA_DIR)
app = create_app("consent-service")


def _audit(action: str, decision: str, reason: str) -> None:
    audit_event(action=action, resource=request.path, decision=decision, reason=reason,
                claims=g.claims)


def _deny(action: str, status: int, code: str, detail: str) -> ApiError:
    _audit(action, DENY, code)
    return ApiError(status, code, detail)


def _owner_customer_id(action: str) -> str:
    customer_id = g.claims.get("customer_id")
    if g.claims.get("actor_type") != "customer" or not customer_id:
        detail = "Solo un cliente gestiona sus consentimientos"
        raise _deny(action, 403, "insufficient_scope", detail)
    return customer_id


def _owned_consent(session, consent_id: str, action: str) -> Consent:
    customer_id = _owner_customer_id(action)
    consent = session.get(Consent, consent_id)
    # Un consentimiento ajeno responde igual que uno inexistente: no se revela que existe.
    if consent is None or consent.customer_id != customer_id:
        raise _deny(action, 404, "consent_not_found", "Consentimiento no encontrado")
    return consent


def _is_uuid(value) -> bool:
    try:
        uuid.UUID(str(value))
    except ValueError:
        return False
    return True


def decide(consents: list[Consent], partner_uuid: str, purpose: str) -> tuple[bool, str]:
    """Decisión de acceso sobre los consentimientos de un cliente (orden en CLAUDE.md §8)."""
    exact = [c for c in consents if c.granted_to == partner_uuid and c.purpose == purpose]
    if any(c.status == ACTIVE for c in exact):
        return True, "consent_active"
    if exact:
        return False, "consent_revoked"
    active = [c for c in consents if c.status == ACTIVE]
    if any(c.granted_to == partner_uuid for c in active):
        return False, "purpose_mismatch"
    if any(c.purpose == purpose for c in active):
        return False, "partner_mismatch"
    return False, "consent_not_found"


@app.post("/consents")
@scopes.require_scope(scopes.CONSENT_WRITE, action="consent.create")
def create_consent():
    action = "consent.create"
    customer_id = _owner_customer_id(action)
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise _deny(action, 400, "invalid_request", "Se espera JSON {purpose, granted_to}")
    unknown = sorted(set(body) - CREATE_FIELDS)
    if unknown:
        raise _deny(action, 400, "unknown_field", f"Campos no permitidos: {', '.join(unknown)}")
    purpose, granted_to = body.get("purpose"), body.get("granted_to")
    if not isinstance(purpose, str) or not PURPOSE_RE.match(purpose):
        raise _deny(action, 400, "invalid_request", "purpose inválido")
    if not isinstance(granted_to, str) or not _is_uuid(granted_to):
        raise _deny(action, 400, "invalid_request", "granted_to debe ser el partner_uuid")

    _audit(action, ALLOW, "consent_created")
    consent = Consent(customer_id=customer_id, purpose=purpose, granted_to=granted_to.lower())
    with Session.begin() as session:
        session.add(consent)
    return jsonify(consent.to_dict()), 201


@app.get("/consents")
@scopes.require_scope(scopes.CONSENT_WRITE, action="consent.list")
def list_own_consents():
    customer_id = _owner_customer_id("consent.list")
    query = select(Consent).where(Consent.customer_id == customer_id).order_by(Consent.created_at)
    with Session() as session:
        consents = [c.to_dict() for c in session.scalars(query)]
    _audit("consent.list", ALLOW, "owner")
    return jsonify(consents)


@app.get("/consents/<consent_id>")
@scopes.require_scope(scopes.CONSENT_WRITE, action="consent.read")
def get_consent(consent_id: str):
    with Session() as session:
        consent = _owned_consent(session, consent_id, "consent.read")
    _audit("consent.read", ALLOW, "owner")
    return jsonify(consent.to_dict())


@app.post("/consents/<consent_id>/revoke")
@scopes.require_scope(scopes.CONSENT_WRITE, action="consent.revoke")
def revoke_consent(consent_id: str):
    action = "consent.revoke"
    with Session.begin() as session:
        consent = _owned_consent(session, consent_id, action)
        _audit(action, ALLOW, "consent_revoked" if consent.status == ACTIVE else "already_revoked")
        if consent.status == ACTIVE:  # idempotente: revocar dos veces conserva el primer revoked_at
            consent.status = REVOKED
            consent.revoked_at = datetime.now(UTC)
    return jsonify(consent.to_dict())


@app.get("/consents/check")
@scopes.require_scope(scopes.CONSENT_READ, action="consent.check")
def check_consent():
    action = "consent.check"
    customer_id = request.args.get("customer_id", "")
    purpose = request.args.get("purpose", "")
    partner_uuid = request.args.get("partner_uuid", "").lower()
    if not (customer_id and purpose and partner_uuid):
        raise _deny(action, 400, "invalid_request",
                    "customer_id, purpose y partner_uuid son obligatorios")
    with Session() as session:
        consents = list(session.scalars(select(Consent).where(Consent.customer_id == customer_id)))
    allowed, reason = decide(consents, partner_uuid, purpose)
    _audit(action, ALLOW if allowed else DENY, reason)
    return jsonify({"allowed": allowed, "reason": reason})


@app.get("/consents/active")
@scopes.require_scope(scopes.CONSENT_READ, action="consent.active")
def active_consents():
    action = "consent.active"
    partner_uuid = request.args.get("partner_uuid", "").lower()
    purpose = request.args.get("purpose", "")
    if not (partner_uuid and purpose):
        raise _deny(action, 400, "invalid_request", "partner_uuid y purpose son obligatorios")
    query = (
        select(Consent.customer_id)
        .where(Consent.granted_to == partner_uuid, Consent.purpose == purpose,
               Consent.status == ACTIVE)
        .distinct()
        .order_by(Consent.customer_id)
    )
    with Session() as session:
        customers = list(session.scalars(query))
    _audit(action, ALLOW, "listed")
    return jsonify(customers)
