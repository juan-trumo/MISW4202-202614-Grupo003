"""audit-service :5005 — Solventa, experimento de seguridad.

Tácticas: mantener auditoría (registro append-only, sin UPDATE ni DELETE, bloqueado también por
triggers en la BD); autorizar actores (solo tokens con audit:write registran eventos).
ASR: SEG-02, SEG-08.

No se audita a sí mismo (audit_enabled=False) para evitar recursión. /events (GET) y /stats
solo existen con EXPERIMENT_MODE=1: son la fuente de audit_coverage del arnés.
"""

import os
from datetime import datetime
from pathlib import Path

from flask import g, jsonify, request
from sqlalchemy import case, func, select

from common import scopes
from common.app_base import create_app, experiment_mode
from common.audit_client import ALLOW, DENY
from common.errors import ApiError

from models import AuditEvent, init_db

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
REQUIRED_FIELDS = ("ts", "service", "actor", "action", "resource", "decision", "reason")
OPTIONAL_FIELDS = ("correlation_id", "actor_type", "partner_uuid")
MAX_FIELD_LEN = 256
MAX_LIST = 10_000

Session = init_db(DATA_DIR)
app = create_app("audit-service", audit_enabled=False)


def _validated_event(body) -> dict:
    if not isinstance(body, dict):
        raise ApiError(400, "invalid_request", "Se espera un objeto JSON")
    unknown = sorted(set(body) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS))
    if unknown:
        raise ApiError(400, "unknown_field", f"Campos no permitidos: {', '.join(unknown)}")
    event = {}
    for field in REQUIRED_FIELDS + OPTIONAL_FIELDS:
        value = body.get(field)
        if value is None:
            if field in REQUIRED_FIELDS:
                raise ApiError(400, "invalid_request", f"Falta el campo {field}")
            event[field] = None
            continue
        if not isinstance(value, str) or len(value) > MAX_FIELD_LEN:
            raise ApiError(400, "invalid_request", f"{field} debe ser texto de hasta 256")
        event[field] = value
    if event["decision"] not in (ALLOW, DENY):
        raise ApiError(400, "invalid_request", "decision debe ser ALLOW o DENY")
    try:
        datetime.fromisoformat(event["ts"])
    except ValueError:
        raise ApiError(400, "invalid_request", "ts debe ser ISO-8601") from None
    return event


def _require_experiment_mode() -> None:
    if not experiment_mode():
        raise ApiError(404, "not_found", "Disponible solo con EXPERIMENT_MODE=1")


@app.post("/events")
@scopes.require_scope(scopes.AUDIT_WRITE, action="audit.write")
def create_event():
    event = AuditEvent(**_validated_event(request.get_json(silent=True)),
                       submitted_by=g.claims["sub"])
    with Session.begin() as session:
        session.add(event)
        session.flush()
        event_id = event.id
    return jsonify({"id": event_id}), 201


@app.get("/events")
def list_events():
    _require_experiment_mode()
    query = select(AuditEvent).order_by(AuditEvent.id).limit(MAX_LIST)
    correlation_id = request.args.get("correlation_id")
    if correlation_id:
        query = query.where(AuditEvent.correlation_id == correlation_id)
    with Session() as session:
        return jsonify([e.to_dict() for e in session.scalars(query)])


@app.get("/stats")
def stats():
    _require_experiment_mode()
    allow = func.sum(case((AuditEvent.decision == ALLOW, 1), else_=0))
    deny = func.sum(case((AuditEvent.decision == DENY, 1), else_=0))
    query = select(AuditEvent.service, func.count(), allow, deny).group_by(AuditEvent.service)
    with Session() as session:
        rows = session.execute(query).all()
    by_service = {svc: {"total": t, "allow": a or 0, "deny": d or 0} for svc, t, a, d in rows}
    return jsonify({
        "total": sum(v["total"] for v in by_service.values()),
        "allow": sum(v["allow"] for v in by_service.values()),
        "deny": sum(v["deny"] for v in by_service.values()),
        "by_service": by_service,
    })
