"""Scopes (§7.2) y decorador @require_scope.

Táctica: autorizar actores (basado en permisos). Cada servicio valida el JWT y los scopes por
sí mismo; partner_uuid y customer_id salen solo de los claims firmados (g.claims), nunca del
body. Todo rechazo de autenticación o autorización se audita como DENY (SEG-02, SEG-08).
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps

from flask import current_app, g, request

from common.audit_client import DENY, audit_event
from common.errors import ApiError
from common.jwt_utils import verify_token

CONSENT_WRITE = "consent:write"
CONSENT_READ = "consent:read"
FINANCE_READ = "finance:read"
POLICY_ISSUE = "policy:issue"
AUDIT_WRITE = "audit:write"

ALL_SCOPES = frozenset({CONSENT_WRITE, CONSENT_READ, FINANCE_READ, POLICY_ISSUE, AUDIT_WRITE})


def bearer_token() -> str:
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise ApiError(401, "invalid_token", "Falta el header Authorization: Bearer <token>")
    return token.strip()


def require_scope(*required: str, action: str, resource: str | None = None) -> Callable:
    """Exige un JWT válido con todos los scopes indicados; deja los claims en g.claims."""

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            claims: dict | None = None
            try:
                public_key = current_app.extensions["solventa"].public_key()
                claims = verify_token(bearer_token(), public_key)
                missing = [s for s in required if s not in claims["scopes"]]
                if missing:
                    detail = f"Faltan scopes: {', '.join(missing)}"
                    raise ApiError(403, "insufficient_scope", detail)
            except ApiError as err:
                # Si auditar falla, audit_event lanza 503 y reemplaza este error (falla cerrada).
                audit_event(
                    action=action,
                    resource=resource or request.path,
                    decision=DENY,
                    reason=err.code,
                    claims=claims,
                )
                raise
            g.claims = claims
            return fn(*args, **kwargs)

        return wrapper

    return decorator
