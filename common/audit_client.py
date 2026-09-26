"""Cliente de auditoría con falla cerrada (§7.4).

Táctica: mantener auditoría. Si POST /events falla o tarda más de AUDIT_TIMEOUT_S, se lanza
503 audit_unavailable y la operación protegida no se ejecuta (SEG-02, SEG-08). Trade-off
declarado: se sacrifica disponibilidad para no tener accesos sin auditar.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import requests
from flask import current_app

from common.correlation import current_correlation_id, outbound_headers
from common.errors import ApiError
from common.jwt_utils import ServiceTokenProvider

log = logging.getLogger(__name__)

ALLOW = "ALLOW"
DENY = "DENY"


def _unavailable(detail: str) -> ApiError:
    return ApiError(503, "audit_unavailable", detail)


class AuditClient:
    def __init__(
        self,
        service: str,
        base_url: str,
        token_provider: ServiceTokenProvider,
        timeout_s: float = 2.0,
    ) -> None:
        self.service = service
        self.base_url = base_url.rstrip("/")
        self.token_provider = token_provider
        self.timeout_s = timeout_s

    def build_event(
        self,
        *,
        action: str,
        resource: str,
        decision: str,
        reason: str,
        claims: dict | None = None,
        actor: str | None = None,
        actor_type: str | None = None,
        partner_uuid: str | None = None,
    ) -> dict:
        claims = claims or {}
        return {
            "ts": datetime.now(UTC).isoformat(),
            "correlation_id": current_correlation_id(),
            "service": self.service,
            "actor": actor or claims.get("sub") or "anonymous",
            "actor_type": actor_type or claims.get("actor_type"),
            "partner_uuid": partner_uuid or claims.get("partner_uuid"),
            "action": action,
            "resource": resource,
            "decision": decision,
            "reason": reason,
        }

    def record(self, **fields) -> None:
        """Registra el evento o lanza 503 audit_unavailable (falla cerrada)."""
        event = self.build_event(**fields)
        for attempt in (1, 2):
            try:
                token = self.token_provider.get()
            except Exception as exc:  # cualquier fallo obteniendo el token = no se puede auditar
                log.error("No se obtuvo token de servicio para auditar: %s", exc)
                raise _unavailable("No se pudo autenticar ante audit-service") from None
            try:
                resp = requests.post(
                    f"{self.base_url}/events",
                    json=event,
                    headers=outbound_headers(token),
                    timeout=self.timeout_s,
                )
            except requests.RequestException as exc:
                log.error("audit-service no respondió: %s", exc)
                raise _unavailable("audit-service no respondió") from None
            if resp.status_code == 201:
                return
            if resp.status_code == 401 and attempt == 1:
                # Token de servicio vencido o rechazado: se renueva una vez y se reintenta.
                self.token_provider.invalidate()
                continue
            log.error("audit-service respondió %s", resp.status_code)
            raise _unavailable(f"audit-service respondió {resp.status_code}")


def audit_event(**fields) -> None:
    """Audita desde un request usando el cliente del servicio actual (no-op si no audita)."""
    client: AuditClient | None = current_app.extensions["solventa"].audit
    if client is not None:
        client.record(**fields)
