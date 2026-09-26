"""Sesión HTTP que registra cada request del arnés a un servicio protegido.

Base de audit_coverage sobre TODO el tráfico del experimento: cada request a un servicio
protegido lleva su propio X-Correlation-ID y se guarda (cid, servicio destino, status) para
comprobar después que ese servicio dejó al menos un evento en audit-service.
"""

from __future__ import annotations

import threading
import uuid
from urllib.parse import urlparse

import requests

# Rutas de los BFF → servicio protegido que las atiende. Las URLs de observación
# (/policies/count, /events, /stats en 127.0.0.1) no son tráfico de negocio y no se registran.
_BFF_PORTS = {8001, 8002}
_ROUTES = (
    ("/auth/token", "auth-service"),
    ("/consents", "consent-service"),
    ("/quotes", "quote-service"),
    ("/policies", "policy-service"),
)


def target_service(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.port not in _BFF_PORTS:
        return None
    for prefix, service in _ROUTES:
        if parsed.path.startswith(prefix):
            return service
    return None


class RecordingSession(requests.Session):
    def __init__(self, prefix: str = "exp") -> None:
        super().__init__()
        self.prefix = prefix
        self.records: list[dict] = []
        self._lock = threading.Lock()

    def request(self, method, url, *args, headers=None, **kwargs):
        service = target_service(url)
        headers = dict(headers or {})
        if service:
            headers.setdefault("X-Correlation-ID", f"{self.prefix}-{uuid.uuid4()}")
        resp = super().request(method, url, *args, headers=headers, **kwargs)
        if service:
            with self._lock:
                self.records.append({
                    "correlation_id": headers["X-Correlation-ID"],
                    "service": service,
                    "method": method.upper(),
                    "path": urlparse(url).path,
                    "status": resp.status_code,
                })
        return resp
