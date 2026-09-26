"""X-Correlation-ID y logging JSON (§7.4).

Táctica: mantener auditoría. El correlation_id permite emparejar cada request con su evento
de auditoría y medir audit_coverage (SEG-02, SEG-08).
"""

from __future__ import annotations

import json
import logging
import re
import sys
import uuid
from datetime import UTC, datetime

from flask import Flask, g, has_request_context, request

HEADER = "X-Correlation-ID"
# Solo caracteres seguros: evita inyección en logs con un ID manipulado por el cliente.
_VALID_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def current_correlation_id() -> str | None:
    if has_request_context():
        return getattr(g, "correlation_id", None)
    return None


def init_correlation(app: Flask) -> None:
    @app.before_request
    def _assign_correlation_id() -> None:
        incoming = request.headers.get(HEADER, "").strip()
        g.correlation_id = incoming if _VALID_ID.match(incoming) else str(uuid.uuid4())

    @app.after_request
    def _echo_correlation_id(response):
        cid = current_correlation_id()
        if cid:
            response.headers[HEADER] = cid
        return response


def outbound_headers(token: str | None = None, extra: dict | None = None) -> dict:
    """Headers para llamadas entre servicios: propaga el correlation_id y el Bearer."""
    headers: dict[str, str] = {}
    cid = current_correlation_id()
    if cid:
        headers[HEADER] = cid
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra:
        headers.update(extra)
    return headers


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "msg": record.getMessage(),
            "correlation_id": current_correlation_id(),
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False)


def configure_logging(service: str, level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
