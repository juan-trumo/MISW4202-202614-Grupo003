"""Formato uniforme de errores (§7.5).

Toda respuesta de error es {"error", "detail", "correlation_id"} para que el arnés y la
auditoría puedan correlacionar cada rechazo (táctica: mantener auditoría; SEG-02, SEG-08).
"""

from __future__ import annotations

import logging

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from common.correlation import current_correlation_id

log = logging.getLogger(__name__)

_HTTP_CODES = {
    400: "invalid_request",
    404: "not_found",
    405: "method_not_allowed",
    415: "invalid_request",
}


class ApiError(Exception):
    """Error de negocio o de seguridad con status HTTP y código de §7.5."""

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(f"{status} {code}: {detail}")
        self.status = status
        self.code = code
        self.detail = detail


def error_body(code: str, detail: str) -> dict:
    return {"error": code, "detail": detail, "correlation_id": current_correlation_id()}


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(ApiError)
    def _api_error(err: ApiError):
        return jsonify(error_body(err.code, err.detail)), err.status

    @app.errorhandler(HTTPException)
    def _http_error(err: HTTPException):
        code = _HTTP_CODES.get(err.code or 500, "internal_error")
        return jsonify(error_body(code, err.description or "")), err.code

    @app.errorhandler(Exception)
    def _unexpected(err: Exception):
        log.exception("Error no controlado")
        return jsonify(error_body("internal_error", "Error interno")), 500
