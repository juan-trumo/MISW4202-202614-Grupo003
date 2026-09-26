"""Fábrica común de apps Flask: correlation-id, errores, logging JSON, /health, JWT y auditoría.

Centraliza las tácticas transversales para que ningún servicio pueda olvidar validar tokens
o auditar (autorizar actores y mantener auditoría; SEG-02, SEG-08).
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass

from flask import Flask, jsonify

from common.audit_client import AuditClient
from common.correlation import configure_logging, init_correlation
from common.errors import ApiError, register_error_handlers
from common.jwt_utils import PublicKeyProvider, ServiceTokenProvider, remote_token_fetcher


@dataclass
class ServiceContext:
    name: str
    public_key: Callable[[], bytes]
    audit: AuditClient | None


def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


def env_json(name: str, default=None):
    raw = os.environ.get(name)
    return json.loads(raw) if raw else default


def experiment_mode() -> bool:
    return os.environ.get("EXPERIMENT_MODE", "0") == "1"


def _no_token_verification() -> bytes:
    raise ApiError(500, "internal_error", "Este servicio no valida tokens")


def _default_service_token() -> ServiceTokenProvider:
    client_id = os.environ.get("SERVICE_CLIENT_ID", "")
    secret = (env_json("SEED_SECRETS", {}) or {}).get(client_id)
    if not client_id or not secret:
        raise RuntimeError("SERVICE_CLIENT_ID sin secreto en SEED_SECRETS: no se puede auditar")
    return ServiceTokenProvider(
        remote_token_fetcher(os.environ.get("AUTH_URL", "http://auth:5001"), client_id, secret)
    )


def create_app(
    service_name: str,
    *,
    verify_tokens: bool = True,
    audit_enabled: bool = True,
    public_key: Callable[[], bytes] | None = None,
    service_token: ServiceTokenProvider | None = None,
) -> Flask:
    configure_logging(service_name, os.environ.get("LOG_LEVEL", "INFO"))
    app = Flask(service_name)
    app.json.ensure_ascii = False

    if not verify_tokens:
        public_key = _no_token_verification
    elif public_key is None:
        provider = PublicKeyProvider(os.environ.get("AUTH_URL", "http://auth:5001"))
        provider.warmup()
        public_key = provider.get

    audit = None
    if audit_enabled:
        audit = AuditClient(
            service_name,
            os.environ.get("AUDIT_URL", "http://audit:5005"),
            service_token or _default_service_token(),
            env_float("AUDIT_TIMEOUT_S", 2.0),
        )

    app.extensions["solventa"] = ServiceContext(service_name, public_key, audit)
    init_correlation(app)
    register_error_handlers(app)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": service_name})

    return app
