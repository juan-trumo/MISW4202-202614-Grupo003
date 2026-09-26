"""Tokens internos JWT RS256 (§7.1).

Tácticas: intercambio de tokens (credencial externa → JWT interno de vida corta) y autorizar
actores. Solo auth-service tiene la clave privada; cada servicio valida el token por sí mismo
con la clave pública y no confía en el BFF (SEG-02, SEG-08).
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from common.errors import ApiError

ISSUER = "solventa-auth"
AUDIENCE = "solventa-internal"
ALGORITHM = "RS256"
REQUIRED_CLAIMS = ["iss", "aud", "sub", "iat", "exp", "jti", "scopes", "actor_type"]

log = logging.getLogger(__name__)


def load_or_create_private_key(path: Path) -> bytes:
    """Carga la clave privada de auth-service o la genera la primera vez (volumen persistente)."""
    path = Path(path)
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(pem)
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return pem


def public_pem_from_private(private_pem: bytes) -> bytes:
    key = serialization.load_pem_private_key(private_pem, password=None)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def issue_token(
    private_pem: bytes,
    *,
    sub: str,
    actor_type: str,
    scopes: list[str],
    ttl: int,
    partner_uuid: str | None = None,
    customer_id: str | None = None,
    consents: list[str] | None = None,
    now: float | None = None,
) -> str:
    iat = int(now if now is not None else time.time())
    claims: dict = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": sub,
        "actor_type": actor_type,
        "scopes": sorted(set(scopes)),
        "iat": iat,
        "exp": iat + int(ttl),
        "jti": str(uuid.uuid4()),
    }
    if partner_uuid:
        claims["partner_uuid"] = partner_uuid
    if customer_id:
        claims["customer_id"] = customer_id
    if consents is not None:
        claims["consents"] = list(consents)
    return jwt.encode(claims, private_pem, algorithm=ALGORITHM)


def verify_token(token: str, public_pem: bytes) -> dict:
    """Valida firma, exp, iss y aud con leeway 0. Lanza 401 token_expired o invalid_token."""
    try:
        claims = jwt.decode(
            token,
            public_pem,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            leeway=0,
            options={"require": REQUIRED_CLAIMS},
        )
    except jwt.ExpiredSignatureError:
        raise ApiError(401, "token_expired", "El token expiró") from None
    except jwt.PyJWTError as exc:
        raise ApiError(401, "invalid_token", f"Token inválido: {type(exc).__name__}") from None
    if not isinstance(claims.get("scopes"), list):
        raise ApiError(401, "invalid_token", "El claim scopes debe ser una lista")
    return claims


class PublicKeyProvider:
    """Descarga y cachea la clave pública de auth-service (GET /keys/public) con reintentos."""

    def __init__(self, auth_url: str, *, attempts: int = 3, delay_s: float = 1.0) -> None:
        self.auth_url = auth_url.rstrip("/")
        self.attempts = attempts
        self.delay_s = delay_s
        self._pem: bytes | None = None
        self._lock = threading.Lock()

    def get(self) -> bytes:
        if self._pem:
            return self._pem
        with self._lock:
            if not self._pem:
                self._pem = self._fetch(self.attempts)
            return self._pem

    def warmup(self, attempts: int = 60) -> None:
        """Descarga la clave al arrancar, en segundo plano, sin bloquear el arranque."""

        def _run() -> None:
            try:
                pem = self._fetch(attempts)
            except ApiError:
                log.warning("Sin clave pública al arrancar; se reintentará bajo demanda")
                return
            with self._lock:
                self._pem = self._pem or pem
            log.info("Clave pública de auth-service cargada")

        threading.Thread(target=_run, name="jwt-key-warmup", daemon=True).start()

    def _fetch(self, attempts: int) -> bytes:
        for attempt in range(1, attempts + 1):
            try:
                resp = requests.get(f"{self.auth_url}/keys/public", timeout=2)
                if resp.status_code == 200 and b"BEGIN PUBLIC KEY" in resp.content:
                    return resp.content
            except requests.RequestException:
                pass
            if attempt < attempts:
                time.sleep(self.delay_s)
        raise ApiError(503, "auth_unavailable", "No se obtuvo la clave pública de auth-service")


class ServiceTokenProvider:
    """Cachea el token de servicio y lo renueva antes de que expire."""

    def __init__(self, fetch: Callable[[], tuple[str, int]], margin_s: float = 10.0) -> None:
        self._fetch = fetch
        self._margin_s = margin_s
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.Lock()

    def get(self) -> str:
        with self._lock:
            if self._token and time.monotonic() < self._expires_at:
                return self._token
            token, expires_in = self._fetch()
            margin = min(self._margin_s, expires_in / 2)
            self._token = token
            self._expires_at = time.monotonic() + expires_in - margin
            return token

    def invalidate(self) -> None:
        with self._lock:
            self._token = None
            self._expires_at = 0.0


def remote_token_fetcher(
    auth_url: str, client_id: str, client_secret: str
) -> Callable[[], tuple[str, int]]:
    """Intercambio de credencial de servicio por token interno en auth-service (POST /token)."""

    def _fetch() -> tuple[str, int]:
        resp = requests.post(
            f"{auth_url.rstrip('/')}/token",
            json={"client_id": client_id, "client_secret": client_secret},
            timeout=2,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["access_token"], int(data["expires_in"])

    return _fetch
