"""Payload canónico y HMAC-SHA256 de la emisión de pólizas (§7.3).

Táctica: verificar integridad del mensaje (SEG-08). Limitación declarada: HMAC con clave
compartida por socio da integridad y autenticidad, no no-repudio.
"""

from __future__ import annotations

import hashlib
import hmac
import json

SIGNATURE_HEADER = "X-Signature"

ALLOWED_FIELDS = frozenset(
    {
        "partner_uuid",
        "quote_id",
        "holder_id",
        "holder_name",
        "premium",
        "coverage",
        "currency",
        "issued_at",
        "nonce",
    }
)


def unknown_fields(payload: dict) -> list[str]:
    return sorted(set(payload) - ALLOWED_FIELDS)


def missing_fields(payload: dict) -> list[str]:
    return sorted(ALLOWED_FIELDS - set(payload))


def canonicalize(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _key_bytes(key: str | bytes) -> bytes:
    return key if isinstance(key, bytes) else key.encode("utf-8")


def compute_hmac(key: str | bytes, canonical: bytes) -> str:
    return hmac.new(_key_bytes(key), canonical, hashlib.sha256).hexdigest()


def sign_payload(key: str | bytes, payload: dict) -> str:
    return compute_hmac(key, canonicalize(payload))


def verify_signature(key: str | bytes, payload: dict, signature: str | None) -> bool:
    """Compara en tiempo constante la firma recibida con la calculada sobre el payload canónico."""
    if not signature:
        return False
    try:
        received = signature.strip().lower().encode("ascii")
    except UnicodeEncodeError:
        return False
    expected = sign_payload(key, payload).encode("ascii")
    return hmac.compare_digest(expected, received)


def load_partner_keys(raw: str | None) -> dict[str, bytes]:
    """PARTNER_HMAC_KEYS = JSON {partner_uuid: key}. Valores de desarrollo, nunca claves reales."""
    if not raw:
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("PARTNER_HMAC_KEYS debe ser un objeto JSON {partner_uuid: key}")
    return {str(k): _key_bytes(v) for k, v in data.items()}
