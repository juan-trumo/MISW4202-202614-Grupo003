"""Hash de secretos de cliente con PBKDF2-SHA256.

Táctica: identificar y autenticar actores (SEG-02, SEG-08). El hash OCULTA el secreto en
auth.db (no se puede recuperar); es distinto del HMAC de SEG-08, que VERIFICA la integridad
de un mensaje con una clave compartida.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 100_000


def hash_secret(secret: str, *, iterations: int = ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, iterations)
    return f"{ALGORITHM}${iterations}${salt.hex()}${digest.hex()}"


def verify_secret(secret: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$")
        if algorithm != ALGORITHM:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", secret.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except ValueError:
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


# Hash señuelo: si el client_id no existe se verifica contra él, con el mismo costo, para no
# revelar por tiempo de respuesta qué client_id están registrados.
DUMMY_HASH = hash_secret("secreto-senuelo-no-valido")
