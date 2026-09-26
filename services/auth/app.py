"""auth-service :5001 — Solventa, experimento de seguridad.

Tácticas: identificar y autenticar actores (client_id + secreto con hash PBKDF2); intercambio
de tokens (credencial externa → JWT RS256 interno de vida corta con scopes mínimos); mantener
auditoría (cada emisión o rechazo queda registrado, con falla cerrada). ASR: SEG-02, SEG-08.

En CONSENT_MODE=claim incrusta en el token de socio los consentimientos activos (claim
`consents`); ese es el lado "claim" del punto de sensibilidad de SEG-02.
"""

import os
from pathlib import Path

import requests
from flask import Response, jsonify, request

from common import scopes
from common.app_base import create_app, env_int, env_json, experiment_mode
from common.audit_client import ALLOW, DENY, audit_event
from common.correlation import outbound_headers
from common.errors import ApiError
from common.jwt_utils import (
    ServiceTokenProvider,
    issue_token,
    load_or_create_private_key,
    public_pem_from_private,
)

from models import ACTIVE, Credential, init_db
from passwords import DUMMY_HASH, verify_secret
from seed import seed_credentials

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
TOKEN_TTL = env_int("TOKEN_TTL", 300)
CONSENT_MODE = os.environ.get("CONSENT_MODE", "lookup")
CONSENT_URL = os.environ.get("CONSENT_URL", "http://consent:5002")
PURPOSE_QUOTATION = "quotation"
ACTION = "auth.token"
RESOURCE = "/token"

# La clave privada solo existe aquí; se genera al primer arranque y persiste en el volumen.
PRIVATE_PEM = load_or_create_private_key(DATA_DIR / "keys" / "private.pem")
PUBLIC_PEM = public_pem_from_private(PRIVATE_PEM)

Session = init_db(DATA_DIR)
seed_credentials(
    Session,
    env_json("SEED_SECRETS", {}),
    os.environ.get("PARTNER_A_UUID", ""),
    os.environ.get("PARTNER_B_UUID", ""),
)


def _own_service_token() -> tuple[str, int]:
    # auth-service firma su propio token de servicio: no se lo pide a sí mismo por HTTP.
    token = issue_token(
        PRIVATE_PEM,
        sub="svc-auth",
        actor_type="service",
        scopes=[scopes.AUDIT_WRITE, scopes.CONSENT_READ],
        ttl=TOKEN_TTL,
    )
    return token, TOKEN_TTL


SERVICE_TOKEN = ServiceTokenProvider(_own_service_token)
app = create_app("auth-service", public_key=lambda: PUBLIC_PEM, service_token=SERVICE_TOKEN)


def _deny(status: int, code: str, detail: str, **actor) -> ApiError:
    """Audita el rechazo (falla cerrada) y devuelve el error para lanzarlo."""
    audit_event(action=ACTION, resource=RESOURCE, decision=DENY, reason=code, **actor)
    return ApiError(status, code, detail)


def _requested_ttl(body: dict, actor: dict) -> int:
    # `ttl` solo existe para TC-AU-03 (token expirado sin esperar TOKEN_TTL) y solo en
    # EXPERIMENT_MODE; nunca puede alargar la vida del token por encima de TOKEN_TTL.
    if not experiment_mode() or "ttl" not in body:
        return TOKEN_TTL
    ttl = body["ttl"]
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= TOKEN_TTL:
        detail = f"ttl debe ser un entero entre 1 y {TOKEN_TTL}"
        raise _deny(400, "invalid_request", detail, **actor)
    return ttl


def _active_consents(partner_uuid: str) -> list[str]:
    """Modo claim: clientes con consentimiento ACTIVE para este socio y propósito."""
    try:
        resp = requests.get(
            f"{CONSENT_URL}/consents/active",
            params={"partner_uuid": partner_uuid, "purpose": PURPOSE_QUOTATION},
            headers=outbound_headers(SERVICE_TOKEN.get()),
            timeout=2,
        )
    except requests.RequestException:
        resp = None
    if resp is None or resp.status_code != 200:
        raise ApiError(503, "consent_unavailable", "No se pudieron leer los consentimientos")
    data = resp.json()
    if not isinstance(data, list) or not all(isinstance(c, str) for c in data):
        raise ApiError(503, "consent_unavailable", "Respuesta inválida de consent-service")
    return data


@app.get("/keys/public")
def public_key():
    return Response(PUBLIC_PEM, mimetype="application/x-pem-file")


@app.post("/token")
def token():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise _deny(400, "invalid_request", "Se espera JSON {client_id, client_secret}")
    client_id, secret = body.get("client_id"), body.get("client_secret")
    if not (isinstance(client_id, str) and client_id and isinstance(secret, str) and secret):
        raise _deny(400, "invalid_request", "client_id y client_secret son obligatorios")
    attempted = {"actor": client_id[:64]}
    ttl = _requested_ttl(body, attempted)

    with Session() as session:
        cred = session.get(Credential, client_id)
    secret_ok = verify_secret(secret, cred.secret_hash if cred else DUMMY_HASH)
    if cred is None or not secret_ok or cred.status != ACTIVE:
        raise _deny(401, "invalid_credentials", "Credenciales inválidas", **attempted)

    actor = {
        "actor": cred.client_id,
        "actor_type": cred.actor_type,
        "partner_uuid": cred.partner_uuid,
    }
    consents = None
    if CONSENT_MODE == "claim" and cred.actor_type == "partner":
        try:
            consents = _active_consents(cred.partner_uuid)
        except ApiError as err:
            raise _deny(err.status, err.code, err.detail, **actor) from None

    audit_event(action=ACTION, resource=RESOURCE, decision=ALLOW, reason="token_issued", **actor)
    access_token = issue_token(
        PRIVATE_PEM,
        sub=cred.client_id,
        actor_type=cred.actor_type,
        scopes=cred.scopes,
        ttl=ttl,
        partner_uuid=cred.partner_uuid,
        customer_id=cred.customer_id,
        consents=consents,
    )
    return jsonify({"access_token": access_token, "token_type": "Bearer", "expires_in": ttl})
