import time

import jwt
import pytest

from common.errors import ApiError
from common.jwt_utils import AUDIENCE, ISSUER, ServiceTokenProvider, issue_token, verify_token


def test_token_valido_tiene_claims_obligatorios(keys, make_token):
    _, public = keys
    claims = verify_token(make_token(partner_uuid="P-A"), public)
    assert claims["iss"] == ISSUER and claims["aud"] == AUDIENCE
    assert claims["scopes"] == ["finance:read"]
    assert claims["partner_uuid"] == "P-A"
    assert claims["exp"] - claims["iat"] == 60
    assert claims["jti"]


def test_token_expirado_da_token_expired(keys):
    private, public = keys
    token = issue_token(
        private, sub="x", actor_type="partner", scopes=[], ttl=10, now=time.time() - 60
    )
    with pytest.raises(ApiError) as err:
        verify_token(token, public)
    assert (err.value.status, err.value.code) == (401, "token_expired")


def test_firma_alterada_da_invalid_token(keys, make_token):
    _, public = keys
    header, payload, signature = make_token().split(".")
    tampered = f"{header}.{payload}.{signature[:-4]}AAAA"
    with pytest.raises(ApiError) as err:
        verify_token(tampered, public)
    assert err.value.code == "invalid_token"


def test_otra_audiencia_da_invalid_token(keys):
    private, public = keys
    now = int(time.time())
    token = jwt.encode(
        {"iss": ISSUER, "aud": "otra", "sub": "x", "actor_type": "partner", "scopes": [],
         "iat": now, "exp": now + 60, "jti": "1"},
        private, algorithm="RS256",
    )
    with pytest.raises(ApiError) as err:
        verify_token(token, public)
    assert err.value.code == "invalid_token"


def test_hs256_con_clave_publica_se_rechaza(keys):
    """Ataque de confusión de algoritmo: firmar con HS256 usando la clave pública como secreto."""
    _, public = keys
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "actor_type": "partner",
              "scopes": ["policy:issue"], "iat": now, "exp": now + 60, "jti": "1"}
    try:
        forged = jwt.encode(claims, public, algorithm="HS256")
    except jwt.InvalidKeyError:
        return  # PyJWT ya se niega a usar un PEM como secreto HMAC
    with pytest.raises(ApiError):
        verify_token(forged, public)


def test_service_token_provider_cachea_y_renueva():
    calls = []

    def fetch():
        calls.append(1)
        return f"t{len(calls)}", 60

    provider = ServiceTokenProvider(fetch)
    assert provider.get() == "t1"
    assert provider.get() == "t1"
    provider.invalidate()
    assert provider.get() == "t2"
    assert len(calls) == 2
