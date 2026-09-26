import pytest
from flask import g, jsonify

from common import scopes
from common.app_base import create_app
from common.jwt_utils import (
    ServiceTokenProvider,
    issue_token,
    load_or_create_private_key,
    public_pem_from_private,
)
from common.testing import FakeAudit


@pytest.fixture(scope="session")
def keys(tmp_path_factory):
    private = load_or_create_private_key(tmp_path_factory.mktemp("keys") / "private.pem")
    return private, public_pem_from_private(private)


@pytest.fixture
def make_token(keys):
    private, _ = keys

    def _make(scopes_=("finance:read",), ttl=60, **kw):
        kw.setdefault("sub", "socio-a")
        kw.setdefault("actor_type", "partner")
        return issue_token(private, scopes=list(scopes_), ttl=ttl, **kw)

    return _make


@pytest.fixture
def protected_app(keys):
    """App mínima con una ruta protegida, para probar require_scope y la falla cerrada."""
    _, public = keys
    app = create_app(
        "test-service",
        public_key=lambda: public,
        service_token=ServiceTokenProvider(lambda: ("unused", 60)),
    )
    fake = FakeAudit()
    app.extensions["solventa"].audit = fake

    @app.post("/protected")
    @scopes.require_scope(scopes.FINANCE_READ, action="quote.create")
    def protected():
        return jsonify({"sub": g.claims["sub"]})

    app.testing = True
    return app, fake
