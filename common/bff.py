"""Reenvío de los BFF hacia los servicios internos.

Táctica: limitar exposición. El BFF solo publica las rutas de su canal y reenvía Authorization
y X-Signature sin tocarlos; el cuerpo viaja byte a byte. No valida tokens ni decide nada: cada
servicio interno valida por sí mismo (SEG-02, SEG-08).
"""

from __future__ import annotations

import requests
from flask import Response, request

from common.correlation import outbound_headers
from common.errors import ApiError

FORWARDED_HEADERS = ("Authorization", "X-Signature", "Content-Type")
UPSTREAM_TIMEOUT_S = 10


def forward(base_url: str, path: str) -> Response:
    url = f"{base_url.rstrip('/')}{path}"
    if request.query_string:
        url = f"{url}?{request.query_string.decode('latin-1')}"
    passthrough = {h: request.headers[h] for h in FORWARDED_HEADERS if h in request.headers}
    try:
        upstream = requests.request(
            request.method,
            url,
            data=request.get_data(),
            headers=outbound_headers(extra=passthrough),
            timeout=UPSTREAM_TIMEOUT_S,
        )
    except requests.RequestException:
        raise ApiError(502, "upstream_unavailable", "El servicio interno no respondió") from None
    response = Response(upstream.content, status=upstream.status_code)
    if "Content-Type" in upstream.headers:
        response.headers["Content-Type"] = upstream.headers["Content-Type"]
    return response
