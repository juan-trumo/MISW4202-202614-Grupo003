"""policy-service :5004 — Solventa, experimento de seguridad.

Tácticas: verificar integridad del mensaje (HMAC-SHA256 sobre el payload canónico antes del
INSERT); autorizar actores (policy:issue; partner_uuid del body debe igualar al del token);
separar entidades (único dueño de policy.db); mantener auditoría con falla cerrada. ASR: SEG-08.

Parte 1: solo /health. POST /policies y /policies/count llegan en la Parte 4.
"""

from common.app_base import create_app

app = create_app("policy-service")
