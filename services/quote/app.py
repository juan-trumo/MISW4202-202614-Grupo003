"""quote-service :5003 — Solventa, experimento de seguridad.

Tácticas: autorizar actores (finance:read; partner_uuid solo del claim firmado); revocar acceso
(respeta REVOKED según CONSENT_MODE claim | lookup y CONSENT_CACHE_TTL, el punto de
sensibilidad de SEG-02); mantener auditoría con falla cerrada. ASR: SEG-02.

Parte 1: solo /health. POST /quotes llega en la Parte 3.
"""

from common.app_base import create_app

app = create_app("quote-service")
