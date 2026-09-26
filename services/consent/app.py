"""consent-service :5002 — Solventa, experimento de seguridad.

Tácticas: separar entidades (único dueño y escritor de consent.db); revocar acceso (ACTIVE →
REVOKED); autorizar actores (consent:write para el cliente dueño, consent:read para servicios);
mantener auditoría. ASR: SEG-02.

Parte 1: solo /health. Los endpoints de consentimiento llegan en la Parte 3.
"""

from common.app_base import create_app

app = create_app("consent-service")
