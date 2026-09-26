"""Seed de credenciales de desarrollo (§9). Datos ficticios; secretos desde SEED_SECRETS.

Cada actor recibe solo los scopes que necesita (táctica: autorizar actores con mínimo
privilegio; SEG-02, SEG-08). Se ejecuta en cada arranque y es idempotente: si cambian los
secretos del .env, se actualizan los hashes.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import sessionmaker

from common import scopes as s

from models import ACTIVE, Credential
from passwords import hash_secret

log = logging.getLogger(__name__)

CUSTOMER_COUNT = 5


def seed_definitions(partner_a_uuid: str, partner_b_uuid: str) -> list[dict]:
    customers = [
        {
            "client_id": f"cliente-{i:03d}",
            "actor_type": "customer",
            "customer_id": f"C-{i:03d}",
            "scopes": [s.CONSENT_WRITE],
        }
        for i in range(1, CUSTOMER_COUNT + 1)
    ]
    partners = [
        {
            "client_id": client_id,
            "actor_type": "partner",
            "partner_uuid": partner_uuid,
            "scopes": [s.FINANCE_READ, s.POLICY_ISSUE],
        }
        for client_id, partner_uuid in (("socio-a", partner_a_uuid), ("socio-b", partner_b_uuid))
    ]
    services = [
        {"client_id": "svc-quote", "actor_type": "service",
         "scopes": [s.CONSENT_READ, s.AUDIT_WRITE]},
        {"client_id": "svc-consent", "actor_type": "service", "scopes": [s.AUDIT_WRITE]},
        {"client_id": "svc-policy", "actor_type": "service", "scopes": [s.AUDIT_WRITE]},
        {"client_id": "svc-auth", "actor_type": "service",
         "scopes": [s.AUDIT_WRITE, s.CONSENT_READ]},
    ]
    return customers + partners + services


def seed_credentials(
    session_factory: sessionmaker, secrets: dict, partner_a_uuid: str, partner_b_uuid: str
) -> int:
    seeded = 0
    with session_factory.begin() as session:
        for definition in seed_definitions(partner_a_uuid, partner_b_uuid):
            client_id = definition["client_id"]
            secret = secrets.get(client_id)
            if not secret:
                log.warning("Sin secreto en SEED_SECRETS para %s; no se crea", client_id)
                continue
            row = session.get(Credential, client_id) or Credential(client_id=client_id)
            row.secret_hash = hash_secret(secret)
            row.actor_type = definition["actor_type"]
            row.partner_uuid = definition.get("partner_uuid")
            row.customer_id = definition.get("customer_id")
            row.scopes = sorted(definition["scopes"])
            row.status = ACTIVE
            session.add(row)
            seeded += 1
    log.info("Seed de credenciales aplicado: %d", seeded)
    return seeded
