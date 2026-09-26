"""consent.db — tabla consent (§9). Solo consent-service la escribe (separar entidades)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from common.db import make_engine, make_session_factory

ACTIVE = "ACTIVE"
REVOKED = "REVOKED"


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    # SQLite no guarda la zona horaria: todo se escribe en UTC, así que se restituye al leer.
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=UTC)).isoformat()


class Base(DeclarativeBase):
    pass


class Consent(Base):
    __tablename__ = "consent"
    __table_args__ = (Index("ix_consent_lookup", "customer_id", "granted_to", "purpose"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    customer_id: Mapped[str] = mapped_column(String(64))
    purpose: Mapped[str] = mapped_column(String(64))
    granted_to: Mapped[str] = mapped_column(String(36))  # partner_uuid
    status: Mapped[str] = mapped_column(String(16), default=ACTIVE)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "customer_id": self.customer_id,
            "purpose": self.purpose,
            "granted_to": self.granted_to,
            "status": self.status,
            "created_at": _iso(self.created_at),
            "revoked_at": _iso(self.revoked_at),
        }


def init_db(data_dir: Path) -> sessionmaker:
    engine = make_engine(Path(data_dir) / "consent.db")
    Base.metadata.create_all(engine)
    return make_session_factory(engine)
