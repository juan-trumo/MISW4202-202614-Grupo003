"""auth.db — tabla credential (§9). Solo auth-service la lee y escribe (separar entidades)."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import JSON, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from common.db import make_engine, make_session_factory

ACTIVE = "ACTIVE"
DISABLED = "DISABLED"


class Base(DeclarativeBase):
    pass


class Credential(Base):
    __tablename__ = "credential"

    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    secret_hash: Mapped[str] = mapped_column(String(256))
    actor_type: Mapped[str] = mapped_column(String(16))  # customer | partner | service
    partner_uuid: Mapped[str | None] = mapped_column(String(36), nullable=True)
    customer_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scopes: Mapped[list[str]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default=ACTIVE)


def init_db(data_dir: Path) -> sessionmaker:
    engine = make_engine(Path(data_dir) / "auth.db")
    Base.metadata.create_all(engine)
    return make_session_factory(engine)
