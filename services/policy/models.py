"""policy.db — tabla policy (§9). Solo policy-service la escribe (separar entidades).

Una fila solo existe si su payload pasó la verificación HMAC: integrity_verified es siempre
True y sirve para calcular integrity_validation_rate (SEG-08).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from common.db import make_engine, make_session_factory


class Base(DeclarativeBase):
    pass


class Policy(Base):
    __tablename__ = "policy"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    partner_uuid: Mapped[str] = mapped_column(String(36), index=True)
    quote_id: Mapped[str] = mapped_column(String(64))
    holder_id: Mapped[str] = mapped_column(String(64))
    holder_name: Mapped[str] = mapped_column(String(128))
    premium: Mapped[str] = mapped_column(String(32))
    coverage: Mapped[str] = mapped_column(String(128))
    currency: Mapped[str] = mapped_column(String(3))
    issued_at: Mapped[str] = mapped_column(String(40))
    nonce: Mapped[str] = mapped_column(String(36), unique=True)
    signature: Mapped[str] = mapped_column(String(64))
    integrity_verified: Mapped[bool] = mapped_column(Boolean)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


def init_db(data_dir: Path) -> sessionmaker:
    engine = make_engine(Path(data_dir) / "policy.db")
    Base.metadata.create_all(engine)
    return make_session_factory(engine)
