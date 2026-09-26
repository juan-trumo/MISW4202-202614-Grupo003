"""audit.db — tabla audit_event (§7.4, §9), append-only.

Táctica: mantener auditoría. Además de no exponer UPDATE ni DELETE por API, dos triggers de
SQLite abortan cualquier UPDATE o DELETE sobre la tabla (SEG-02, SEG-08).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from common.db import make_engine, make_session_factory


class Base(DeclarativeBase):
    pass


class AuditEvent(Base):
    __tablename__ = "audit_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(40))
    correlation_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    service: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(64))
    actor_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    partner_uuid: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action: Mapped[str] = mapped_column(String(64))
    resource: Mapped[str] = mapped_column(String(256))
    decision: Mapped[str] = mapped_column(String(8))
    reason: Mapped[str] = mapped_column(String(64))
    # Quién escribió el evento según su token (sub): evita que un servicio registre a nombre de otro
    # sin dejar rastro.
    submitted_by: Mapped[str] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts,
            "correlation_id": self.correlation_id,
            "service": self.service,
            "actor": self.actor,
            "actor_type": self.actor_type,
            "partner_uuid": self.partner_uuid,
            "action": self.action,
            "resource": self.resource,
            "decision": self.decision,
            "reason": self.reason,
            "submitted_by": self.submitted_by,
        }


_APPEND_ONLY_TRIGGERS = (
    "CREATE TRIGGER IF NOT EXISTS audit_event_no_update BEFORE UPDATE ON audit_event "
    "BEGIN SELECT RAISE(ABORT, 'audit_event es append-only'); END;",
    "CREATE TRIGGER IF NOT EXISTS audit_event_no_delete BEFORE DELETE ON audit_event "
    "BEGIN SELECT RAISE(ABORT, 'audit_event es append-only'); END;",
)


def init_db(data_dir: Path) -> sessionmaker:
    engine = make_engine(Path(data_dir) / "audit.db")
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        for ddl in _APPEND_ONLY_TRIGGERS:
            conn.exec_driver_sql(ddl)
    return make_session_factory(engine)
