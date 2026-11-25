"""
Modelo ORM de Auditoría de Eventos de Seguridad (`AuditLog`) y catálogo de eventos (`AuditEventType`).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, DateTime, ForeignKey, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class AuditEventType(str, Enum):
    """Catálogo estandarizado de eventos críticos de seguridad y auditoría."""

    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    TOKEN_REFRESH = "TOKEN_REFRESH"
    TOKEN_REUSE_DETECTED = "TOKEN_REUSE_DETECTED"
    REGISTER = "REGISTER"
    EMAIL_VERIFIED = "EMAIL_VERIFIED"
    PASSWORD_RESET_REQUEST = "PASSWORD_RESET_REQUEST"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    PROFILE_UPDATED = "PROFILE_UPDATED"
    ADMIN_ACTION = "ADMIN_ACTION"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_DELETED = "ACCOUNT_DELETED"


class AuditLog(Base):
    """
    Registro inmutable de eventos de seguridad y operaciones críticas.
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(50),
        index=True,
        nullable=False,
    )
    ip_address: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        default="0.0.0.0",
        index=True,
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )
    details: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        index=True,
        nullable=False,
    )

    user: Mapped["User | None"] = relationship(
        "User",
        back_populates="audit_logs",
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} event_type={self.event_type!r} "
            f"user_id={self.user_id} ip={self.ip_address!r}>"
        )
