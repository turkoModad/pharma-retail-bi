"""
Modelos ORM para la gestión de sesiones y tokens temporales:
- `RefreshToken`: Rotación estricta de Refresh Tokens con detección de robo por familia (`family_id`).
- `OneTimeToken` y `OneTimeTokenType`: Tokens de un solo uso hasheados con SHA-256 y expiración de 15 minutos.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Uuid, false, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base

if TYPE_CHECKING:
    from app.models.user import User


class OneTimeTokenType(str, Enum):
    """Tipos de token de un solo uso soportados por el sistema."""

    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"


class RefreshToken(Base):
    """
    Registro de Refresh Token (expiración 7 días) con soporte para rotación estricta
    e invalidación en cascada de toda la familia (`family_id`) ante detección de reúso.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    family_id: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )
    replaced_by_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    ip_address: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    user_agent: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=false(),
        index=True,
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="refresh_tokens",
    )

    @property
    def is_expired(self) -> bool:
        """Indica si el Refresh Token ha superado su fecha de expiración."""
        now = datetime.now(timezone.utc)
        exp = (
            self.expires_at
            if self.expires_at.tzinfo is not None
            else self.expires_at.replace(tzinfo=timezone.utc)
        )
        return now >= exp

    @property
    def is_valid(self) -> bool:
        """Indica si el Refresh Token no está revocado ni expirado."""
        return not self.is_revoked and not self.is_expired

    def __repr__(self) -> str:
        return (
            f"<RefreshToken id={self.id} user_id={self.user_id} "
            f"family_id={self.family_id!r} is_revoked={self.is_revoked}>"
        )


class OneTimeToken(Base):
    """
    Token temporal de un solo uso (15 minutos de vigencia) almacenado como hash SHA-256
    para flujos de verificación de correo y restablecimiento de contraseña.
    """

    __tablename__ = "one_time_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    token_type: Mapped[str] = mapped_column(
        String(32),
        index=True,
        nullable=False,
    )
    is_used: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=false(),
        nullable=False,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=False,
    )
    requested_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="one_time_tokens",
    )

    @property
    def is_expired(self) -> bool:
        """Indica si el token de un solo uso ha superado su ventana de 15 minutos."""
        now = datetime.now(timezone.utc)
        exp = (
            self.expires_at
            if self.expires_at.tzinfo is not None
            else self.expires_at.replace(tzinfo=timezone.utc)
        )
        return now >= exp

    @property
    def is_valid(self) -> bool:
        """Indica si el token de un solo uso no ha sido utilizado ni ha expirado."""
        return not self.is_used and not self.is_expired

    def __repr__(self) -> str:
        return (
            f"<OneTimeToken id={self.id} user_id={self.user_id} "
            f"type={self.token_type!r} is_used={self.is_used}>"
        )
