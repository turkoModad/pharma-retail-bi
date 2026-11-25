"""
Modelo ORM de Usuario (`User`) y enumeración de roles RBAC (`UserRole`).

Implementa:
- Cifrado simétrico transparente de PII en reposo (`phone`, `document_id`, `address`) mediante Fernet.
- Blind Indexing determinístico (`email_hash`) mediante HMAC-SHA256.
- Control de bloqueo temporal de cuenta contra fuerza bruta (`failed_login_attempts`, `locked_until`, `is_locked`).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Integer, String, Text, Uuid, event, false, func, true
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.core.security import compute_blind_index, decrypt_pii, encrypt_pii

if TYPE_CHECKING:
    from app.models.audit_log import AuditLog
    from app.models.token import OneTimeToken, RefreshToken


class UserRole(str, Enum):
    """Roles del sistema de control de acceso basado en roles (RBAC)."""

    USER = "user"
    ADMIN = "admin"


class User(Base):
    """Entidad de usuario con protección criptográfica de PII y atributos de seguridad."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
         nullable=False,
    )
    email_encrypted: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    email_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    full_name_encrypted: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    phone_encrypted: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    document_id_encrypted: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    address_encrypted: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    role: Mapped[str] = mapped_column(
        String(20),
        default=UserRole.USER.value,
        server_default=UserRole.USER.value,
        index=True,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=true(),
        nullable=False,
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        server_default=false(),
        nullable=False,
    )

    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        server_default="0",
        nullable=False,
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    token_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        server_default="1",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    one_time_tokens: Mapped[list["OneTimeToken"]] = relationship(
        "OneTimeToken",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="user",
        passive_deletes=True,
    )


    @property
    def email(self) -> str:
        """Retorna el correo electrónico descifrado en memoria."""
        return decrypt_pii(self.email_encrypted) or ""

    @email.setter
    def email(self, value: str) -> None:
        """Normaliza y cifra el correo electrónico con Fernet, actualizando su blind index."""
        normalized = (value or "").strip().lower()
        self.email_encrypted = encrypt_pii(normalized) or ""
        self.email_hash = compute_blind_index(normalized)

    @property
    def full_name(self) -> str:
        """Retorna el nombre completo descifrado en memoria."""
        return decrypt_pii(self.full_name_encrypted) or ""

    @full_name.setter
    def full_name(self, value: str) -> None:
        """Normaliza y cifra el nombre completo mediante Fernet antes de persistirlo."""
        cleaned = (value or "").strip()
        self.full_name_encrypted = encrypt_pii(cleaned) or ""

    @property
    def phone(self) -> str | None:
        """Retorna el teléfono descifrado en memoria."""
        return decrypt_pii(self.phone_encrypted)

    @phone.setter
    def phone(self, value: str | None) -> None:
        """Cifra el teléfono mediante Fernet antes de persistirlo."""
        self.phone_encrypted = encrypt_pii(value)

    @property
    def document_id(self) -> str | None:
        """Retorna el documento de identidad descifrado en memoria."""
        return decrypt_pii(self.document_id_encrypted)

    @document_id.setter
    def document_id(self, value: str | None) -> None:
        """Cifra el documento de identidad mediante Fernet antes de persistirlo."""
        self.document_id_encrypted = encrypt_pii(value)

    @property
    def address(self) -> str | None:
        """Retorna la dirección postal descifrada en memoria."""
        return decrypt_pii(self.address_encrypted)

    @address.setter
    def address(self, value: str | None) -> None:
        """Cifra la dirección postal mediante Fernet antes de persistirla."""
        self.address_encrypted = encrypt_pii(value)

    @property
    def is_locked(self) -> bool:
        """Indica si la cuenta se encuentra temporalmente bloqueada por intentos fallidos."""
        if self.locked_until is None:
            return False
        now = datetime.now(timezone.utc)
        lock_deadline = (
            self.locked_until
            if self.locked_until.tzinfo is not None
            else self.locked_until.replace(tzinfo=timezone.utc)
        )
        return lock_deadline > now

    def __repr__(self) -> str:
        return (
            f"<User id={self.id} role={self.role!r} "
            f"is_active={self.is_active} is_verified={self.is_verified}>"
        )


@event.listens_for(User, "before_insert")
@event.listens_for(User, "before_update")
def _populate_user_email_blind_index(
    mapper: object, connection: object, target: User
) -> None:
    """Garantiza que `email_hash` esté sincronizado con `email_encrypted` antes de persistir."""
    if target.email_encrypted and not target.email_hash:
        decrypted = decrypt_pii(target.email_encrypted)
        if decrypted:
            target.email_hash = compute_blind_index(decrypted.strip().lower())
