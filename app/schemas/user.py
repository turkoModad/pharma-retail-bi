"""
Esquemas Pydantic v2 para gestión de usuarios, perfiles con PII y administración RBAC.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.security import decrypt_pii, validate_password_strength

_EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)


def validate_email_address(value: Any) -> str:
    """
    Normaliza y valida direcciones de correo electrónico permitiendo también
    dominios de red local/intranet (.local, .lan, .internal) para despliegues en PC/RPi.
    """
    if not isinstance(value, str):
        raise ValueError("El correo electrónico debe ser una cadena de texto.")
    cleaned = value.strip().lower()
    if not cleaned or len(cleaned) > 255 or ".." in cleaned or not _EMAIL_REGEX.match(cleaned):
        raise ValueError("Formato de correo electrónico inválido.")
    return cleaned


def _check_password_strength(value: str) -> str:
    """
    Valida la política de fortaleza de contraseñas delegando en `validate_password_strength`
    de `app.core.security`. Soporta retorno booleano, tupla `(bool, msg)` o excepción `ValueError`.
    """
    if not value or not isinstance(value, str):
        raise ValueError("La contraseña es obligatoria.")
    result = validate_password_strength(value)
    if isinstance(result, tuple):
        is_valid = bool(result[0])
        reason = (
            str(result[1])
            if len(result) > 1
            else (
                "La contraseña debe tener al menos 10 caracteres, incluyendo mayúsculas, "
                "minúsculas, números y símbolos especiales."
            )
        )
        if not is_valid:
            raise ValueError(reason)
    elif isinstance(result, bool) and not result:
        raise ValueError(
            "La contraseña debe tener al menos 10 caracteres, incluyendo mayúsculas, "
            "minúsculas, números y símbolos especiales."
        )
    return value


def _safe_decrypt_field(obj: Any, plain_attr: str, encrypted_attr: str) -> str | None:
    """
    Obtiene y descifra de forma segura un atributo PII desde una instancia ORM o diccionario.
    """
    val = getattr(obj, plain_attr, None)
    if val is None and hasattr(obj, encrypted_attr):
        enc_val = getattr(obj, encrypted_attr, None)
        if enc_val:
            try:
                return decrypt_pii(enc_val)
            except Exception:
                return None
    if isinstance(val, str) and val.startswith("gAAAAA"):
        try:
            return decrypt_pii(val)
        except Exception:
            return val
    return val


class UserCreate(BaseModel):
    """Esquema de entrada para registro de nuevos usuarios."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: str = Field(..., description="Correo electrónico único del usuario")
    password: str = Field(
        ...,
        min_length=10,
        max_length=128,
        description="Contraseña segura (mínimo 10 caracteres, mayúsculas, minúsculas, números y símbolos)",
    )
    confirm_password: str | None = Field(default=None, max_length=128)
    full_name: str = Field(
        ...,
        min_length=2,
        max_length=150,
        description="Nombre y apellido completo del usuario",
    )
    phone: str | None = Field(
        default=None,
        max_length=50,
        description="Teléfono de contacto (se almacena cifrado con Fernet en reposo)",
    )
    document_id: str | None = Field(
        default=None,
        max_length=60,
        description="Documento de identidad / DNI / RUC (se almacena cifrado con Fernet en reposo)",
    )
    address: str | None = Field(
        default=None,
        max_length=300,
        description="Dirección física o domicilio (se almacena cifrado con Fernet en reposo)",
    )

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: Any) -> str:
        return validate_email_address(value)

    @field_validator("password", mode="after")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return _check_password_strength(value)

    @model_validator(mode="after")
    def verify_password_confirmation(self) -> "UserCreate":
        if self.confirm_password is not None and self.password != self.confirm_password:
            raise ValueError("La confirmación de contraseña no coincide.")
        return self


class AccountDeleteRequest(BaseModel):
    """Esquema para solicitud de baja definitiva de cuenta con doble verificación."""

    current_password: str = Field(..., min_length=1, max_length=128)
    confirmation: str = Field(..., min_length=1, max_length=32)

    @field_validator("confirmation", mode="after")
    @classmethod
    def validate_confirmation_word(cls, value: str) -> str:
        if value.strip() != "ELIMINAR":
            raise ValueError("Debe escribir exactamente ELIMINAR para confirmar la baja.")
        return value.strip()


class UserProfileUpdate(BaseModel):
    """Esquema para actualización de perfil propio (protegido contra IDOR)."""

    model_config = ConfigDict(str_strip_whitespace=True)

    full_name: str | None = Field(default=None, min_length=2, max_length=150)
    phone: str | None = Field(default=None, max_length=50)
    document_id: str | None = Field(default=None, max_length=60)
    address: str | None = Field(default=None, max_length=300)


class PasswordChangeRequest(BaseModel):
    """Esquema para cambio de contraseña desde sesión autenticada."""

    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=10, max_length=128)
    confirm_password: str | None = Field(default=None, max_length=128)

    @field_validator("new_password", mode="after")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        return _check_password_strength(value)

    @model_validator(mode="after")
    def verify_passwords_match_and_differ(self) -> "PasswordChangeRequest":
        if self.confirm_password is not None and self.new_password != self.confirm_password:
            raise ValueError("La confirmación de la nueva contraseña no coincide.")
        if self.current_password == self.new_password:
            raise ValueError("La nueva contraseña debe ser diferente de la contraseña actual.")
        return self


class UserRead(BaseModel):
    """Esquema de salida con datos del usuario y PII descifrada en memoria para visualización autorizada."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str
    phone: str | None = None
    document_id: str | None = None
    address: str | None = None
    role: str
    is_active: bool
    is_verified: bool
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    created_at: datetime
    updated_at: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def extract_and_decrypt_orm_user(cls, data: Any) -> Any:
        if isinstance(data, dict):
            role_val = data.get("role")
            if isinstance(role_val, Enum):
                data = dict(data)
                data["role"] = role_val.value
            return data

        if hasattr(data, "id") and hasattr(data, "email"):
            role_raw = getattr(data, "role", "user")
            role_str = role_raw.value if isinstance(role_raw, Enum) else str(role_raw)
            return {
                "id": getattr(data, "id"),
                "email": getattr(data, "email"),
                "full_name": getattr(data, "full_name", ""),
                "phone": _safe_decrypt_field(data, "phone", "phone_encrypted"),
                "document_id": _safe_decrypt_field(data, "document_id", "document_id_encrypted"),
                "address": _safe_decrypt_field(data, "address", "address_encrypted"),
                "role": role_str,
                "is_active": bool(getattr(data, "is_active", True)),
                "is_verified": bool(getattr(data, "is_verified", False)),
                "failed_login_attempts": int(getattr(data, "failed_login_attempts", 0) or 0),
                "locked_until": getattr(data, "locked_until", None),
                "created_at": getattr(data, "created_at"),
                "updated_at": getattr(data, "updated_at", None),
            }
        return data

    @classmethod
    def from_user(cls, user: Any) -> "UserRead":
        """Construye un `UserRead` descifrando explícitamente los campos PII del modelo ORM."""
        return cls.model_validate(user)


class AdminUserUpdate(BaseModel):
    """Esquema para operaciones administrativas sobre cuentas de usuario (RBAC)."""

    role: str | None = Field(
        default=None,
        description="Nuevo rol a asignar ('user' o 'admin')",
    )
    is_active: bool | None = Field(
        default=None,
        description="Estado de activación de la cuenta",
    )
    unlock_account: bool = Field(
        default=False,
        description="Si es True, resetea failed_login_attempts=0 y locked_until=None",
    )

    @field_validator("role", mode="before")
    @classmethod
    def validate_role(cls, value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, Enum):
            value = value.value
        normalized = str(value).strip().lower()
        if normalized not in ("user", "admin"):
            raise ValueError("El rol debe ser 'user' o 'admin'.")
        return normalized
