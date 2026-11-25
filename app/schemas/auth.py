"""
Esquemas Pydantic v2 para flujos de autenticación, tokens JWT/Refresh,
verificación de cuenta y recuperación de contraseña.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.user import UserRead, _check_password_strength, validate_email_address


class LoginRequest(BaseModel):
    """Credenciales de inicio de sesión."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: str = Field(..., description="Correo electrónico del usuario")
    password: str = Field(..., min_length=1, max_length=128, description="Contraseña en texto plano")

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: Any) -> str:
        return validate_email_address(value)


class TokenPairResponse(BaseModel):
    """Respuesta estándar con par de tokens (Access JWT + Refresh Token opaco)."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(default=1800, description="Tiempo de vida del access_token en segundos")
    csrf_token: str | None = None
    user: UserRead | None = None


class RefreshTokenRequest(BaseModel):
    """Solicitud opcional en body JSON para rotación de Refresh Token."""

    refresh_token: str | None = None


class ForgotPasswordRequest(BaseModel):
    """Solicitud de enlace de recuperación de contraseña."""

    model_config = ConfigDict(str_strip_whitespace=True)

    email: str = Field(..., description="Correo electrónico asociado a la cuenta")

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: Any) -> str:
        return validate_email_address(value)


class ResetPasswordRequest(BaseModel):
    """Solicitud de restablecimiento de contraseña mediante token de un solo uso."""

    model_config = ConfigDict(str_strip_whitespace=True)

    token: str = Field(..., min_length=10, max_length=512, description="Token criptográfico de un solo uso")
    new_password: str = Field(
        ...,
        min_length=10,
        max_length=128,
        description="Nueva contraseña validada bajo política estricta",
    )
    confirm_password: str | None = Field(default=None, max_length=128)

    @model_validator(mode="before")
    @classmethod
    def accept_password_alias(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "new_password" not in data and "password" in data:
                data = dict(data)
                data["new_password"] = data["password"]
        return data

    @field_validator("new_password", mode="after")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        return _check_password_strength(value)

    @model_validator(mode="after")
    def check_confirmation(self) -> "ResetPasswordRequest":
        if self.confirm_password is not None and self.new_password != self.confirm_password:
            raise ValueError("La confirmación de contraseña no coincide.")
        return self

    @property
    def password(self) -> str:
        return self.new_password


class VerifyEmailRequest(BaseModel):
    """Solicitud de verificación de correo electrónico con token de un solo uso."""

    model_config = ConfigDict(str_strip_whitespace=True)

    token: str = Field(..., min_length=10, max_length=512, description="Token de verificación de email")


class MessageResponse(BaseModel):
    """Respuesta genérica de estado y mensaje informativo."""

    message: str
    detail: str | None = None
    status: str = "ok"
