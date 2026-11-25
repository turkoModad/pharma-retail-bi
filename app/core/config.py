"""
Módulo de configuración centralizada de la aplicación.

Carga variables de entorno desde `app/.env` o `.env` utilizando `python-dotenv`
y valida el esquema de configuración con `pydantic-settings` (con fallback
determinístico basado en `dataclass` y `os.getenv` para entornos sin
`pydantic-settings` instalado).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

_APP_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _APP_DIR.parent

for _env_file in (_APP_DIR / ".env", _PROJECT_ROOT / ".env"):
    if _env_file.is_file():
        load_dotenv(dotenv_path=_env_file, override=False)


DEFAULT_FERNET_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
DEFAULT_CORS_ORIGINS = ["http://127.0.0.1:8480", "http://localhost:8480"]
DEFAULT_ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
DEFAULT_TRUSTED_PROXIES = ["127.0.0.1", "::1"]

_INSECURE_DEFAULT_SECRETS = frozenset(
    {
        "",
        DEFAULT_FERNET_KEY,
        "Z3VhcJk9X2t5cE1mVnh6QWJDRGVmR2hJSmtsTW5PcFFyU3R1Vnd4WXo0NTY=",
        "cambia-esta-clave-secreta-jwt-minimo-32-bytes-produccion-2026",
        "cambia-esta-clave-hmac-sha256-para-blind-indexing-seguro-2026",
        "cambia-esta-clave-csrf-double-submit-cookie-segura-2026",
    }
)


def validate_production_security(cfg: Any) -> None:
    """Valida que en modo producción no se usen secretos por defecto ni cookies inseguras."""
    env = str(getattr(cfg, "ENVIRONMENT", "")).strip().lower()
    if env != "production":
        return

    for key_name in ("SECRET_KEY", "FERNET_KEY", "HMAC_SECRET", "CSRF_SECRET"):
        val = str(getattr(cfg, key_name, "") or "").strip()
        if not val or val in _INSECURE_DEFAULT_SECRETS or len(val) < 32:
            raise ValueError(
                f"Configuración insegura en producción: {key_name} debe estar definido, "
                f"no usar el valor por defecto y tener al menos 32 caracteres."
            )

    if not bool(getattr(cfg, "COOKIE_SECURE", False)):
        raise ValueError(
            "Configuración insegura en producción: COOKIE_SECURE debe ser True."
        )


def _build_default_database_url(async_driver: bool = True) -> str:
    """Construye DATABASE_URL por defecto apuntando a SQLite asíncrono (`aiosqlite`)."""
    db_path = os.getenv("SQLITE_DB_PATH", "./data/authsec.db")
    scheme = "sqlite+aiosqlite" if async_driver else "sqlite"
    return f"{scheme}:///{db_path}"


def _parse_bool(value: Any, default: bool = False) -> bool:
    """Convierte un valor de entorno en booleano de forma segura."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on", "t", "y"}:
        return True
    if normalized in {"0", "false", "no", "off", "f", "n", ""}:
        return False
    return default


def _parse_int(value: Any, default: int) -> int:
    """Convierte un valor de entorno en entero con fallback seguro."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if value is None or str(value).strip() == "":
        return default
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default


def _parse_str_list(value: Any, default: list[str]) -> list[str]:
    """Convierte una cadena JSON o lista separada por comas en `list[str]`."""
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return list(default)
    raw = str(value).strip()
    if not raw:
        return list(default)
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_optional_str(value: Any, default: str | None = None) -> str | None:
    """Normaliza cadenas vacías a `None` para parámetros opcionales como COOKIE_DOMAIN."""
    if value is None:
        return default
    cleaned = str(value).strip()
    return cleaned if cleaned else default


try:
    from pydantic import field_validator, model_validator
    from pydantic_settings import BaseSettings, SettingsConfigDict

    _HAS_PYDANTIC_SETTINGS = True
except ImportError:
    _HAS_PYDANTIC_SETTINGS = False


if _HAS_PYDANTIC_SETTINGS:

    class Settings(BaseSettings):
        """Configuración tipada respaldada por `pydantic-settings`."""

        model_config = SettingsConfigDict(
            env_file=(str(_APP_DIR / ".env"), str(_PROJECT_ROOT / ".env")),
            env_file_encoding="utf-8",
            case_sensitive=True,
            extra="ignore",
        )

        ENVIRONMENT: str = "development"
        APP_NAME: str = "AuthSec & Audit Platform"
        APP_HOST: str = "127.0.0.1"
        APP_PORT: int = 8480
        APP_BASE_URL: str = "http://127.0.0.1:8480"
        DEBUG: bool = False

        DATABASE_URL: str = field(
            default_factory=lambda: _build_default_database_url(async_driver=True)
        ) if not _HAS_PYDANTIC_SETTINGS else _build_default_database_url(async_driver=True)
        DATABASE_URL_SYNC: str = field(
            default_factory=lambda: _build_default_database_url(async_driver=False)
        ) if not _HAS_PYDANTIC_SETTINGS else _build_default_database_url(async_driver=False)

        SECRET_KEY: str = (
            "cambia-esta-clave-secreta-jwt-minimo-32-bytes-produccion-2026"
        )
        JWT_ALGORITHM: str = "HS256"
        ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
        REFRESH_TOKEN_EXPIRE_DAYS: int = 7
        ONE_TIME_TOKEN_EXPIRE_MINUTES: int = 15

        FERNET_KEY: str = DEFAULT_FERNET_KEY
        HMAC_SECRET: str = (
            "cambia-esta-clave-hmac-sha256-para-blind-indexing-seguro-2026"
        )
        CSRF_SECRET: str = (
            "cambia-esta-clave-csrf-double-submit-cookie-segura-2026"
        )

        COOKIE_SECURE: bool = False
        COOKIE_SAMESITE: str = "lax"
        COOKIE_DOMAIN: str | None = None
        MAX_FAILED_LOGIN_ATTEMPTS: int = 5
        ACCOUNT_LOCKOUT_MINUTES: int = 15
        CORS_ORIGINS: list[str] = DEFAULT_CORS_ORIGINS
        ALLOWED_HOSTS: list[str] = DEFAULT_ALLOWED_HOSTS
        TRUSTED_PROXIES: list[str] = DEFAULT_TRUSTED_PROXIES

        SMTP_HOST: str = ""
        SMTP_PORT: int = 587
        SMTP_USER: str = ""
        SMTP_PASSWORD: str = ""
        SMTP_FROM_EMAIL: str = "no-reply@authsec.local"
        SMTP_FROM_NAME: str = "Seguridad AuthSec"
        SMTP_TLS: bool = True

        @field_validator("COOKIE_DOMAIN", mode="before")
        @classmethod
        def _normalize_cookie_domain(cls, v: Any) -> str | None:
            return _parse_optional_str(v, default=None)

        @field_validator("CORS_ORIGINS", mode="before")
        @classmethod
        def _normalize_cors_origins(cls, v: Any) -> list[str]:
            return _parse_str_list(v, default=DEFAULT_CORS_ORIGINS)

        @field_validator("ALLOWED_HOSTS", mode="before")
        @classmethod
        def _normalize_allowed_hosts(cls, v: Any) -> list[str]:
            return _parse_str_list(v, default=DEFAULT_ALLOWED_HOSTS)

        @field_validator("TRUSTED_PROXIES", mode="before")
        @classmethod
        def _normalize_trusted_proxies(cls, v: Any) -> list[str]:
            return _parse_str_list(v, default=DEFAULT_TRUSTED_PROXIES)

        @model_validator(mode="after")
        def _validate_prod_secrets(self) -> "Settings":
            validate_production_security(self)
            return self

        def __post_init__(self) -> None:
            validate_production_security(self)

        @property
        def is_production(self) -> bool:
            """Indica si la aplicación se ejecuta en modo producción."""
            return self.ENVIRONMENT.strip().lower() == "production"

else:

    @dataclass
    class Settings:
        """Fallback de configuración respaldado por `os.getenv` cuando `pydantic-settings` no está disponible."""

        ENVIRONMENT: str = field(
            default_factory=lambda: os.getenv("ENVIRONMENT", "development")
        )
        APP_NAME: str = field(
            default_factory=lambda: os.getenv(
                "APP_NAME", "AuthSec & Audit Platform"
            )
        )
        APP_HOST: str = field(
            default_factory=lambda: os.getenv("APP_HOST", "127.0.0.1")
        )
        APP_PORT: int = field(
            default_factory=lambda: _parse_int(os.getenv("APP_PORT"), default=8480)
        )
        APP_BASE_URL: str = field(
            default_factory=lambda: os.getenv(
                "APP_BASE_URL", "http://127.0.0.1:8480"
            )
        )
        DEBUG: bool = field(
            default_factory=lambda: _parse_bool(os.getenv("DEBUG"), default=False)
        )

        DATABASE_URL: str = field(
            default_factory=lambda: os.getenv(
                "DATABASE_URL",
                "sqlite+aiosqlite:///./data/authsec.db",
            )
        )
        DATABASE_URL_SYNC: str = field(
            default_factory=lambda: os.getenv(
                "DATABASE_URL_SYNC",
                "sqlite:///./data/authsec.db",
            )
        )

        SECRET_KEY: str = field(
            default_factory=lambda: os.getenv(
                "SECRET_KEY",
                "cambia-esta-clave-secreta-jwt-minimo-32-bytes-produccion-2026",
            )
        )
        JWT_ALGORITHM: str = field(
            default_factory=lambda: os.getenv("JWT_ALGORITHM", "HS256")
        )
        ACCESS_TOKEN_EXPIRE_MINUTES: int = field(
            default_factory=lambda: _parse_int(
                os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"), default=30
            )
        )
        REFRESH_TOKEN_EXPIRE_DAYS: int = field(
            default_factory=lambda: _parse_int(
                os.getenv("REFRESH_TOKEN_EXPIRE_DAYS"), default=7
            )
        )
        ONE_TIME_TOKEN_EXPIRE_MINUTES: int = field(
            default_factory=lambda: _parse_int(
                os.getenv("ONE_TIME_TOKEN_EXPIRE_MINUTES"), default=15
            )
        )

        FERNET_KEY: str = field(
            default_factory=lambda: os.getenv("FERNET_KEY", DEFAULT_FERNET_KEY)
        )
        HMAC_SECRET: str = field(
            default_factory=lambda: os.getenv(
                "HMAC_SECRET",
                "cambia-esta-clave-hmac-sha256-para-blind-indexing-seguro-2026",
            )
        )
        CSRF_SECRET: str = field(
            default_factory=lambda: os.getenv(
                "CSRF_SECRET",
                "cambia-esta-clave-csrf-double-submit-cookie-segura-2026",
            )
        )

        COOKIE_SECURE: bool = field(
            default_factory=lambda: _parse_bool(
                os.getenv("COOKIE_SECURE"), default=False
            )
        )
        COOKIE_SAMESITE: str = field(
            default_factory=lambda: os.getenv("COOKIE_SAMESITE", "lax")
        )
        COOKIE_DOMAIN: str | None = field(
            default_factory=lambda: _parse_optional_str(
                os.getenv("COOKIE_DOMAIN"), default=None
            )
        )
        MAX_FAILED_LOGIN_ATTEMPTS: int = field(
            default_factory=lambda: _parse_int(
                os.getenv("MAX_FAILED_LOGIN_ATTEMPTS"), default=5
            )
        )
        ACCOUNT_LOCKOUT_MINUTES: int = field(
            default_factory=lambda: _parse_int(
                os.getenv("ACCOUNT_LOCKOUT_MINUTES"), default=15
            )
        )
        CORS_ORIGINS: list[str] = field(
            default_factory=lambda: _parse_str_list(
                os.getenv("CORS_ORIGINS"), default=DEFAULT_CORS_ORIGINS
            )
        )
        ALLOWED_HOSTS: list[str] = field(
            default_factory=lambda: _parse_str_list(
                os.getenv("ALLOWED_HOSTS"), default=DEFAULT_ALLOWED_HOSTS
            )
        )
        TRUSTED_PROXIES: list[str] = field(
            default_factory=lambda: _parse_str_list(
                os.getenv("TRUSTED_PROXIES"), default=DEFAULT_TRUSTED_PROXIES
            )
        )

        SMTP_HOST: str = field(
            default_factory=lambda: os.getenv("SMTP_HOST", "")
        )
        SMTP_PORT: int = field(
            default_factory=lambda: _parse_int(
                os.getenv("SMTP_PORT"), default=587
            )
        )
        SMTP_USER: str = field(
            default_factory=lambda: os.getenv("SMTP_USER", "")
        )
        SMTP_PASSWORD: str = field(
            default_factory=lambda: os.getenv("SMTP_PASSWORD", "")
        )
        SMTP_FROM_EMAIL: str = field(
            default_factory=lambda: os.getenv(
                "SMTP_FROM_EMAIL", "no-reply@authsec.local"
            )
        )
        SMTP_FROM_NAME: str = field(
            default_factory=lambda: os.getenv(
                "SMTP_FROM_NAME", "Seguridad AuthSec"
            )
        )
        SMTP_TLS: bool = field(
            default_factory=lambda: _parse_bool(
                os.getenv("SMTP_TLS"), default=True
            )
        )

        def __post_init__(self) -> None:
            validate_production_security(self)

        @property
        def is_production(self) -> bool:
            """Indica si la aplicación se ejecuta en modo producción."""
            return self.ENVIRONMENT.strip().lower() == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retorna la instancia singleton de configuración de la aplicación."""
    return Settings()


settings: Settings = get_settings()
