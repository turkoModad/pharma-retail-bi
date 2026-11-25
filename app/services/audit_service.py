"""
Servicio Forense de Auditoría (`audit_logs` con JSONB en PostgreSQL).

Garantiza la trazabilidad completa de eventos de autenticación, autorización y cambios
administrativos, asegurando que ningún dato sensible (PII en texto plano, contraseñas
o tokens crudos) sea persistido en la columna JSONB `details`.
"""

from __future__ import annotations

import ipaddress
import uuid
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict

from sqlalchemy import Enum as SAEnum

if TYPE_CHECKING:
    from fastapi import Request

from app.core.config import settings
from app.core.database import AsyncSession
from app.models.audit_log import AuditEventType, AuditLog

FORBIDDEN_DETAIL_KEYS = frozenset(
    {
        "password",
        "new_password",
        "current_password",
        "confirm_password",
        "password_hash",
        "raw_password",
        "token",
        "raw_token",
        "access_token",
        "refresh_token",
        "csrf_token",
        "secret",
        "secret_key",
        "fernet_key",
        "hmac_secret",
        "email",
        "email_encrypted",
        "full_name",
        "full_name_encrypted",
        "phone",
        "document_id",
        "address",
        "phone_encrypted",
        "document_id_encrypted",
        "address_encrypted",
        "ssn",
        "credit_card",
    }
)


def _is_trusted_proxy(ip_str: str) -> bool:
    """Verifica si la IP directa del socket pertenece a `settings.TRUSTED_PROXIES`."""
    if not ip_str:
        return False
    trusted = settings.TRUSTED_PROXIES
    if "*" in trusted:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return ip_str in trusted

    for entry in trusted:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            if ip_str == entry:
                return True
    return False


def _valid_ip_or_none(raw: str | None) -> str | None:
    if not raw or not raw.strip():
        return None
    candidate = raw.strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return None


def extract_client_ip(request: Request | None) -> str:
    """
    Extrae la dirección IP real del cliente validando `settings.TRUSTED_PROXIES`
    antes de aceptar cabeceras de proxy (`CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`).
    """
    if request is None:
        return "127.0.0.1"

    state_ip = getattr(request.state, "client_ip", None)
    if state_ip and isinstance(state_ip, str):
        return state_ip

    socket_ip = (
        request.client.host
        if (request.client and request.client.host)
        else "127.0.0.1"
    )

    if _is_trusted_proxy(socket_ip):
        cf_ip = _valid_ip_or_none(request.headers.get("cf-connecting-ip"))
        if cf_ip:
            return cf_ip

        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            first_ip = _valid_ip_or_none(forwarded_for.split(",")[0])
            if first_ip:
                return first_ip

        real_ip = _valid_ip_or_none(request.headers.get("x-real-ip"))
        if real_ip:
            return real_ip

    return socket_ip


def extract_user_agent(request: Request | None) -> str:
    """Extrae y trunca de forma segura el `User-Agent` de la petición HTTP."""
    if request is None:
        return "system/internal"

    state_ua = getattr(request.state, "user_agent", None)
    if state_ua and isinstance(state_ua, str):
        return state_ua[:512]

    ua = request.headers.get("user-agent", "unknown")
    return ua.strip()[:512] if ua else "unknown"


def sanitize_audit_details(details: Dict[str, Any] | None) -> Dict[str, Any]:
    """
    Sanea recursivamente el diccionario `details` antes de almacenarlo en JSONB.
    Elimina o enmascara cualquier clave que represente contraseñas, tokens o PII
    en texto plano, preservando únicamente metadatos seguros y `modified_fields`.
    """
    if not details or not isinstance(details, dict):
        return {}

    sanitized: Dict[str, Any] = {}
    for key, value in details.items():
        norm_key = str(key).strip().lower()
        if norm_key in FORBIDDEN_DETAIL_KEYS or any(
            secret_word in norm_key
            for secret_word in ("password", "secret", "raw_token", "fernet")
        ):
            continue

        if isinstance(value, dict):
            sanitized[str(key)] = sanitize_audit_details(value)
        elif isinstance(value, (list, tuple, set)):
            clean_list = []
            for item in value:
                if isinstance(item, dict):
                    clean_list.append(sanitize_audit_details(item))
                elif isinstance(item, (str, int, float, bool)) or item is None:
                    clean_list.append(item)
                else:
                    clean_list.append(str(item))
            sanitized[str(key)] = clean_list
        elif isinstance(value, (str, int, float, bool)) or value is None:
            sanitized[str(key)] = value
        elif isinstance(value, Enum):
            sanitized[str(key)] = value.value
        else:
            sanitized[str(key)] = str(value)

    return sanitized


def _resolve_event_type_value(event_type: str | AuditEventType) -> Any:
    """
    Normaliza el valor de `event_type` según la definición de columna en `AuditLog`.
    """
    try:
        col_type = AuditLog.__table__.columns["event_type"].type
        is_sa_enum = isinstance(col_type, SAEnum)
    except Exception:
        is_sa_enum = False

    if isinstance(event_type, AuditEventType):
        return event_type if is_sa_enum else event_type.value

    raw_str = event_type.value if isinstance(event_type, Enum) else str(event_type)
    if is_sa_enum:
        try:
            return AuditEventType(raw_str)
        except ValueError:
            return raw_str
    return raw_str


async def log_audit_event(
    db: AsyncSession,
    event_type: str | AuditEventType,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
    user_id: uuid.UUID | None = None,
    details: Dict[str, Any] | None = None,
    commit: bool = False,
) -> AuditLog:
    """
    Registra un evento forense en la tabla `audit_logs` aplicando sanitización
    estricta del payload JSONB `details`.
    """
    safe_details = sanitize_audit_details(details)
    resolved_event = _resolve_event_type_value(event_type)

    audit_entry = AuditLog(
        user_id=user_id,
        event_type=resolved_event,
        ip_address=(ip_address or "127.0.0.1")[:64],
        user_agent=(user_agent or "unknown")[:512] if user_agent is not None else "unknown",
        details=safe_details,
    )
    db.add(audit_entry)
    await db.flush()
    if commit:
        await db.commit()
        await db.refresh(audit_entry)
    return audit_entry
