"""
Dependencias de Autenticación, Autorización RBAC y Gestión de Cookies Seguras para FastAPI.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

import jwt
from fastapi import Depends, HTTPException, Request, Response, status

from app.core.config import settings
from app.core.database import AsyncSession, get_db
from app.core.security import (
    decode_access_token,
    generate_csrf_token,
    is_access_token_revoked,
)
from app.models.user import User, UserRole


def extract_access_token(request: Request) -> str | None:
    """
    Extrae el Access Token JWT priorizando la cabecera `Authorization: Bearer <token>`
    y como segundo mecanismo la cookie `HttpOnly` llamada `access_token`.
    """
    auth_header = request.headers.get("authorization")
    if auth_header:
        parts = auth_header.strip().split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip()

    cookie_token = request.cookies.get("access_token")
    if cookie_token and cookie_token.strip():
        raw = cookie_token.strip()
        if raw.lower().startswith("bearer "):
            return raw[7:].strip()
        return raw

    return None


def extract_refresh_token(request: Request, body_token: str | None = None) -> str | None:
    """
    Extrae el Refresh Token desde el payload explícito, la cookie `HttpOnly`
    llamada `refresh_token` o la cabecera `X-Refresh-Token`.
    """
    if body_token and body_token.strip():
        return body_token.strip()

    cookie_refresh = request.cookies.get("refresh_token")
    if cookie_refresh and cookie_refresh.strip():
        return cookie_refresh.strip()

    header_refresh = request.headers.get("x-refresh-token")
    if header_refresh and header_refresh.strip():
        return header_refresh.strip()

    return None


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Valida el JWT Access Token actual, recupera el usuario desde la base de datos
    y verifica que la cuenta esté activa y no bloqueada temporalmente.
    """
    token = extract_access_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado: se requiere un token de acceso válido.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El token de acceso ha expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso inválido o adulterado.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if is_access_token_revoked(payload.get("jti")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="La sesión fue cerrada y el token ha sido revocado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    sub = payload.get("sub")
    try:
        user_id = uuid.UUID(str(sub))
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identificador de sujeto ('sub') inválido en el token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El usuario asociado al token ya no existe.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="La cuenta de usuario se encuentra desactivada.",
        )

    token_ver = payload.get("ver")
    if token_ver is None or int(token_ver) != int(getattr(user, "token_version", 1)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El token de acceso ha sido revocado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="La cuenta de usuario se encuentra bloqueada temporalmente.",
        )

    request.state.current_user = user
    return user


async def get_optional_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """
    Intenta resolver el usuario autenticado actual sin lanzar excepción si no hay
    sesión activa o si el token expiró (útil para vistas SSR Jinja2 y logout).
    """
    token = extract_access_token(request)
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        if is_access_token_revoked(payload.get("jti")):
            return None
        user_id = uuid.UUID(str(payload.get("sub")))
        user = await db.get(User, user_id)
        if user is None or not user.is_active or user.is_locked:
            return None
        token_ver = payload.get("ver")
        if token_ver is None or int(token_ver) != int(getattr(user, "token_version", 1)):
            return None
        request.state.current_user = user
        return user
    except Exception:
        return None


async def get_current_verified_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Verifica que el usuario autenticado haya confirmado su correo electrónico."""
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cuenta pendiente de verificación de correo electrónico.",
        )
    return current_user


async def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependencia RBAC que exige rol `admin`.
    Lanza HTTP 403 Forbidden si un usuario con rol `user` intenta acceder.
    """
    role_str = (
        current_user.role.value
        if hasattr(current_user.role, "value")
        else str(current_user.role)
    )
    if role_str != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado: se requieren privilegios de administrador (RBAC).",
        )
    return current_user


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    csrf_token: str | None = None,
) -> str:
    """
    Configura las cookies de sesión en la respuesta HTTP:
    - `access_token`: `HttpOnly=True`, `Secure`, `SameSite`, expiración 30 min.
    - `refresh_token`: `HttpOnly=True`, `Secure`, `SameSite`, expiración 7 días.
    - `csrf_token`: `HttpOnly=False` (accesible por JS para Double Submit Cookie), firmado con HMAC.
    """
    samesite_val = (settings.COOKIE_SAMESITE or "lax").lower()
    secure_flag = bool(settings.COOKIE_SECURE)
    cookie_domain = settings.COOKIE_DOMAIN
    access_max_age = int(settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60
    refresh_max_age = int(settings.REFRESH_TOKEN_EXPIRE_DAYS) * 86400
    effective_csrf = csrf_token or generate_csrf_token()

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=secure_flag,
        samesite=samesite_val,
        domain=cookie_domain,
        path="/",
        max_age=access_max_age,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=secure_flag,
        samesite=samesite_val,
        domain=cookie_domain,
        path="/",
        max_age=refresh_max_age,
    )
    response.set_cookie(
        key="csrf_token",
        value=effective_csrf,
        httponly=False,
        secure=secure_flag,
        samesite=samesite_val,
        domain=cookie_domain,
        path="/",
        max_age=refresh_max_age,
    )
    return effective_csrf


def clear_auth_cookies(response: Response) -> None:
    """Elimina las cookies de autenticación y CSRF del cliente."""
    cookie_domain = settings.COOKIE_DOMAIN
    samesite_val = (settings.COOKIE_SAMESITE or "lax").lower()
    secure_flag = bool(settings.COOKIE_SECURE)
    for cookie_name in ("access_token", "refresh_token", "csrf_token"):
        response.delete_cookie(
            key=cookie_name,
            path="/",
            domain=cookie_domain,
            secure=secure_flag,
            httponly=(cookie_name != "csrf_token"),
            samesite=samesite_val,
        )


def is_html_form_request(request: Request) -> bool:
    """
    Determina si la petición proviene de un formulario HTML de navegador que espera
    una redirección/vista HTML en lugar de un payload JSON puro.
    """
    accept = (request.headers.get("accept") or "").lower()
    content_type = (request.headers.get("content-type") or "").lower()
    xhr = (request.headers.get("x-requested-with") or "").lower()

    if "application/json" in content_type or xhr == "xmlhttprequest":
        return False
    if "application/json" in accept and "text/html" not in accept:
        return False
    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        return "text/html" in accept
    return False


async def parse_request_payload(request: Request) -> Dict[str, Any]:
    """
    Extrae de manera unificada el payload de entrada ya sea desde `application/json`
    o desde `application/x-www-form-urlencoded` / `multipart/form-data`.
    """
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        try:
            data = await request.json()
            if isinstance(data, dict):
                return data
        except Exception:
            return {}
        return {}

    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        try:
            form_data = await request.form()
            return {k: v for k, v in form_data.items() if isinstance(v, str)}
        except Exception:
            return {}

    try:
        raw = await request.body()
        if raw:
            data = await request.json()
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}
