"""
Router de Vistas Server-Side Rendering (Jinja2 + Pico.css):
- `GET /`: Redirige a `/profile` si hay sesión activa o a `/login`.
- `GET /login`: Vista de inicio de sesión (`login.html`).
- `GET /register`: Vista de registro con medidor de política de contraseña (`register.html`).
- `GET /forgot-password`: Vista de solicitud de recuperación (`forgot_password.html`).
- `GET /reset-password`: Vista de restablecimiento con token (`reset_password.html`).
- `GET /profile`: Panel de perfil propio con PII descifrada y últimos accesos (`profile.html`).
- `GET /admin`: Dashboard administrativo RBAC con gestión de usuarios y `audit_logs` (`admin_dashboard.html`).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.core.database import AsyncSession, get_db
from app.core.security import generate_csrf_token, verify_csrf_token_signature
from app.models.user import User, UserRole
from app.routers.dependencies import get_optional_current_user
from app.schemas.audit import AuditLogRead
from app.schemas.user import UserRead
from app.services.email_service import get_last_sent_email
from app.services.user_service import (
    get_user_recent_logins,
    list_all_users,
    list_audit_logs,
)

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

router = APIRouter(tags=["Vistas SSR (Jinja2)"])


def _ensure_csrf_token(request: Request) -> str:
    state_csrf = getattr(request.state, "csrf_token", None)
    if state_csrf and isinstance(state_csrf, str) and verify_csrf_token_signature(state_csrf):
        return state_csrf
    cookie_csrf = request.cookies.get("csrf_token")
    if cookie_csrf and verify_csrf_token_signature(cookie_csrf):
        request.state.csrf_token = cookie_csrf
        return cookie_csrf
    fresh = generate_csrf_token()
    request.state.csrf_token = fresh
    return fresh


def _resolve_flash_messages(request: Request) -> Dict[str, str]:
    qp = request.query_params
    error_message = qp.get("error") or ""
    success_message = qp.get("success") or ""
    flash_message = qp.get("message") or ""

    if qp.get("registered") == "1":
        success_message = (
            "Cuenta registrada exitosamente. Revise su correo (o el enlace de desarrollo) "
            "para verificar su cuenta antes de que expire en 15 minutos."
        )
    elif qp.get("verified") == "1":
        success_message = "¡Correo electrónico verificado exitosamente! Ya puede iniciar sesión."
    elif qp.get("reset") == "1":
        success_message = (
            "Contraseña restablecida con éxito. Todas sus sesiones anteriores fueron cerradas."
        )
    elif qp.get("logged_out") == "1":
        flash_message = "Ha cerrado su sesión de forma segura."
    elif qp.get("account_deleted") == "1":
        success_message = "Su cuenta ha sido eliminada permanentemente y todas sus sesiones fueron cerradas."
    elif qp.get("sent") == "1":
        success_message = (
            "Si el correo proporcionado se encuentra registrado, recibirá un enlace "
            "temporal válido por 15 minutos."
        )
    elif qp.get("updated") == "1":
        success_message = "Los cambios han sido guardados y auditados correctamente."
    elif qp.get("pwd_changed") == "1":
        success_message = "Su contraseña ha sido actualizada correctamente."
    elif qp.get("status_updated") == "1":
        success_message = "Estado de cuenta del usuario actualizado."
    elif qp.get("role_updated") == "1":
        success_message = "Rol RBAC del usuario actualizado."
    elif qp.get("unlocked") == "1":
        success_message = "La cuenta del usuario ha sido desbloqueada exitosamente."

    return {
        "error_message": error_message,
        "success_message": success_message,
        "flash_message": flash_message,
    }


def _render_template(
    request: Request,
    template_name: str,
    context: Dict[str, Any],
    status_code: int = status.HTTP_200_OK,
) -> Response:
    csrf_token = _ensure_csrf_token(request)
    msgs = _resolve_flash_messages(request)

    dev_verification_link = None
    dev_reset_link = None
    if not settings.is_production and not (settings.SMTP_HOST or "").strip():
        last_verif = get_last_sent_email(email_type="email_verification")
        if last_verif and last_verif.get("token"):
            dev_verification_link = f"/auth/verify-email?token={last_verif['token']}"
        last_reset = get_last_sent_email(email_type="password_reset")
        if last_reset and last_reset.get("token"):
            dev_reset_link = f"/reset-password?token={last_reset['token']}"

    full_context: Dict[str, Any] = {
        "request": request,
        "csrf_token": csrf_token,
        "current_user": context.get("current_user"),
        "error_message": context.get("error_message") or msgs["error_message"],
        "success_message": context.get("success_message") or msgs["success_message"],
        "flash_message": context.get("flash_message") or msgs["flash_message"],
        "dev_verification_link": dev_verification_link,
        "dev_reset_link": dev_reset_link,
        **context,
    }

    try:
        response = templates.TemplateResponse(
            request=request,
            name=template_name,
            context=full_context,
            status_code=status_code,
        )
    except TypeError:
        response = templates.TemplateResponse(
            template_name,
            full_context,
            status_code=status_code,
        )

    samesite_val = (settings.COOKIE_SAMESITE or "lax").lower()
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        secure=bool(settings.COOKIE_SECURE),
        samesite=samesite_val,
        domain=settings.COOKIE_DOMAIN,
        path="/",
        max_age=int(settings.REFRESH_TOKEN_EXPIRE_DAYS) * 86400,
    )
    return response


@router.get("/", include_in_schema=False)
async def root_redirect(
    request: Request,
    current_user: User | None = Depends(get_optional_current_user),
) -> Response:
    """Redirige a `/profile` si el usuario tiene sesión activa o a `/login` en caso contrario."""
    target = "/profile" if current_user is not None else "/login"
    return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/login", response_class=HTMLResponse)
async def login_view(
    request: Request,
    current_user: User | None = Depends(get_optional_current_user),
) -> Response:
    """Renderiza el formulario de inicio de sesión."""
    if current_user is not None:
        return RedirectResponse(url="/profile", status_code=status.HTTP_303_SEE_OTHER)
    return _render_template(
        request=request,
        template_name="login.html",
        context={"current_user": None},
    )


@router.get("/register", response_class=HTMLResponse)
async def register_view(
    request: Request,
    current_user: User | None = Depends(get_optional_current_user),
) -> Response:
    """Renderiza el formulario de registro de usuario."""
    if current_user is not None:
        return RedirectResponse(url="/profile", status_code=status.HTTP_303_SEE_OTHER)
    return _render_template(
        request=request,
        template_name="register.html",
        context={"current_user": None},
    )


@router.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_view(
    request: Request,
    current_user: User | None = Depends(get_optional_current_user),
) -> Response:
    """Renderiza el formulario de solicitud de restablecimiento de contraseña."""
    user_read = UserRead.from_user(current_user) if current_user else None
    return _render_template(
        request=request,
        template_name="forgot_password.html",
        context={"current_user": user_read},
    )


@router.get("/reset-password", response_class=HTMLResponse)
async def reset_password_view(
    request: Request,
    token: str | None = None,
    current_user: User | None = Depends(get_optional_current_user),
) -> Response:
    """Renderiza el formulario de definición de nueva contraseña con token de un solo uso."""
    user_read = UserRead.from_user(current_user) if current_user else None
    resolved_token = token or request.query_params.get("token") or ""
    return _render_template(
        request=request,
        template_name="reset_password.html",
        context={
            "current_user": user_read,
            "token": resolved_token,
        },
    )


@router.get("/profile", response_class=HTMLResponse)
async def profile_view(
    request: Request,
    current_user: User | None = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """
    Vista protegida de perfil de usuario: muestra PII descifrada en memoria,
    estado de verificación de cuenta y tabla de últimos inicios de sesión (`audit_logs`).
    """
    if current_user is None:
        accept = (request.headers.get("accept") or "").lower()
        if "text/html" in accept and "application/json" not in accept:
            return RedirectResponse(
                url="/login?expired=1",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Debe iniciar sesión para acceder a su perfil.",
        )

    user_read = UserRead.from_user(current_user)
    recent_logs = await get_user_recent_logins(db=db, user_id=current_user.id, limit=15)
    recent_logins = [AuditLogRead.model_validate(item) for item in recent_logs]
    login_success_entries = [
        item for item in recent_logins if item.event_type == "LOGIN_SUCCESS"
    ]
    if len(login_success_entries) >= 2:
        last_connection = login_success_entries[1].created_at
    elif len(login_success_entries) == 1:
        last_connection = login_success_entries[0].created_at
    else:
        last_connection = None

    return _render_template(
        request=request,
        template_name="profile.html",
        context={
            "current_user": user_read,
            "user": user_read,
            "last_connection": last_connection,
            "recent_logins": recent_logins,
            "audit_logs": recent_logins,
        },
    )


@router.get("/admin", response_class=HTMLResponse)
async def admin_dashboard_view(
    request: Request,
    current_user: User | None = Depends(get_optional_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """
    Vista protegida de administración RBAC (`role == 'admin'`).
    Si un usuario autenticado con rol `user` intenta acceder, retorna HTTP 403 Forbidden.
    """
    if current_user is None:
        accept = (request.headers.get("accept") or "").lower()
        if "text/html" in accept and "application/json" not in accept:
            return RedirectResponse(
                url="/login?expired=1",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado: inicie sesión como administrador.",
        )

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

    user_read = UserRead.from_user(current_user)
    all_users_orm = await list_all_users(db=db, limit=200)
    all_users = [UserRead.from_user(u) for u in all_users_orm]

    audit_entries_orm = await list_audit_logs(db=db, limit=100)
    audit_entries = [AuditLogRead.model_validate(a) for a in audit_entries_orm]

    return _render_template(
        request=request,
        template_name="admin_dashboard.html",
        context={
            "current_user": user_read,
            "users": all_users,
            "audit_logs": audit_entries,
        },
    )
