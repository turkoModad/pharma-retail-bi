"""
Router de Autenticación (`/auth`):
- `POST /auth/register`: Registro seguro con Argon2id, Fernet PII, Blind Index y token SHA-256 (15 min).
- `GET|POST /auth/verify-email`: Confirmación de cuenta mediante token de un solo uso.
- `POST /auth/login`: Autenticación con bloqueo por fuerza bruta (5 intentos -> 15 min) y emisión de tokens.
- `POST /auth/refresh`: Rotación estricta de Refresh Token y detección de robo/reúso por familia.
- `POST /auth/logout`: Revocación de sesión y limpieza de cookies `HttpOnly`.
- `POST /auth/forgot-password`: Solicitud de recuperación anti-enumeración (token 15 min).
- `POST /auth/reset-password`: Restablecimiento de contraseña y revocación global de sesiones del usuario.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import ValidationError

from app.core.config import settings
from app.core.database import AsyncSession, get_db
from app.core.limiter import rate_limit
from app.core.security import decode_access_token, revoke_access_token_jti
from app.routers.dependencies import (
    clear_auth_cookies,
    extract_access_token,
    extract_refresh_token,
    get_optional_current_user,
    is_html_form_request,
    parse_request_payload,
    set_auth_cookies,
)
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    TokenPairResponse,
)
from app.schemas.user import UserCreate, UserRead
from app.services.audit_service import extract_client_ip, extract_user_agent
from app.services.auth_service import (
    authenticate_user,
    logout_session,
    register_user,
    request_password_reset,
    reset_password_with_token,
    rotate_refresh_token,
    verify_email_token,
)

router = APIRouter(prefix="/auth", tags=["Autenticación y Sesiones"])


def _format_validation_error(exc: ValidationError) -> str:
    messages = []
    for err in exc.errors():
        msg = err.get("msg", "Valor inválido")
        loc = ".".join(str(x) for x in err.get("loc", []) if x != "body")
        messages.append(f"{loc}: {msg}" if loc else msg)
    return "; ".join(messages) if messages else "Datos de entrada inválidos."


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit(max_requests=10, window_seconds=60, scope="auth:register"))],
)
async def register_endpoint(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Registra un nuevo usuario, cifra su PII con Fernet y emite token de verificación."""
    raw_data = await parse_request_payload(request)
    is_html = is_html_form_request(request)

    if is_html and not str(raw_data.get("confirm_password") or "").strip():
        return RedirectResponse(
            url=f"/register?error={quote('Debe confirmar su contraseña.')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        payload = UserCreate.model_validate(raw_data)
    except ValidationError as exc:
        err_msg = _format_validation_error(exc)
        if is_html:
            return RedirectResponse(
                url=f"/register?error={quote(err_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg,
        ) from exc

    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    try:
        user, raw_token, _ = await register_user(
            db=db,
            payload=payload,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except HTTPException as exc:
        if is_html:
            return RedirectResponse(
                url=f"/register?error={quote(str(exc.detail))}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise

    if is_html:
        return RedirectResponse(
            url="/login?registered=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    user_read = UserRead.from_user(user)
    response_body = user_read.model_dump(mode="json")
    response_body["user"] = user_read.model_dump(mode="json")
    response_body["message"] = (
        "Usuario registrado exitosamente. Revise su correo para verificar la cuenta (expira en 15 minutos)."
    )
    if not settings.is_production:
        response_body["verification_token"] = raw_token

    return JSONResponse(status_code=status.HTTP_201_CREATED, content=response_body)


@router.get("/verify-email")
@router.post("/verify-email")
async def verify_email_endpoint(
    request: Request,
    token: str | None = None,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Verifica la cuenta de un usuario mediante el token SHA-256 de un solo uso."""
    resolved_token = token or request.query_params.get("token")
    if not resolved_token and request.method == "POST":
        body_data = await parse_request_payload(request)
        resolved_token = str(body_data.get("token") or "")

    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    accept = (request.headers.get("accept") or "").lower()
    wants_browser_redirect = (
        request.method == "GET"
        and "text/html" in accept
        and "application/json" not in accept
    )

    try:
        user = await verify_email_token(
            db=db,
            raw_token=resolved_token or "",
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except HTTPException as exc:
        if wants_browser_redirect:
            return RedirectResponse(
                url=f"/login?error={quote(str(exc.detail))}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise

    if wants_browser_redirect:
        return RedirectResponse(
            url="/login?verified=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return {
        "message": "Correo electrónico verificado exitosamente.",
        "status": "ok",
        "is_verified": True,
        "user_id": str(user.id),
    }


@router.post(
    "/login",
    response_model=TokenPairResponse,
    dependencies=[Depends(rate_limit(max_requests=10, window_seconds=60, scope="auth:login"))],
)
async def login_endpoint(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Autentica credenciales de usuario, emite Access Token (30 min) y Refresh Token (7 días)
    en cookies `HttpOnly` y cuerpo JSON.
    """
    raw_data = await parse_request_payload(request)
    if "email" not in raw_data and "username" in raw_data:
        raw_data["email"] = raw_data["username"]

    is_html = is_html_form_request(request)

    try:
        login_req = LoginRequest.model_validate(raw_data)
    except ValidationError as exc:
        err_msg = _format_validation_error(exc)
        if is_html:
            return RedirectResponse(
                url=f"/login?error={quote(err_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg,
        ) from exc

    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    try:
        auth_data = await authenticate_user(
            db=db,
            email=login_req.email,
            password=login_req.password,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except HTTPException as exc:
        if is_html:
            return RedirectResponse(
                url=f"/login?error={quote(str(exc.detail))}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise

    if is_html:
        redirect_resp = RedirectResponse(
            url="/profile",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        set_auth_cookies(
            response=redirect_resp,
            access_token=auth_data["access_token"],
            refresh_token=auth_data["refresh_token"],
            csrf_token=auth_data["csrf_token"],
        )
        return redirect_resp

    set_auth_cookies(
        response=response,
        access_token=auth_data["access_token"],
        refresh_token=auth_data["refresh_token"],
        csrf_token=auth_data["csrf_token"],
    )

    return TokenPairResponse(
        access_token=auth_data["access_token"],
        refresh_token=auth_data["refresh_token"],
        token_type="bearer",
        expires_in=auth_data["expires_in"],
        csrf_token=auth_data["csrf_token"],
        user=UserRead.from_user(auth_data["user"]),
    )


@router.post(
    "/refresh",
    response_model=TokenPairResponse,
    dependencies=[Depends(rate_limit(max_requests=20, window_seconds=60, scope="auth:refresh"))],
)
async def refresh_token_endpoint(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Rota el Refresh Token actual invalidando el anterior y emitiendo un nuevo par
    `(access_token, refresh_token)`. Si detecta reúso de un Refresh Token ya rotado,
    revoca todas las sesiones activas del usuario y audita `TOKEN_REUSE_DETECTED`.
    """
    raw_data = await parse_request_payload(request)
    body_refresh = raw_data.get("refresh_token") if isinstance(raw_data, dict) else None
    raw_refresh_token = extract_refresh_token(request, body_token=body_refresh)

    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    try:
        rotated = await rotate_refresh_token(
            db=db,
            raw_refresh_token=raw_refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except HTTPException:
        clear_auth_cookies(response)
        raise

    set_auth_cookies(
        response=response,
        access_token=rotated["access_token"],
        refresh_token=rotated["refresh_token"],
        csrf_token=rotated["csrf_token"],
    )

    return TokenPairResponse(
        access_token=rotated["access_token"],
        refresh_token=rotated["refresh_token"],
        token_type="bearer",
        expires_in=rotated["expires_in"],
        csrf_token=rotated["csrf_token"],
        user=UserRead.from_user(rotated["user"]),
    )


@router.post("/logout")
async def logout_endpoint(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Revoca la sesión activa del usuario, limpia cookies y registra `LOGOUT`."""
    raw_data = await parse_request_payload(request)
    body_refresh = raw_data.get("refresh_token") if isinstance(raw_data, dict) else None
    raw_refresh_token = extract_refresh_token(request, body_token=body_refresh)
    raw_access_token = extract_access_token(request)
    if raw_access_token:
        try:
            access_payload = decode_access_token(raw_access_token)
            revoke_access_token_jti(
                access_payload.get("jti"),
                access_payload.get("exp"),
            )
        except Exception:
            pass
    current_user = await get_optional_current_user(request, db)

    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    await logout_session(
        db=db,
        raw_refresh_token=raw_refresh_token,
        user_id=current_user.id if current_user else None,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if is_html_form_request(request):
        redirect_resp = RedirectResponse(
            url="/login?logged_out=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        clear_auth_cookies(redirect_resp)
        return redirect_resp

    clear_auth_cookies(response)
    return {
        "message": "Sesión cerrada correctamente.",
        "status": "ok",
    }


@router.post(
    "/forgot-password",
    dependencies=[
        Depends(rate_limit(max_requests=5, window_seconds=60, scope="auth:forgot-password"))
    ],
)
async def forgot_password_endpoint(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Inicia el flujo de recuperación de contraseña emitiendo un token temporal (15 min)
    sin filtrar si el correo electrónico existe o no.
    """
    raw_data = await parse_request_payload(request)
    is_html = is_html_form_request(request)

    try:
        forgot_req = ForgotPasswordRequest.model_validate(raw_data)
    except ValidationError as exc:
        err_msg = _format_validation_error(exc)
        if is_html:
            return RedirectResponse(
                url=f"/forgot-password?error={quote(err_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg,
        ) from exc

    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    result = await request_password_reset(
        db=db,
        email=forgot_req.email,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if is_html:
        return RedirectResponse(
            url="/forgot-password?sent=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    payload_out: dict[str, Any] = {
        "message": result["message"],
        "status": "ok",
    }
    if not settings.is_production and result.get("raw_token"):
        payload_out["reset_token"] = result["raw_token"]
    return payload_out


@router.post(
    "/reset-password",
    dependencies=[
        Depends(rate_limit(max_requests=5, window_seconds=60, scope="auth:reset-password"))
    ],
)
async def reset_password_endpoint(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Restablece la contraseña mediante un token SHA-256 de un solo uso válido (< 15 min)
    y revoca todas las sesiones previas del usuario.
    """
    raw_data = await parse_request_payload(request)
    is_html = is_html_form_request(request)

    if is_html and not str(raw_data.get("confirm_password") or "").strip():
        tok = raw_data.get("token") or ""
        return RedirectResponse(
            url=f"/reset-password?token={quote(str(tok))}&error={quote('Debe confirmar la nueva contraseña.')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    try:
        reset_req = ResetPasswordRequest.model_validate(raw_data)
    except ValidationError as exc:
        err_msg = _format_validation_error(exc)
        if is_html:
            tok = raw_data.get("token") or ""
            return RedirectResponse(
                url=f"/reset-password?token={quote(str(tok))}&error={quote(err_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg,
        ) from exc

    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    try:
        await reset_password_with_token(
            db=db,
            raw_token=reset_req.token,
            new_password=reset_req.new_password,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except HTTPException as exc:
        if is_html:
            return RedirectResponse(
                url=f"/reset-password?token={quote(reset_req.token)}&error={quote(str(exc.detail))}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise

    if is_html:
        redirect_resp = RedirectResponse(
            url="/login?reset=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        clear_auth_cookies(redirect_resp)
        return redirect_resp

    clear_auth_cookies(response)
    return {
        "message": "Contraseña actualizada exitosamente. Todas las sesiones anteriores fueron revocadas.",
        "status": "ok",
    }
