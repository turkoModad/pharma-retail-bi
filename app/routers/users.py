"""
Router de Perfil de Usuario y Protección Anti-IDOR (`/users`):
- `GET /users/me`: Retorna el perfil propio con PII descifrada en memoria.
- `PUT /users/me`, `PATCH /users/me` y `POST /users/me/profile`: Actualiza datos personales (Fernet)
  registrando en `audit_logs` únicamente los nombres de los campos modificados (`modified_fields`).
- `POST /users/me/password` y `PUT /users/me/password`: Cambio autenticado de contraseña.
- `GET /users/me/logins`: Historial forense de inicios de sesión y eventos de la cuenta propia.
- `GET|PUT|PATCH /users/{user_id}`: Endpoints protegidos con validación estricta Anti-IDOR
  (`current_user.id == user_id` o rol `admin`, lanzando HTTP 403 y auditando intentos no autorizados).
"""

from __future__ import annotations

import uuid
from typing import Any, List
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError

from app.core.database import AsyncSession, get_db
from app.core.limiter import rate_limit
from app.core.security import decode_access_token, revoke_access_token_jti
from app.models.user import User
from app.routers.dependencies import (
    clear_auth_cookies,
    extract_access_token,
    get_current_user,
    is_html_form_request,
    parse_request_payload,
)
from app.schemas.audit import AuditLogRead
from app.schemas.user import (
    AccountDeleteRequest,
    PasswordChangeRequest,
    UserProfileUpdate,
    UserRead,
)
from app.services.audit_service import extract_client_ip, extract_user_agent
from app.services.user_service import (
    change_own_password,
    delete_own_account,
    enforce_anti_idor,
    get_user_recent_logins,
    update_own_profile,
)

router = APIRouter(prefix="/users", tags=["Perfil de Usuario y Anti-IDOR"])


def _format_validation_error(exc: ValidationError) -> str:
    messages = []
    for err in exc.errors():
        msg = err.get("msg", "Valor inválido")
        loc = ".".join(str(x) for x in err.get("loc", []) if x != "body")
        messages.append(f"{loc}: {msg}" if loc else msg)
    return "; ".join(messages) if messages else "Datos de entrada inválidos."


@router.get("/me", response_model=UserRead)
async def get_my_profile(
    current_user: User = Depends(get_current_user),
) -> UserRead:
    """Retorna los datos del usuario autenticado con sus campos PII descifrados."""
    return UserRead.from_user(current_user)


@router.put("/me", response_model=UserRead)
@router.patch("/me", response_model=UserRead)
@router.post("/me/profile", response_model=UserRead)
async def update_my_profile(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Actualiza los datos del perfil propio (exclusivamente sobre `current_user.id`).
    Cifra PII con Fernet y audita solo `modified_fields` sin valores sensibles.
    """
    raw_data = await parse_request_payload(request)
    raw_data.pop("csrf_token", None)
    is_html = is_html_form_request(request)

    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    injected_id = raw_data.pop("user_id", None) or raw_data.pop("id", None)
    target_uid: uuid.UUID | None = None
    if injected_id:
        try:
            target_uid = uuid.UUID(str(injected_id))
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Identificador de usuario inválido.",
            ) from exc

    try:
        profile_update = UserProfileUpdate.model_validate(raw_data)
    except ValidationError as exc:
        err_msg = _format_validation_error(exc)
        if is_html:
            return RedirectResponse(
                url=f"/profile?error={quote(err_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg,
        ) from exc

    updated_user = await update_own_profile(
        db=db,
        current_user=current_user,
        payload=profile_update,
        target_user_id=target_uid,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    if is_html:
        return RedirectResponse(
            url="/profile?updated=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return UserRead.from_user(updated_user)


@router.post(
    "/me/password",
    dependencies=[Depends(rate_limit(max_requests=5, window_seconds=60, scope="users:password"))],
)
@router.put(
    "/me/password",
    dependencies=[Depends(rate_limit(max_requests=5, window_seconds=60, scope="users:password"))],
)
async def update_my_password(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Actualiza la contraseña del usuario autenticado tras validar la contraseña actual."""
    raw_data = await parse_request_payload(request)
    raw_data.pop("csrf_token", None)

    is_html = is_html_form_request(request)
    if is_html and not str(raw_data.get("confirm_password") or "").strip():
        return RedirectResponse(
            url=f"/profile?error={quote('Debe confirmar la nueva contraseña.')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    try:
        pwd_req = PasswordChangeRequest.model_validate(raw_data)
    except ValidationError as exc:
        err_msg = _format_validation_error(exc)
        if is_html:
            return RedirectResponse(
                url=f"/profile?error={quote(err_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg,
        ) from exc

    try:
        await change_own_password(
            db=db,
            current_user=current_user,
            payload=pwd_req,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except HTTPException as exc:
        if is_html:
            return RedirectResponse(
                url=f"/profile?error={quote(str(exc.detail))}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise

    if is_html:
        return RedirectResponse(
            url="/profile?pwd_changed=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return {
        "message": "Contraseña actualizada exitosamente.",
        "status": "ok",
    }


@router.get("/me/logins", response_model=List[AuditLogRead])
async def get_my_recent_logins(
    limit: int = 15,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> List[AuditLogRead]:
    """Retorna los últimos eventos de acceso y seguridad de la cuenta propia."""
    logs = await get_user_recent_logins(db=db, user_id=current_user.id, limit=limit)
    return [AuditLogRead.model_validate(entry) for entry in logs]


@router.delete(
    "/me",
    dependencies=[Depends(rate_limit(max_requests=5, window_seconds=60, scope="users:delete"))],
)
@router.post(
    "/me/delete",
    dependencies=[Depends(rate_limit(max_requests=5, window_seconds=60, scope="users:delete"))],
)
async def delete_my_account(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Elimina permanentemente la cuenta propia previa doble verificación."""
    raw_data = await parse_request_payload(request)
    raw_data.pop("csrf_token", None)
    is_html = is_html_form_request(request)

    try:
        del_req = AccountDeleteRequest.model_validate(raw_data)
    except ValidationError as exc:
        err_msg = _format_validation_error(exc)
        if is_html:
            return RedirectResponse(
                url=f"/profile?error={quote(err_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg,
        ) from exc

    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    try:
        await delete_own_account(
            db=db,
            current_user=current_user,
            current_password=del_req.current_password,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except HTTPException as exc:
        if is_html:
            return RedirectResponse(
                url=f"/profile?error={quote(str(exc.detail))}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise

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

    if is_html:
        redirect_resp = RedirectResponse(
            url="/login?account_deleted=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        clear_auth_cookies(redirect_resp)
        return redirect_resp

    from fastapi.responses import JSONResponse
    json_resp = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Cuenta eliminada permanentemente.", "status": "ok"},
    )
    clear_auth_cookies(json_resp)
    return json_resp


@router.get("/{user_id}", response_model=UserRead)
async def get_user_by_id_anti_idor(
    user_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    """
    Consulta un usuario por ID verificando estrictamente Anti-IDOR:
    un usuario con rol `user` solo puede consultar su propio `user_id`.
    """
    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    await enforce_anti_idor(
        db=db,
        current_user=current_user,
        target_user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        action="read_user_profile",
    )

    if user_id == current_user.id:
        return UserRead.from_user(current_user)

    target_user = await db.get(User, user_id)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado.",
        )
    return UserRead.from_user(target_user)


@router.put("/{user_id}", response_model=UserRead)
@router.patch("/{user_id}", response_model=UserRead)
@router.post("/{user_id}/profile", response_model=UserRead)
async def update_user_by_id_anti_idor(
    user_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    """
    Actualiza el perfil de un usuario por ID aplicando control estricto Anti-IDOR:
    rechaza con HTTP 403 Forbidden cualquier intento de modificar otro `user_id` por un no-admin.
    """
    ip_address = extract_client_ip(request)
    user_agent = extract_user_agent(request)

    await enforce_anti_idor(
        db=db,
        current_user=current_user,
        target_user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        action="update_user_profile",
    )

    raw_data = await parse_request_payload(request)
    raw_data.pop("csrf_token", None)

    try:
        profile_update = UserProfileUpdate.model_validate(raw_data)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_format_validation_error(exc),
        ) from exc

    target_user = current_user if user_id == current_user.id else await db.get(User, user_id)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado.",
        )

    updated = await update_own_profile(
        db=db,
        current_user=target_user,
        payload=profile_update,
        target_user_id=target_user.id,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return UserRead.from_user(updated)
