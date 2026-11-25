"""
Router de Administración RBAC, Auditoría Forense y Analítica Ejecutiva (`/admin`, `/api/admin`).

Todos los endpoints exigen el rol `admin` mediante la dependencia `require_admin`
(retornando HTTP 403 Forbidden ante usuarios con rol `user`).
"""

from __future__ import annotations

import uuid
from typing import Any, List
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError

from app.core.database import AsyncSession, get_db
from app.models.user import User
from app.routers.dependencies import (
    is_html_form_request,
    parse_request_payload,
    require_admin,
)
from app.schemas.audit import AuditLogRead
from app.schemas.user import AdminEmailUpdate, AdminUserUpdate, UserRead
from app.services.analytics_service import (
    get_compras_analytics,
    get_drogas_comparison,
    get_productos_analytics,
)
from app.services.audit_service import extract_client_ip, extract_user_agent
from app.services.user_service import (
    admin_update_user,
    list_audit_logs,
    list_audit_logs_paginated,
    list_users_with_summary,
)

router = APIRouter(tags=["Administración RBAC y Auditoría"])


def _parse_bool_flag(val: Any) -> bool | None:
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    norm = str(val).strip().lower()
    if norm in ("true", "1", "yes", "on"):
        return True
    if norm in ("false", "0", "no", "off"):
        return False
    return None


@router.get("/admin/users", response_model=List[UserRead])
@router.get("/admin/api/users", response_model=List[UserRead])
@router.get("/api/admin/users", response_model=List[UserRead])
async def admin_list_users_endpoint(
    limit: int = 200,
    offset: int = 0,
    search: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> List[UserRead]:
    """Lista los usuarios del sistema con filtros opcionales (exclusivo rol `admin`)."""
    result = await list_users_with_summary(
        db=db,
        search=search,
        role=role,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )
    return result["users"]


@router.get("/api/admin/users/overview")
async def admin_users_overview_endpoint(
    limit: int = 200,
    offset: int = 0,
    search: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Retorna tarjetas de resumen (*Total*, *Admins*, *Activos*, *Deshabilitados*) y usuarios filtrados."""
    result = await list_users_with_summary(
        db=db,
        search=search,
        role=role,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )
    return {
        "summary": result["summary"],
        "total_filtered": result["total_filtered"],
        "users": [u.model_dump(mode="json") for u in result["users"]],
    }


@router.get("/admin/audit-logs", response_model=List[AuditLogRead])
@router.get("/admin/api/audit-logs", response_model=List[AuditLogRead])
@router.get("/api/admin/audit-logs", response_model=List[AuditLogRead])
@router.get("/admin/logs", response_model=List[AuditLogRead])
async def admin_list_audit_logs_endpoint(
    limit: int = 100,
    offset: int = 0,
    event_type: str | None = None,
    user_id: uuid.UUID | None = None,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> List[AuditLogRead]:
    """Consulta la bitácora forense `audit_logs` (exclusivo rol `admin`)."""
    logs = await list_audit_logs(
        db=db,
        limit=limit,
        offset=offset,
        event_type=event_type,
        user_id=user_id,
    )
    return [AuditLogRead.model_validate(entry) for entry in logs]


@router.get("/api/admin/logs")
async def admin_paginated_logs_endpoint(
    page: int = 1,
    page_size: int = 25,
    event_type: str | None = None,
    user: str | None = None,
    ip: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    Visor forense paginado (25 registros por página) sobre `audit_logs`
    con filtros combinables por evento, usuario/correo, IP y rango de fechas.
    """
    result = await list_audit_logs_paginated(
        db=db,
        page=page,
        page_size=page_size,
        event_type=event_type,
        user_query=user,
        ip_address=ip,
        date_from=date_from,
        date_to=date_to,
    )
    return {
        "items": [item.model_dump(mode="json") for item in result["items"]],
        "total": result["total"],
        "page": result["page"],
        "page_size": result["page_size"],
        "total_pages": result["total_pages"],
        "event_types": result["event_types"],
    }


@router.patch("/admin/users/{user_id}", response_model=UserRead)
@router.put("/admin/users/{user_id}", response_model=UserRead)
@router.post("/admin/users/{user_id}", response_model=UserRead)
@router.patch("/admin/api/users/{user_id}", response_model=UserRead)
@router.put("/admin/api/users/{user_id}", response_model=UserRead)
@router.patch("/api/admin/users/{user_id}", response_model=UserRead)
@router.put("/api/admin/users/{user_id}", response_model=UserRead)
@router.post("/api/admin/users/{user_id}", response_model=UserRead)
async def admin_update_user_endpoint(
    user_id: uuid.UUID,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Actualiza rol (`user`/`admin`), estado (`is_active`), correo (`email`),
    verificación (`is_verified`) o desbloquea una cuenta (`unlock_account`).
    """
    raw_data = await parse_request_payload(request)
    raw_data.pop("csrf_token", None)
    is_html = is_html_form_request(request)

    try:
        update_payload = AdminUserUpdate(
            role=raw_data.get("role"),
            is_active=_parse_bool_flag(raw_data.get("is_active")),
            is_verified=_parse_bool_flag(raw_data.get("is_verified")),
            email=raw_data.get("email"),
            unlock_account=bool(_parse_bool_flag(raw_data.get("unlock_account")) or False),
        )
    except ValidationError as exc:
        err_msg = "; ".join(err.get("msg", "Error") for err in exc.errors())
        if is_html:
            return RedirectResponse(
                url=f"/admin?error={quote(err_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg,
        ) from exc

    updated_user = await admin_update_user(
        db=db,
        admin_user=admin_user,
        target_user_id=user_id,
        payload=update_payload,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )

    if is_html:
        return RedirectResponse(
            url="/admin?updated=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return UserRead.from_user(updated_user)


@router.post("/admin/users/{user_id}/status", response_model=UserRead)
@router.patch("/admin/users/{user_id}/status", response_model=UserRead)
@router.put("/admin/users/{user_id}/status", response_model=UserRead)
@router.post("/api/admin/users/{user_id}/status", response_model=UserRead)
@router.patch("/api/admin/users/{user_id}/status", response_model=UserRead)
@router.put("/api/admin/users/{user_id}/status", response_model=UserRead)
async def admin_change_user_status(
    user_id: uuid.UUID,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Activa o desactiva la cuenta de un usuario, revocando sesiones al suspender."""
    raw_data = await parse_request_payload(request)
    is_active_flag = _parse_bool_flag(raw_data.get("is_active"))
    if is_active_flag is None:
        target = await db.get(User, user_id)
        if target is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado.",
            )
        is_active_flag = not bool(target.is_active)

    updated = await admin_update_user(
        db=db,
        admin_user=admin_user,
        target_user_id=user_id,
        payload=AdminUserUpdate(is_active=is_active_flag),
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )

    if is_html_form_request(request):
        return RedirectResponse(
            url="/admin?status_updated=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return UserRead.from_user(updated)


@router.post("/admin/users/{user_id}/email", response_model=UserRead)
@router.patch("/admin/users/{user_id}/email", response_model=UserRead)
@router.put("/admin/users/{user_id}/email", response_model=UserRead)
@router.post("/api/admin/users/{user_id}/email", response_model=UserRead)
@router.patch("/api/admin/users/{user_id}/email", response_model=UserRead)
@router.put("/api/admin/users/{user_id}/email", response_model=UserRead)
async def admin_change_user_email(
    user_id: uuid.UUID,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Actualiza el correo electrónico de un usuario validando formato, unicidad y auditoría."""
    raw_data = await parse_request_payload(request)
    is_html = is_html_form_request(request)

    try:
        email_req = AdminEmailUpdate(email=raw_data.get("email", ""))
    except ValidationError as exc:
        err_msg = "; ".join(err.get("msg", "Correo inválido") for err in exc.errors())
        if is_html:
            return RedirectResponse(
                url=f"/admin?error={quote(err_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg,
        ) from exc

    updated = await admin_update_user(
        db=db,
        admin_user=admin_user,
        target_user_id=user_id,
        payload=AdminUserUpdate(email=email_req.email),
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )

    if is_html:
        return RedirectResponse(
            url="/admin?updated=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return UserRead.from_user(updated)


@router.post("/admin/users/{user_id}/role", response_model=UserRead)
@router.patch("/admin/users/{user_id}/role", response_model=UserRead)
@router.put("/admin/users/{user_id}/role", response_model=UserRead)
@router.post("/api/admin/users/{user_id}/role", response_model=UserRead)
@router.patch("/api/admin/users/{user_id}/role", response_model=UserRead)
@router.put("/api/admin/users/{user_id}/role", response_model=UserRead)
async def admin_change_user_role(
    user_id: uuid.UUID,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Cambia el rol RBAC (`user` / `admin`) de un usuario protegiendo al último admin."""
    raw_data = await parse_request_payload(request)
    role_val = raw_data.get("role")
    is_html = is_html_form_request(request)

    try:
        payload = AdminUserUpdate(role=str(role_val) if role_val is not None else "")
    except ValidationError as exc:
        err_msg = "; ".join(err.get("msg", "Rol inválido") for err in exc.errors())
        if is_html:
            return RedirectResponse(
                url=f"/admin?error={quote(err_msg)}",
                status_code=status.HTTP_303_SEE_OTHER,
            )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=err_msg,
        ) from exc

    updated = await admin_update_user(
        db=db,
        admin_user=admin_user,
        target_user_id=user_id,
        payload=payload,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )

    if is_html:
        return RedirectResponse(
            url="/admin?role_updated=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return UserRead.from_user(updated)


@router.post("/admin/users/{user_id}/verify", response_model=UserRead)
@router.patch("/admin/users/{user_id}/verify", response_model=UserRead)
@router.put("/admin/users/{user_id}/verify", response_model=UserRead)
@router.post("/api/admin/users/{user_id}/verify", response_model=UserRead)
@router.patch("/api/admin/users/{user_id}/verify", response_model=UserRead)
@router.put("/api/admin/users/{user_id}/verify", response_model=UserRead)
async def admin_verify_user_email(
    user_id: uuid.UUID,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Marca manualmente como verificado (o no verificado) el correo de un usuario."""
    raw_data = await parse_request_payload(request)
    is_verified_flag = _parse_bool_flag(raw_data.get("is_verified"))
    if is_verified_flag is None:
        is_verified_flag = True

    updated = await admin_update_user(
        db=db,
        admin_user=admin_user,
        target_user_id=user_id,
        payload=AdminUserUpdate(is_verified=is_verified_flag),
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )

    if is_html_form_request(request):
        return RedirectResponse(
            url="/admin?updated=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return UserRead.from_user(updated)


@router.post("/admin/users/{user_id}/unlock", response_model=UserRead)
@router.patch("/admin/users/{user_id}/unlock", response_model=UserRead)
@router.put("/admin/users/{user_id}/unlock", response_model=UserRead)
@router.post("/api/admin/users/{user_id}/unlock", response_model=UserRead)
@router.patch("/api/admin/users/{user_id}/unlock", response_model=UserRead)
@router.put("/api/admin/users/{user_id}/unlock", response_model=UserRead)
async def admin_unlock_user_account(
    user_id: uuid.UUID,
    request: Request,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Desbloquea manualmente una cuenta bloqueada por fuerza bruta, reseteando
    `failed_login_attempts = 0` y `locked_until = None`, y audita `ADMIN_ACTION`.
    """
    updated = await admin_update_user(
        db=db,
        admin_user=admin_user,
        target_user_id=user_id,
        payload=AdminUserUpdate(unlock_account=True),
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )

    if is_html_form_request(request):
        return RedirectResponse(
            url="/admin?unlocked=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return UserRead.from_user(updated)


@router.get("/api/admin/analytics/compras")
async def admin_analytics_compras_endpoint(
    group_by: str = "year",
    date_from: str | None = None,
    date_to: str | None = None,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """KPIs ejecutivos y serie temporal de compras agrupada por año (defecto), mes o día."""
    return await get_compras_analytics(
        db=db,
        group_by=group_by,
        date_from=date_from,
        date_to=date_to,
    )


@router.get("/api/admin/analytics/productos")
async def admin_analytics_productos_endpoint(
    mode: str = "last_purchase",
    search: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = 1,
    page_size: int = 20,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Explorador paginado de productos por última compra o ranking de más comprados."""
    return await get_productos_analytics(
        db=db,
        mode=mode,
        search=search,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
    )


@router.get("/api/admin/analytics/drogas")
async def admin_analytics_drogas_endpoint(
    droga: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    admin_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Buscador de principios activos y comparador de precios por droga entre marcas."""
    return await get_drogas_comparison(
        db=db,
        droga=droga,
        q=q,
        date_from=date_from,
        date_to=date_to,
    )
