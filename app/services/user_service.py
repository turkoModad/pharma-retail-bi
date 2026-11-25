"""
Servicio de Gestión de Perfil Propio (con protección Anti-IDOR y cifrado Fernet de PII)
y Operaciones Administrativas RBAC (`admin_update_user`, consulta de usuarios y bitácora `audit_logs`).
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List

from sqlalchemy import func, select

if TYPE_CHECKING:
    from fastapi import HTTPException, status
else:
    try:
        from fastapi import HTTPException, status
    except ImportError:
        class HTTPException(Exception):
            def __init__(self, status_code: int, detail: Any = None, headers: Dict[str, str] | None = None) -> None:
                super().__init__(str(detail))
                self.status_code = int(status_code)
                self.detail = detail
                self.headers = headers or {}

        class status:
            HTTP_400_BAD_REQUEST = 400
            HTTP_401_UNAUTHORIZED = 401
            HTTP_403_FORBIDDEN = 403
            HTTP_404_NOT_FOUND = 404
            HTTP_409_CONFLICT = 409
            HTTP_422_UNPROCESSABLE_ENTITY = 422

from app.core.database import AsyncSession
from app.core.security import (
    compute_blind_index,
    decrypt_pii,
    encrypt_pii,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.models.audit_log import AuditEventType, AuditLog
from app.models.token import RefreshToken
from app.models.user import User, UserRole
from app.schemas.audit import AuditLogRead
from app.schemas.user import (
    AdminUserUpdate,
    PasswordChangeRequest,
    UserProfileUpdate,
    UserRead,
)
from app.services.audit_service import log_audit_event


async def enforce_anti_idor(
    db: AsyncSession,
    current_user: User,
    target_user_id: uuid.UUID,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
    action: str = "access_or_modify_user",
) -> None:
    """
    Verifica estrictamente que un usuario estándar (`role != 'admin'`) únicamente pueda
    acceder o modificar recursos pertenecientes a su propio `user.id`.
    Si se detecta un intento de IDOR (Insecure Direct Object Reference), registra el incidente
    en `audit_logs` y lanza HTTP 403 Forbidden.
    """
    role_str = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)
    if current_user.id != target_user_id and role_str != UserRole.ADMIN.value:
        await log_audit_event(
            db=db,
            event_type=AuditEventType.ADMIN_ACTION,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=current_user.id,
            details={
                "security_alert": "IDOR_ATTEMPT_BLOCKED",
                "attempted_action": action,
                "target_user_id": str(target_user_id),
            },
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso denegado: no tiene permisos para acceder o modificar recursos de otro usuario.",
        )


async def update_own_profile(
    db: AsyncSession,
    current_user: User,
    payload: UserProfileUpdate,
    target_user_id: uuid.UUID | None = None,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> User:
    """
    Actualiza los datos del perfil propio del usuario autenticado:
    - Valida Anti-IDOR si se especifica `target_user_id`.
    - Cifra cualquier cambio en `phone`, `document_id` y `address` mediante Fernet.
    - Registra en `audit_logs` (`PROFILE_UPDATED`) únicamente la lista de nombres de campos
      modificados (`details={"modified_fields": [...]}`) sin almacenar valores PII en texto plano.
    """
    if target_user_id is not None:
        await enforce_anti_idor(
            db=db,
            current_user=current_user,
            target_user_id=target_user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action="update_profile",
        )

    modified_fields: List[str] = []
    provided_fields = payload.model_fields_set

    if "full_name" in provided_fields and payload.full_name is not None:
        cleaned_name = payload.full_name.strip()
        if cleaned_name and cleaned_name != current_user.full_name:
            current_user.full_name = cleaned_name
            modified_fields.append("full_name")

    if "phone" in provided_fields:
        new_phone = payload.phone.strip() if payload.phone and payload.phone.strip() else None
        try:
            current_phone = decrypt_pii(current_user.phone_encrypted)
        except Exception:
            current_phone = None
        if new_phone != current_phone:
            current_user.phone_encrypted = encrypt_pii(new_phone) if new_phone else None
            modified_fields.append("phone")

    if "document_id" in provided_fields:
        new_doc = (
            payload.document_id.strip()
            if payload.document_id and payload.document_id.strip()
            else None
        )
        try:
            current_doc = decrypt_pii(current_user.document_id_encrypted)
        except Exception:
            current_doc = None
        if new_doc != current_doc:
            current_user.document_id_encrypted = encrypt_pii(new_doc) if new_doc else None
            modified_fields.append("document_id")

    if "address" in provided_fields:
        new_addr = payload.address.strip() if payload.address and payload.address.strip() else None
        try:
            current_addr = decrypt_pii(current_user.address_encrypted)
        except Exception:
            current_addr = None
        if new_addr != current_addr:
            current_user.address_encrypted = encrypt_pii(new_addr) if new_addr else None
            modified_fields.append("address")

    current_user.updated_at = datetime.now(timezone.utc)

    await log_audit_event(
        db=db,
        event_type=AuditEventType.PROFILE_UPDATED,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=current_user.id,
        details={"modified_fields": modified_fields},
    )

    await db.commit()
    await db.refresh(current_user)
    return current_user


async def change_own_password(
    db: AsyncSession,
    current_user: User,
    payload: PasswordChangeRequest,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> User:
    """
    Cambia la contraseña del usuario autenticado tras verificar su contraseña actual,
    aplicar validación de fortaleza y hashear con Argon2id.
    """
    if not verify_password(payload.current_password, current_user.password_hash):
        await log_audit_event(
            db=db,
            event_type=AuditEventType.LOGIN_FAILED,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=current_user.id,
            details={"reason": "invalid_current_password_on_change"},
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La contraseña actual ingresada es incorrecta.",
        )

    try:
        validate_password_strength(payload.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    now = datetime.now(timezone.utc)
    current_user.password_hash = hash_password(payload.new_password)
    current_user.token_version = int(getattr(current_user, "token_version", 1) or 1) + 1
    current_user.updated_at = now

    await log_audit_event(
        db=db,
        event_type=AuditEventType.PASSWORD_CHANGED,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=current_user.id,
        details={
            "method": "authenticated_password_change",
            "modified_fields": ["password"],
        },
    )

    await db.commit()
    await db.refresh(current_user)
    return current_user


async def get_user_recent_logins(
    db: AsyncSession,
    user_id: uuid.UUID,
    limit: int = 15,
) -> List[AuditLog]:
    """
    Obtiene los registros de actividad y accesos recientes (`LOGIN_SUCCESS`, `LOGIN_FAILED`,
    `LOGOUT`, `PASSWORD_CHANGED`, `PROFILE_UPDATED`, `EMAIL_VERIFIED`) para la vista de perfil.
    """
    stmt = (
        select(AuditLog)
        .where(AuditLog.user_id == user_id)
        .order_by(AuditLog.created_at.desc())
        .limit(max(1, min(limit, 100)))
    )
    result = await db.scalars(stmt)
    return list(result.all())


async def list_all_users(
    db: AsyncSession,
    limit: int = 200,
    offset: int = 0,
) -> List[User]:
    """Lista los usuarios registrados ordenados por fecha de creación descendente."""
    stmt = (
        select(User)
        .order_by(User.created_at.desc())
        .offset(max(0, offset))
        .limit(max(1, min(limit, 500)))
    )
    result = await db.scalars(stmt)
    return list(result.all())


async def list_users_with_summary(
    db: AsyncSession,
    search: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
    limit: int = 200,
    offset: int = 0,
) -> Dict[str, Any]:
    """
    Lista usuarios descifrados con resumen global (`total`, `admins`, `active`, `disabled`)
    y filtrado en memoria sobre correo/nombre descifrados.
    """
    all_users = list((await db.scalars(select(User).order_by(User.created_at.desc()))).all())

    total = len(all_users)
    admins = 0
    active = 0
    disabled = 0

    norm_search = (search or "").strip().lower()
    norm_role = role.strip().lower() if role and role.strip() else None

    filtered: List[UserRead] = []
    for u in all_users:
        u_role = u.role.value if hasattr(u.role, "value") else str(u.role)
        u_active = bool(u.is_active)
        if u_role == UserRole.ADMIN.value:
            admins += 1
        if u_active:
            active += 1
        else:
            disabled += 1

        if norm_role and u_role != norm_role:
            continue
        if is_active is not None and u_active != is_active:
            continue

        u_read = UserRead.from_user(u)
        if norm_search:
            haystack = f"{u_read.email} {u_read.full_name} {u_read.id}".lower()
            if norm_search not in haystack:
                continue
        filtered.append(u_read)

    safe_offset = max(0, int(offset or 0))
    safe_limit = max(1, min(int(limit or 200), 500))
    paginated = filtered[safe_offset : safe_offset + safe_limit]

    return {
        "summary": {
            "total": total,
            "admins": admins,
            "active": active,
            "disabled": disabled,
        },
        "total_filtered": len(filtered),
        "users": paginated,
    }


async def _count_active_admins(db: AsyncSession) -> int:
    stmt = select(func.count()).select_from(User).where(
        User.role == UserRole.ADMIN.value,
        User.is_active.is_(True),
    )
    return int((await db.scalar(stmt)) or 0)


async def admin_update_user(
    db: AsyncSession,
    admin_user: User,
    target_user_id: uuid.UUID,
    payload: AdminUserUpdate,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> User:
    """
    Ejecuta acciones administrativas sobre un usuario objetivo:
    - Cambio de rol RBAC (`user` / `admin`) protegiendo al último admin activo.
    - Activación o desactivación de cuenta (`is_active`) impidiendo auto-deshabilitación
      y revocando inmediatamente todos sus `refresh_tokens` y JWTs activos.
    - Cambio de correo electrónico validando formato, normalización y unicidad.
    - Verificación manual de correo (`is_verified`).
    - Desbloqueo manual de cuenta (`failed_login_attempts = 0`, `locked_until = None`).
    Registra siempre `ADMIN_ACTION` en `audit_logs`.
    """
    admin_role = admin_user.role.value if hasattr(admin_user.role, "value") else str(admin_user.role)
    if admin_role != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requieren privilegios de administrador para realizar esta operación.",
        )

    target_user = await db.get(User, target_user_id)
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="El usuario especificado no existe.",
        )

    now = datetime.now(timezone.utc)
    changes: Dict[str, Any] = {"admin_user_id": str(admin_user.id)}
    modified_fields: List[str] = []

    target_prev_role = (
        target_user.role.value if hasattr(target_user.role, "value") else str(target_user.role)
    )
    target_prev_active = bool(target_user.is_active)

    if payload.is_active is False and target_user.id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No puede deshabilitar su propia cuenta de administrador.",
        )

    will_deactivate_admin = (
        target_prev_role == UserRole.ADMIN.value
        and target_prev_active
        and (
            payload.is_active is False
            or (payload.role is not None and payload.role.strip().lower() == UserRole.USER.value)
        )
    )
    if will_deactivate_admin:
        active_admins_count = await _count_active_admins(db)
        if active_admins_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Operación bloqueada: debe permanecer al menos un administrador activo en el sistema.",
            )

    if payload.email is not None:
        new_email = payload.email.strip().lower()
        new_email_hash = compute_blind_index(new_email)
        conflict_stmt = select(User).where(
            User.email_hash == new_email_hash,
            User.id != target_user.id,
        )
        conflict_user = await db.scalar(conflict_stmt)
        if conflict_user is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Ya existe otro usuario registrado con ese correo electrónico.",
            )
        prev_email = target_user.email
        if new_email != prev_email:
            target_user.email = new_email
            changes["action"] = "email_changed"
            changes["previous_email"] = prev_email
            changes["new_email"] = new_email
            modified_fields.append("email")

    if payload.role is not None:
        new_role = payload.role.strip().lower()
        if new_role not in (UserRole.USER.value, UserRole.ADMIN.value):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Rol inválido. Valores permitidos: 'user', 'admin'.",
            )
        if new_role != target_prev_role:
            target_user.role = new_role
            target_user.token_version = int(getattr(target_user, "token_version", 1) or 1) + 1
            changes["action"] = changes.get("action", "role_changed")
            changes["previous_role"] = target_prev_role
            changes["new_role"] = new_role
            modified_fields.append("role")

    if payload.is_active is not None:
        if bool(payload.is_active) != target_prev_active:
            target_user.is_active = bool(payload.is_active)
            changes["action"] = changes.get("action", "status_changed")
            changes["previous_is_active"] = target_prev_active
            changes["new_is_active"] = bool(payload.is_active)
            modified_fields.append("is_active")

            if not target_user.is_active:
                target_user.token_version = int(getattr(target_user, "token_version", 1) or 1) + 1
                active_tokens_stmt = select(RefreshToken).where(
                    RefreshToken.user_id == target_user.id,
                    RefreshToken.is_revoked.is_(False),
                )
                revoked_count = 0
                for tok in (await db.scalars(active_tokens_stmt)).all():
                    tok.is_revoked = True
                    tok.revoked_at = now
                    revoked_count += 1
                changes["revoked_active_sessions"] = True
                changes["revoked_tokens_count"] = revoked_count

    if payload.is_verified is not None:
        prev_verified = bool(target_user.is_verified)
        if bool(payload.is_verified) != prev_verified:
            target_user.is_verified = bool(payload.is_verified)
            changes["action"] = changes.get("action", "manual_verification")
            changes["previous_is_verified"] = prev_verified
            changes["new_is_verified"] = bool(payload.is_verified)
            modified_fields.append("is_verified")

    if payload.unlock_account:
        prev_attempts = int(target_user.failed_login_attempts or 0)
        was_locked = target_user.locked_until is not None
        target_user.failed_login_attempts = 0
        target_user.locked_until = None
        changes["action"] = changes.get("action", "account_unlocked")
        changes["unlocked_account"] = True
        changes["previous_failed_attempts"] = prev_attempts
        changes["was_locked"] = was_locked
        modified_fields.extend(["failed_login_attempts", "locked_until"])

    target_user.updated_at = now

    await log_audit_event(
        db=db,
        event_type=AuditEventType.ADMIN_ACTION,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=admin_user.id,
        details={
            "target_user_id": str(target_user.id),
            "modified_fields": modified_fields,
            "changes": changes,
        },
    )

    await db.commit()
    await db.refresh(target_user)
    return target_user


async def list_audit_logs(
    db: AsyncSession,
    limit: int = 100,
    offset: int = 0,
    event_type: str | None = None,
    user_id: uuid.UUID | None = None,
) -> List[AuditLog]:
    """Consulta los eventos de auditoría más recientes con filtros opcionales."""
    stmt = select(AuditLog)
    if event_type:
        stmt = stmt.where(AuditLog.event_type == event_type.strip().upper())
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)

    stmt = (
        stmt.order_by(AuditLog.created_at.desc())
        .offset(max(0, offset))
        .limit(max(1, min(limit, 500)))
    )
    result = await db.scalars(stmt)
    return list(result.all())


async def list_audit_logs_paginated(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 25,
    event_type: str | None = None,
    user_query: str | None = None,
    ip_address: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> Dict[str, Any]:
    """
    Visor forense paginado (25 registros por página) sobre `audit_logs`
    con filtros combinables y enriquecimiento de correo/nombre de usuario.
    """
    safe_page = max(1, int(page or 1))
    safe_size = max(1, min(int(page_size or 25), 100))

    all_users = list((await db.scalars(select(User))).all())
    user_lookup: Dict[uuid.UUID, tuple[str, str]] = {}
    for u in all_users:
        try:
            user_lookup[u.id] = (u.email, u.full_name)
        except Exception:
            user_lookup[u.id] = ("", "")

    stmt = select(AuditLog)
    count_stmt = select(func.count()).select_from(AuditLog)

    conditions = []
    if event_type and event_type.strip():
        conditions.append(AuditLog.event_type == event_type.strip().upper())

    if ip_address and ip_address.strip():
        ip_pat = f"%{ip_address.strip()}%"
        conditions.append(AuditLog.ip_address.ilike(ip_pat))

    if date_from and date_from.strip():
        try:
            d_from = date.fromisoformat(date_from.strip()[:10])
            dt_from = datetime(d_from.year, d_from.month, d_from.day, 0, 0, 0, tzinfo=timezone.utc)
            conditions.append(AuditLog.created_at >= dt_from)
        except ValueError:
            pass

    if date_to and date_to.strip():
        try:
            d_to = date.fromisoformat(date_to.strip()[:10])
            dt_to = datetime(d_to.year, d_to.month, d_to.day, 23, 59, 59, 999999, tzinfo=timezone.utc)
            conditions.append(AuditLog.created_at <= dt_to)
        except ValueError:
            pass

    cleaned_user_q = (user_query or "").strip().lower()
    if cleaned_user_q:
        matching_ids: List[uuid.UUID] = []
        for uid, (u_email, u_name) in user_lookup.items():
            if (
                cleaned_user_q in u_email.lower()
                or cleaned_user_q in u_name.lower()
                or cleaned_user_q in str(uid).lower()
            ):
                matching_ids.append(uid)
        if matching_ids:
            conditions.append(AuditLog.user_id.in_(matching_ids))
        else:
            # No hay usuarios que coincidan -> forzar resultado vacío determinista
            conditions.append(AuditLog.id.is_(None))

    if conditions:
        stmt = stmt.where(*conditions)
        count_stmt = count_stmt.where(*conditions)

    total = int((await db.scalar(count_stmt)) or 0)
    total_pages = max(1, (total + safe_size - 1) // safe_size) if total > 0 else 1
    if safe_page > total_pages:
        safe_page = total_pages
    offset = (safe_page - 1) * safe_size

    rows = list(
        (
            await db.scalars(
                stmt.order_by(AuditLog.created_at.desc())
                .offset(offset)
                .limit(safe_size)
            )
        ).all()
    )

    items: List[AuditLogRead] = []
    for entry in rows:
        item = AuditLogRead.model_validate(entry)
        if entry.user_id and entry.user_id in user_lookup:
            u_email, u_name = user_lookup[entry.user_id]
            item.user_email = u_email or None
            item.user_name = u_name or None
        items.append(item)

    return {
        "items": items,
        "total": total,
        "page": safe_page,
        "page_size": safe_size,
        "total_pages": total_pages,
        "event_types": [e.value for e in AuditEventType],
    }


async def revoke_all_user_sessions(
    db: AsyncSession,
    current_user: User,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> int:
    """
    Revoca todos los Refresh Tokens vigentes del usuario autenticado e incrementa
    `token_version` para invalidar sesiones activas en otros dispositivos.
    """
    now = datetime.now(timezone.utc)
    tokens_stmt = select(RefreshToken).where(
        RefreshToken.user_id == current_user.id,
        RefreshToken.is_revoked.is_(False),
    )
    active_tokens = list((await db.scalars(tokens_stmt)).all())
    for tok in active_tokens:
        tok.is_revoked = True
        tok.revoked_at = now

    current_user.token_version = int(getattr(current_user, "token_version", 1) or 1) + 1
    current_user.updated_at = now

    await log_audit_event(
        db=db,
        event_type=AuditEventType.LOGOUT,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=current_user.id,
        details={
            "action": "revoke_all_sessions",
            "revoked_tokens_count": len(active_tokens),
        },
    )
    await db.commit()
    return len(active_tokens)


async def delete_own_account(
    db: AsyncSession,
    current_user: User,
    current_password: str,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> None:
    """
    Elimina permanentemente la cuenta propia previa verificación de la contraseña actual,
    revocando todos los tokens de refresco y registrando el evento de auditoría.
    """
    if not verify_password(current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="La contraseña actual es incorrecta.",
        )

    now = datetime.now(timezone.utc)
    current_user.token_version = int(getattr(current_user, "token_version", 1) or 1) + 1
    tokens_stmt = select(RefreshToken).where(
        RefreshToken.user_id == current_user.id,
        RefreshToken.is_revoked.is_(False),
    )
    active_tokens = (await db.scalars(tokens_stmt)).all()
    for tok in active_tokens:
        tok.is_revoked = True
        tok.revoked_at = now

    await log_audit_event(
        db=db,
        event_type=AuditEventType.ACCOUNT_DELETED,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=current_user.id,
        details={"deleted_self": True, "revoked_tokens_count": len(active_tokens)},
    )

    await db.delete(current_user)
    await db.commit()
