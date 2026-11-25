"""
Servicio de Autenticación, Gestión de Sesiones (JWT + Refresh Token Rotation),
Detección de Reúso de Tokens, Protección contra Fuerza Bruta y Recuperación de Cuenta.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, Tuple

from sqlalchemy import select

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
            HTTP_422_UNPROCESSABLE_ENTITY = 422

from app.core.config import settings
from app.core.database import AsyncSession
from app.core.security import (
    compute_blind_index,
    create_access_token,
     encrypt_pii,
    generate_csrf_token,
    generate_one_time_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    validate_password_strength,
    verify_password,
)
from app.models.audit_log import AuditEventType
from app.models.token import OneTimeToken, OneTimeTokenType, RefreshToken
from app.models.user import User, UserRole
from app.schemas.user import UserCreate
from app.services.audit_service import log_audit_event
from app.services.email_service import (
    send_password_reset_email,
    send_verification_email,
)

_DUMMY_ARGON2_HASH: str = hash_password("TimingDefense!DummySecret#2026")

GENERIC_LOGIN_ERROR = "Credenciales inválidas o cuenta no disponible."
GENERIC_RESET_MESSAGE = (
    "Si el correo proporcionado se encuentra registrado, recibirá un enlace "
    "temporal para restablecer su contraseña."
)


async def register_user(
    db: AsyncSession,
    payload: UserCreate,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> Tuple[User, str, Dict[str, Any]]:
    """
    Registra un nuevo usuario:
    - Verifica unicidad mediante Blind Index (`email_hash = compute_blind_index(email)`).
    - Valida fortaleza de contraseña y aplica hashing Argon2id.
    - Cifra campos PII (`phone`, `document_id`, `address`) con Fernet.
    - Emite token de verificación de un solo uso (SHA-256 en DB, expiración 15 min).
    - Registra evento `REGISTER` en `audit_logs` y despacha correo/fallback.
    """
    normalized_email = payload.email.strip().lower()
    email_hash = compute_blind_index(normalized_email)

    existing_stmt = select(User).where(User.email_hash == email_hash)
    existing_user = await db.scalar(existing_stmt)
    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fue posible completar el registro: el correo electrónico ya se encuentra registrado.",
        )

    validate_password_strength(payload.password)
    password_hashed = hash_password(payload.password)

    user = User(
        email=normalized_email,
        email_hash=email_hash,
        password_hash=password_hashed,
        full_name=payload.full_name.strip(),
        phone_encrypted=encrypt_pii(payload.phone.strip()) if payload.phone and payload.phone.strip() else None,
        document_id_encrypted=(
            encrypt_pii(payload.document_id.strip())
            if payload.document_id and payload.document_id.strip()
            else None
        ),
        address_encrypted=(
            encrypt_pii(payload.address.strip())
            if payload.address and payload.address.strip()
            else None
        ),
        role=UserRole.USER.value,
        is_active=True,
        is_verified=False,
        failed_login_attempts=0,
        locked_until=None,
    )
    db.add(user)
    await db.flush()

    raw_token, token_sha256, expires_at = generate_one_time_token()
    verification_token = OneTimeToken(
        user_id=user.id,
        token_hash=token_sha256,
        token_type=OneTimeTokenType.EMAIL_VERIFICATION.value,
        is_used=False,
        expires_at=expires_at,
        requested_ip=ip_address,
    )
    db.add(verification_token)

    await log_audit_event(
        db=db,
        event_type=AuditEventType.REGISTER,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=user.id,
        details={
            "role": user.role,
            "verification_token_issued": True,
            "pii_fields_encrypted": [
                field_name
                for field_name, val in (
                    ("phone", payload.phone),
                    ("document_id", payload.document_id),
                    ("address", payload.address),
                )
                if val and val.strip()
            ],
        },
    )

    await db.commit()
    await db.refresh(user)

    email_info = send_verification_email(
        email=user.email,
        full_name=user.full_name,
        raw_token=raw_token,
    )
    return user, raw_token, email_info


async def verify_email_token(
    db: AsyncSession,
    raw_token: str,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> User:
    """
    Verifica una cuenta de usuario mediante el token de un solo uso enviado por email.
    Comprueba existencia por hash SHA-256, que no haya sido usado (`is_used == False`)
    y que no haya superado la ventana de 15 minutos (`not is_expired`).
    """
    if not raw_token or not raw_token.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El token de verificación es obligatorio.",
        )

    token_sha256 = hash_token(raw_token.strip())
    stmt = select(OneTimeToken).where(
        OneTimeToken.token_hash == token_sha256,
        OneTimeToken.token_type == OneTimeTokenType.EMAIL_VERIFICATION.value,
    )
    token_record = await db.scalar(stmt)

    if token_record is None or token_record.is_used or token_record.is_expired:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El enlace de verificación es inválido, ya fue utilizado o ha expirado.",
        )

    user = await db.get(User, token_record.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cuenta de usuario no disponible para verificación.",
        )

    now = datetime.now(timezone.utc)
    token_record.is_used = True
    token_record.used_at = now
    user.is_verified = True
    user.updated_at = now

    await log_audit_event(
        db=db,
        event_type=AuditEventType.EMAIL_VERIFIED,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=user.id,
        details={"token_id": str(token_record.id)},
    )

    await db.commit()
    await db.refresh(user)
    return user


async def authenticate_user(
    db: AsyncSession,
    email: str,
    password: str,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> Dict[str, Any]:
    """
    Autentica a un usuario aplicando:
    - Búsqueda por Blind Index (`email_hash`).
    - Mitigación de enumeración de usuarios (mensajes genéricos y comparación Argon2id dummy).
    - Política de bloqueo temporal (5 intentos fallidos -> bloqueo de 15 minutos en `locked_until`).
    - Emisión de Access Token (30 min) y Refresh Token (7 días) con `family_id`.
    """
    normalized_email = (email or "").strip().lower()
    email_hash = compute_blind_index(normalized_email)

    stmt = select(User).where(User.email_hash == email_hash)
    user = await db.scalar(stmt)

    if user is None:
        verify_password(password or "", _DUMMY_ARGON2_HASH)
        await log_audit_event(
            db=db,
            event_type=AuditEventType.LOGIN_FAILED,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=None,
            details={
                "reason": "user_not_found",
                "email_hash_prefix": email_hash[:12],
            },
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=GENERIC_LOGIN_ERROR,
        )

    if not user.is_active:
        verify_password(password or "", _DUMMY_ARGON2_HASH)
        await log_audit_event(
            db=db,
            event_type=AuditEventType.LOGIN_FAILED,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=user.id,
            details={"reason": "account_inactive"},
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=GENERIC_LOGIN_ERROR,
        )

    now = datetime.now(timezone.utc)

    if user.is_locked:
        await log_audit_event(
            db=db,
            event_type=AuditEventType.LOGIN_FAILED,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=user.id,
            details={
                "reason": "account_locked",
                "locked_until": user.locked_until.isoformat() if user.locked_until else None,
            },
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "La cuenta se encuentra bloqueada temporalmente por múltiples intentos "
                "fallidos de inicio de sesión. Intente nuevamente más tarde."
            ),
        )

    if user.locked_until is not None and not user.is_locked:
        user.locked_until = None
        user.failed_login_attempts = 0

    is_valid_password = verify_password(password or "", user.password_hash)
    if not is_valid_password:
        user.failed_login_attempts = int(user.failed_login_attempts or 0) + 1
        user.updated_at = now
        max_attempts = int(settings.MAX_FAILED_LOGIN_ATTEMPTS)

        if user.failed_login_attempts >= max_attempts:
            lock_minutes = int(settings.ACCOUNT_LOCKOUT_MINUTES)
            user.locked_until = now + timedelta(minutes=lock_minutes)

            await log_audit_event(
                db=db,
                event_type=AuditEventType.LOGIN_FAILED,
                ip_address=ip_address,
                user_agent=user_agent,
                user_id=user.id,
                details={
                    "reason": "invalid_password",
                    "failed_attempts": user.failed_login_attempts,
                },
            )
            await log_audit_event(
                db=db,
                event_type=AuditEventType.ACCOUNT_LOCKED,
                ip_address=ip_address,
                user_agent=user_agent,
                user_id=user.id,
                details={
                    "failed_attempts": user.failed_login_attempts,
                    "lockout_minutes": lock_minutes,
                    "locked_until": user.locked_until.isoformat(),
                },
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Cuenta bloqueada temporalmente durante {lock_minutes} minutos "
                    f"tras alcanzar {max_attempts} intentos fallidos."
                ),
            )

        await log_audit_event(
            db=db,
            event_type=AuditEventType.LOGIN_FAILED,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=user.id,
            details={
                "reason": "invalid_password",
                "failed_attempts": user.failed_login_attempts,
            },
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=GENERIC_LOGIN_ERROR,
        )

    user.failed_login_attempts = 0
    user.locked_until = None
    user.updated_at = now

    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    access_token, jti, _ = create_access_token(
        subject=str(user.id),
        role=role_str,
        token_version=int(getattr(user, "token_version", 1) or 1),
    )
    raw_refresh_token, refresh_token_hash, refresh_expires_at = generate_refresh_token()
    family_id = str(uuid.uuid4())

    refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=refresh_token_hash,
        family_id=family_id,
        ip_address=ip_address,
        user_agent=user_agent,
        is_revoked=False,
        expires_at=refresh_expires_at,
    )
    db.add(refresh_record)

    csrf_token = generate_csrf_token(session_hint=str(user.id))

    await log_audit_event(
        db=db,
        event_type=AuditEventType.LOGIN_SUCCESS,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=user.id,
        details={
            "jti": jti,
            "family_id": family_id,
            "role": role_str,
        },
    )

    await db.commit()
    await db.refresh(user)

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh_token,
        "csrf_token": csrf_token,
        "token_type": "bearer",
        "expires_in": int(settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60,
        "user": user,
    }


async def rotate_refresh_token(
    db: AsyncSession,
    raw_refresh_token: str | None,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> Dict[str, Any]:
    """
    Implementa Refresh Token Rotation estricta y Detección de Reúso (Token Reuse Detection):
    - Si el Refresh Token recibido ya fue revocado o rotado (`is_revoked == True` o
      `replaced_by_hash is not None`), revoca inmediatamente **todas las sesiones activas**
      del usuario en la base de datos y registra `TOKEN_REUSE_DETECTED`.
    - Si es válido, lo marca como revocado, emite uno nuevo en la misma `family_id`
      y retorna el nuevo par `(access_token, refresh_token)`.
    """
    if not raw_refresh_token or not raw_refresh_token.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token no proporcionado.",
        )

    token_sha256 = hash_token(raw_refresh_token.strip())
    stmt = select(RefreshToken).where(RefreshToken.token_hash == token_sha256)
    stored_token = await db.scalar(stmt)

    if stored_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token inválido o no reconocido.",
        )

    now = datetime.now(timezone.utc)

    if stored_token.is_revoked or stored_token.replaced_by_hash is not None:
        active_tokens_stmt = select(RefreshToken).where(
            RefreshToken.user_id == stored_token.user_id,
            RefreshToken.is_revoked.is_(False),
        )
        active_tokens_result = await db.scalars(active_tokens_stmt)
        active_tokens = list(active_tokens_result.all())

        for active_tok in active_tokens:
            active_tok.is_revoked = True
            active_tok.revoked_at = now

        await log_audit_event(
            db=db,
            event_type=AuditEventType.TOKEN_REUSE_DETECTED,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=stored_token.user_id,
            details={
                "compromised_family_id": stored_token.family_id,
                "reused_token_id": str(stored_token.id),
                "revoked_active_sessions": len(active_tokens),
                "action": "revoked_all_user_sessions",
            },
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Alerta de seguridad: se detectó intento de reúso de un Refresh Token "
                "previamente invalidado. Todas las sesiones activas han sido revocadas."
            ),
        )

    if stored_token.is_expired:
        stored_token.is_revoked = True
        stored_token.revoked_at = now
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El Refresh Token ha expirado. Por favor inicie sesión nuevamente.",
        )

    user = await db.get(User, stored_token.user_id)
    if user is None or not user.is_active or user.is_locked:
        stored_token.is_revoked = True
        stored_token.revoked_at = now
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="La cuenta asociada a la sesión no se encuentra activa o está bloqueada.",
        )

    new_raw_refresh, new_refresh_hash, new_refresh_expires = generate_refresh_token()
    stored_token.is_revoked = True
    stored_token.revoked_at = now
    stored_token.replaced_by_hash = new_refresh_hash

    new_refresh_record = RefreshToken(
        user_id=user.id,
        token_hash=new_refresh_hash,
        family_id=stored_token.family_id,
        ip_address=ip_address,
        user_agent=user_agent,
        is_revoked=False,
        expires_at=new_refresh_expires,
    )
    db.add(new_refresh_record)

    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
    new_access_token, jti, _ = create_access_token(
        subject=str(user.id),
        role=role_str,
        token_version=int(getattr(user, "token_version", 1) or 1),
    )
    csrf_token = generate_csrf_token(session_hint=str(user.id))

    await log_audit_event(
        db=db,
        event_type=AuditEventType.TOKEN_REFRESH,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=user.id,
        details={
            "family_id": stored_token.family_id,
            "previous_token_id": str(stored_token.id),
            "jti": jti,
        },
    )

    await db.commit()
    return {
        "access_token": new_access_token,
        "refresh_token": new_raw_refresh,
        "csrf_token": csrf_token,
        "token_type": "bearer",
        "expires_in": int(settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60,
        "user": user,
    }


async def logout_session(
    db: AsyncSession,
    raw_refresh_token: str | None = None,
    user_id: uuid.UUID | None = None,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> None:
    """
    Cierra la sesión actual revocando el Refresh Token (y su familia asociada)
    y registra el evento `LOGOUT` en `audit_logs`.
    """
    now = datetime.now(timezone.utc)
    resolved_user_id = user_id
    revoked_family: str | None = None

    if raw_refresh_token and raw_refresh_token.strip():
        try:
            token_sha256 = hash_token(raw_refresh_token.strip())
            stmt = select(RefreshToken).where(RefreshToken.token_hash == token_sha256)
            token_record = await db.scalar(stmt)
            if token_record is not None:
                resolved_user_id = resolved_user_id or token_record.user_id
                revoked_family = token_record.family_id
                family_stmt = select(RefreshToken).where(
                    RefreshToken.family_id == token_record.family_id,
                    RefreshToken.is_revoked.is_(False),
                )
                family_tokens = (await db.scalars(family_stmt)).all()
                for f_tok in family_tokens:
                    f_tok.is_revoked = True
                    f_tok.revoked_at = now
        except ValueError:
            pass

    if resolved_user_id is not None:
        user_obj = await db.get(User, resolved_user_id)
        if user_obj is not None:
            user_obj.token_version = int(getattr(user_obj, "token_version", 1) or 1) + 1
            user_obj.updated_at = now
        if not revoked_family:
            user_tokens_stmt = select(RefreshToken).where(
                RefreshToken.user_id == resolved_user_id,
                RefreshToken.is_revoked.is_(False),
            )
            user_tokens = (await db.scalars(user_tokens_stmt)).all()
            for u_tok in user_tokens:
                u_tok.is_revoked = True
                u_tok.revoked_at = now

    await log_audit_event(
        db=db,
        event_type=AuditEventType.LOGOUT,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=resolved_user_id,
        details={
            "family_id": revoked_family,
            "session_closed": True,
        },
    )
    await db.commit()


async def request_password_reset(
    db: AsyncSession,
    email: str,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> Dict[str, Any]:
    """
    Genera un token temporal de recuperación de contraseña (15 minutos, SHA-256 en DB)
    sin revelar si el correo electrónico existe en la base de datos.
    """
    normalized_email = (email or "").strip().lower()
    email_hash = compute_blind_index(normalized_email)

    stmt = select(User).where(User.email_hash == email_hash)
    user = await db.scalar(stmt)

    if user is None or not user.is_active:
        await log_audit_event(
            db=db,
            event_type=AuditEventType.PASSWORD_RESET_REQUEST,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=user.id if user is not None else None,
            details={
                "token_issued": False,
                "email_hash_prefix": email_hash[:12],
            },
        )
        await db.commit()
        return {
            "message": GENERIC_RESET_MESSAGE,
            "raw_token": None,
            "email_info": None,
        }

    now = datetime.now(timezone.utc)
    prev_tokens_stmt = select(OneTimeToken).where(
        OneTimeToken.user_id == user.id,
        OneTimeToken.token_type == OneTimeTokenType.PASSWORD_RESET.value,
        OneTimeToken.is_used.is_(False),
    )
    for old_tok in (await db.scalars(prev_tokens_stmt)).all():
        old_tok.is_used = True
        old_tok.used_at = now

    raw_token, token_sha256, expires_at = generate_one_time_token()
    reset_token = OneTimeToken(
        user_id=user.id,
        token_hash=token_sha256,
        token_type=OneTimeTokenType.PASSWORD_RESET.value,
        is_used=False,
        expires_at=expires_at,
        requested_ip=ip_address,
    )
    db.add(reset_token)

    await log_audit_event(
        db=db,
        event_type=AuditEventType.PASSWORD_RESET_REQUEST,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=user.id,
        details={
            "token_issued": True,
            "token_id": str(reset_token.id),
        },
    )

    await db.commit()

    email_info = send_password_reset_email(
        email=user.email,
        full_name=user.full_name,
        raw_token=raw_token,
    )
    return {
        "message": GENERIC_RESET_MESSAGE,
        "raw_token": raw_token,
        "email_info": email_info,
    }


async def reset_password_with_token(
    db: AsyncSession,
    raw_token: str,
    new_password: str,
    ip_address: str = "127.0.0.1",
    user_agent: str | None = None,
) -> User:
    """
    Restablece la contraseña validando el token SHA-256 de un solo uso (< 15 min),
    verifica la política de fortaleza de la nueva contraseña, desbloquea la cuenta
    si estaba bloqueada, revoca todos los Refresh Tokens activos y audita `PASSWORD_CHANGED`.
    """
    if not raw_token or not raw_token.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El token de recuperación es obligatorio.",
        )

    try:
        validate_password_strength(new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    token_sha256 = hash_token(raw_token.strip())
    stmt = select(OneTimeToken).where(
        OneTimeToken.token_hash == token_sha256,
        OneTimeToken.token_type == OneTimeTokenType.PASSWORD_RESET.value,
    )
    token_record = await db.scalar(stmt)

    if token_record is None or token_record.is_used or token_record.is_expired:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El enlace de recuperación es inválido, ya fue utilizado o ha expirado.",
        )

    user = await db.get(User, token_record.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cuenta de usuario no disponible.",
        )

    now = datetime.now(timezone.utc)
    token_record.is_used = True
    token_record.used_at = now

    user.password_hash = hash_password(new_password)
    user.token_version = int(getattr(user, "token_version", 1) or 1) + 1
    user.failed_login_attempts = 0
    user.locked_until = None
    user.updated_at = now

    active_refresh_stmt = select(RefreshToken).where(
        RefreshToken.user_id == user.id,
        RefreshToken.is_revoked.is_(False),
    )
    active_sessions = list((await db.scalars(active_refresh_stmt)).all())
    for session_tok in active_sessions:
        session_tok.is_revoked = True
        session_tok.revoked_at = now

    await log_audit_event(
        db=db,
        event_type=AuditEventType.PASSWORD_CHANGED,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=user.id,
        details={
            "method": "password_reset_token",
            "revoked_sessions_count": len(active_sessions),
        },
    )

    await db.commit()
    await db.refresh(user)
    return user
