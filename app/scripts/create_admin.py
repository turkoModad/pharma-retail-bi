"""
Script ejecutable para aprovisionar o promover el primer usuario Administrador (`role='admin'`)
verificado en la base de datos.

Uso desde línea de comandos:
    python -m app.scripts.create_admin \
        --email admin@ejemplo.com \
        --password "<PASSWORD_SEGURO>" \
        --full-name "Administrador General" \
        --phone "+5491100001111" \
        --document-id "ADM-0001"
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from sqlalchemy import select

import app.models
from app.core.database import AsyncSession, AsyncSessionLocal, Base, engine
from app.core.security import (
    compute_blind_index,
    encrypt_pii,
    hash_password,
    validate_password_strength,
)
from app.models.audit_log import AuditEventType
from app.models.user import User, UserRole
from app.services.audit_service import log_audit_event


async def create_or_promote_admin(
    db: AsyncSession,
    email: str,
    password: str,
    full_name: str = "Administrador del Sistema",
    phone: str | None = None,
    document_id: str | None = None,
    address: str | None = None,
) -> User:
    """
    Crea un nuevo usuario con rol `admin` e `is_verified=True` o promueve un usuario
    existente a `admin` actualizando su contraseña y desbloqueando su cuenta.
    Registra `ADMIN_ACTION` en `audit_logs`.
    """
    normalized_email = email.strip().lower()
    email_hash = compute_blind_index(normalized_email)
    validate_password_strength(password)
    hashed_pwd = hash_password(password)

    stmt = select(User).where(User.email_hash == email_hash)
    existing_user = await db.scalar(stmt)
    now = datetime.now(timezone.utc)

    if existing_user is not None:
        existing_user.password_hash = hashed_pwd
        existing_user.full_name = full_name.strip() or existing_user.full_name
        existing_user.role = UserRole.ADMIN.value
        existing_user.is_active = True
        existing_user.is_verified = True
        existing_user.failed_login_attempts = 0
        existing_user.locked_until = None
        existing_user.updated_at = now

        if phone is not None:
            existing_user.phone_encrypted = encrypt_pii(phone.strip()) if phone.strip() else None
        if document_id is not None:
            existing_user.document_id_encrypted = (
                encrypt_pii(document_id.strip()) if document_id.strip() else None
            )
        if address is not None:
            existing_user.address_encrypted = (
                encrypt_pii(address.strip()) if address.strip() else None
            )

        admin_user = existing_user
        action_label = "promoted_existing_user_to_admin"
    else:
        admin_user = User(
            email=normalized_email,
            email_hash=email_hash,
            password_hash=hashed_pwd,
            full_name=full_name.strip(),
            phone_encrypted=encrypt_pii(phone.strip()) if phone and phone.strip() else None,
            document_id_encrypted=(
                encrypt_pii(document_id.strip())
                if document_id and document_id.strip()
                else None
            ),
            address_encrypted=(
                encrypt_pii(address.strip()) if address and address.strip() else None
            ),
            role=UserRole.ADMIN.value,
            is_active=True,
            is_verified=True,
            failed_login_attempts=0,
            locked_until=None,
        )
        db.add(admin_user)
        await db.flush()
        action_label = "bootstrapped_initial_admin"

    await log_audit_event(
        db=db,
        event_type=AuditEventType.ADMIN_ACTION,
        ip_address="127.0.0.1",
        user_agent="cli/create_admin.py",
        user_id=admin_user.id,
        details={
            "action": action_label,
            "target_user_id": str(admin_user.id),
            "role": UserRole.ADMIN.value,
            "is_verified": True,
        },
    )

    await db.commit()
    await db.refresh(admin_user)
    return admin_user


async def _run_cli(args: argparse.Namespace) -> int:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        admin_user = await create_or_promote_admin(
            db=session,
            email=args.email,
            password=args.password,
            full_name=args.full_name,
            phone=args.phone,
            document_id=args.document_id,
            address=args.address,
        )
        print(
            f"[OK] Usuario administrador configurado exitosamente:\n"
            f"  ID:          {admin_user.id}\n"
            f"  Email:       {admin_user.email}\n"
            f"  Rol:         {admin_user.role}\n"
            f"  Verificado:  {admin_user.is_verified}\n"
            f"  Activo:      {admin_user.is_active}"
        )
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Crea o promueve un usuario Administrador (RBAC) verificado en la base de datos."
    )
    parser.add_argument(
        "--email",
        default=os.getenv("INITIAL_ADMIN_EMAIL", "admin@ejemplo.com"),
        help="Correo electrónico del administrador (o variable INITIAL_ADMIN_EMAIL)",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("INITIAL_ADMIN_PASSWORD"),
        help="Contraseña maestra (>=10 chars, mayús, minús, dígito, símbolo; o variable INITIAL_ADMIN_PASSWORD)",
    )
    parser.add_argument(
        "--full-name",
        default=os.getenv("INITIAL_ADMIN_NAME", "Administrador de Seguridad"),
        help="Nombre completo del administrador",
    )
    parser.add_argument("--phone", default=None, help="Teléfono (cifrado con Fernet)")
    parser.add_argument("--document-id", default=None, help="Documento / DNI (cifrado con Fernet)")
    parser.add_argument("--address", default=None, help="Dirección física (cifrada con Fernet)")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    if not args.password:
        parser.error(
            "Debe proporcionar --password o definir la variable de entorno INITIAL_ADMIN_PASSWORD."
        )
    return asyncio.run(_run_cli(args))


if __name__ == "__main__":
    raise SystemExit(main())
