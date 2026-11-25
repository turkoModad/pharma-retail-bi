"""Cifra la columna full_name en reposo mediante Fernet (full_name_encrypted).

Revision ID: 003_encrypt_user_full_name
Revises: 002_encrypt_user_email
Create Date: 2026-11-24 16:07:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

from app.core.security import decrypt_pii, encrypt_pii

revision: str = "003_encrypt_user_full_name"
down_revision: str | None = "002_encrypt_user_email"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("full_name_encrypted", sa.Text(), nullable=True))

    bind = op.get_bind()
    users_table = sa.table(
        "users",
        sa.column("id", sa.Uuid(as_uuid=True)),
        sa.column("full_name", sa.String(length=150)),
        sa.column("full_name_encrypted", sa.Text()),
    )
    rows = bind.execute(sa.select(users_table.c.id, users_table.c.full_name)).fetchall()
    for user_id, plain_name in rows:
        cleaned = (plain_name or "").strip()
        bind.execute(
            users_table.update()
            .where(users_table.c.id == user_id)
            .values(full_name_encrypted=encrypt_pii(cleaned) or "")
        )

    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column("full_name_encrypted", existing_type=sa.Text(), nullable=False)
        batch_op.drop_column("full_name")


def downgrade() -> None:
    op.add_column("users", sa.Column("full_name", sa.String(length=150), nullable=True))

    bind = op.get_bind()
    users_table = sa.table(
        "users",
        sa.column("id", sa.Uuid(as_uuid=True)),
        sa.column("full_name", sa.String(length=150)),
        sa.column("full_name_encrypted", sa.Text()),
    )
    rows = bind.execute(
        sa.select(users_table.c.id, users_table.c.full_name_encrypted)
    ).fetchall()
    for user_id, enc_name in rows:
        decrypted = decrypt_pii(enc_name) or ""
        bind.execute(
            users_table.update()
            .where(users_table.c.id == user_id)
            .values(full_name=decrypted.strip()[:150])
        )

    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column("full_name", existing_type=sa.String(length=150), nullable=False)
        batch_op.drop_column("full_name_encrypted")
