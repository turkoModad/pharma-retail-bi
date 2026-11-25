"""Cifra la columna email en reposo mediante Fernet (email_encrypted).

Revision ID: 002_encrypt_user_email
Revises: 001_initial_auth_and_audit
Create Date: 2026-11-24 15:52:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

from app.core.security import compute_blind_index, decrypt_pii, encrypt_pii

revision: str = "002_encrypt_user_email"
down_revision: str | None = "001_initial_auth_and_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("email_encrypted", sa.Text(), nullable=True))

    bind = op.get_bind()
    users_table = sa.table(
        "users",
        sa.column("id", sa.Uuid(as_uuid=True)),
        sa.column("email", sa.String(length=255)),
        sa.column("email_encrypted", sa.Text()),
        sa.column("email_hash", sa.String(length=64)),
    )
    rows = bind.execute(sa.select(users_table.c.id, users_table.c.email)).fetchall()
    for user_id, plain_email in rows:
        normalized = (plain_email or "").strip().lower()
        bind.execute(
            users_table.update()
            .where(users_table.c.id == user_id)
            .values(
                email_encrypted=encrypt_pii(normalized) or "",
                email_hash=compute_blind_index(normalized),
            )
        )

    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column("email_encrypted", existing_type=sa.Text(), nullable=False)
        batch_op.drop_index("ix_users_email")
        batch_op.drop_column("email")


def downgrade() -> None:
    op.add_column("users", sa.Column("email", sa.String(length=255), nullable=True))

    bind = op.get_bind()
    users_table = sa.table(
        "users",
        sa.column("id", sa.Uuid(as_uuid=True)),
        sa.column("email", sa.String(length=255)),
        sa.column("email_encrypted", sa.Text()),
    )
    rows = bind.execute(
        sa.select(users_table.c.id, users_table.c.email_encrypted)
    ).fetchall()
    for user_id, enc_email in rows:
        decrypted = decrypt_pii(enc_email) or ""
        bind.execute(
            users_table.update()
            .where(users_table.c.id == user_id)
            .values(email=decrypted.strip().lower())
        )

    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column("email", existing_type=sa.String(length=255), nullable=False)
        batch_op.create_index("ix_users_email", ["email"], unique=True)
        batch_op.drop_column("email_encrypted")
