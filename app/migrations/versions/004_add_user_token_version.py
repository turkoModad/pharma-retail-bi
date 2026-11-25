"""Agrega columna token_version al modelo User para revocación persistente de JWT.

Revision ID: 004_add_user_token_version
Revises: 003_encrypt_user_full_name
Create Date: 2026-11-24 17:20:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "004_add_user_token_version"
down_revision: str | None = "003_encrypt_user_full_name"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column(
                "token_version",
                sa.Integer(),
                server_default="1",
                nullable=False,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("token_version")
