"""
Script idempotente de migración de datos desde PostgreSQL hacia SQLite (`data/authsec.db`).

Uso desde la raíz del proyecto:
    python -m app.scripts.migrate_pg_to_sqlite
    python -m app.scripts.migrate_pg_to_sqlite --pg-url postgresql+psycopg2://<PG_USER>:<PG_PASSWORD>@localhost:5432/farmacia_bi
"""

from __future__ import annotations

import argparse
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    MetaData,
    Numeric,
    PrimaryKeyConstraint,
    String,
    Table,
    Text,
    Time,
    UniqueConstraint,
    Uuid,
    create_engine,
    inspect,
    select,
    text,
)
from sqlalchemy.orm import Session

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from app.core.config import settings
from app.core.database import Base, _attach_sqlite_pragmas, _ensure_sqlite_parent_dir, _normalize_sync_url
from app.core.security import compute_blind_index, encrypt_pii
from app.models.audit_log import AuditLog
from app.models.token import OneTimeToken, RefreshToken
from app.models.user import User
from app.services.audit_service import sanitize_audit_details


def _to_uuid(val: Any) -> uuid.UUID | None:
    if val is None:
        return None
    if isinstance(val, uuid.UUID):
        return val
    return uuid.UUID(str(val))


def _to_datetime(val: Any) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo is not None else val.replace(tzinfo=timezone.utc)
    dt = datetime.fromisoformat(str(val))
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _map_pg_type_to_portable(col_type: Any) -> Any:
    """Convierte tipos reflejados de PostgreSQL a tipos portables compatibles con SQLite."""
    type_name = type(col_type).__name__.upper()
    if "UUID" in type_name:
        return Uuid(as_uuid=False)
    if "JSON" in type_name:
        return JSON()
    if "BOOL" in type_name:
        return Boolean()
    if "BIGINT" in type_name:
        return BigInteger()
    if "INT" in type_name or "SERIAL" in type_name:
        return Integer()
    if "NUMERIC" in type_name or "DECIMAL" in type_name:
        precision = getattr(col_type, "precision", None)
        scale = getattr(col_type, "scale", None)
        return Numeric(precision=precision, scale=scale)
    if "FLOAT" in type_name or "DOUBLE" in type_name or "REAL" in type_name:
        return Float()
    if "TIMESTAMP" in type_name or "DATETIME" in type_name:
        return DateTime(timezone=getattr(col_type, "timezone", False))
    if type_name == "DATE":
        return Date()
    if type_name == "TIME":
        return Time()
    if "VARCHAR" in type_name or "CHAR" in type_name:
        length = getattr(col_type, "length", None)
        return String(length=length) if length else Text()
    return Text()


def _migrate_remaining_tables(
    pg_engine: Any,
    sqlite_engine: Any,
    skip_tables: set[str],
) -> dict[str, dict[str, int]]:
    """Refleja y migra el resto de tablas de negocio (ej. productos, compras, etc.) desde PostgreSQL a SQLite."""
    extra_stats: dict[str, dict[str, int]] = {}
    pg_meta = MetaData()
    pg_meta.reflect(bind=pg_engine, views=False)

    sqlite_meta = MetaData()
    sqlite_inspector = inspect(sqlite_engine)
    existing_sqlite_tables = set(sqlite_inspector.get_table_names())

    tables_to_copy: list[tuple[Table, Table]] = []
    for src_table in pg_meta.sorted_tables:
        if src_table.name in skip_tables:
            continue

        if src_table.name in existing_sqlite_tables:
            dst_table = Table(src_table.name, sqlite_meta, autoload_with=sqlite_engine)
        else:
            cols = []
            for col in src_table.columns:
                cols.append(
                    Column(
                        col.name,
                        _map_pg_type_to_portable(col.type),
                        primary_key=col.primary_key,
                        nullable=col.nullable,
                        autoincrement=bool(col.autoincrement) if col.primary_key else False,
                    )
                )
            constraints = []
            pk_cols = [c.name for c in src_table.primary_key.columns]
            if pk_cols:
                constraints.append(PrimaryKeyConstraint(*pk_cols))
            for uc in src_table.constraints:
                if isinstance(uc, UniqueConstraint):
                    constraints.append(UniqueConstraint(*[c.name for c in uc.columns]))
            for fk in src_table.foreign_keys:
                if fk.column.table.name not in skip_tables:
                    constraints.append(
                        ForeignKeyConstraint(
                            [fk.parent.name],
                            [f"{fk.column.table.name}.{fk.column.name}"],
                            ondelete=fk.ondelete,
                        )
                    )
            dst_table = Table(src_table.name, sqlite_meta, *cols, *constraints)
            dst_table.create(bind=sqlite_engine, checkfirst=True)
            for idx in src_table.indexes:
                Index(
                    idx.name,
                    *[dst_table.c[c.name] for c in idx.columns],
                    unique=idx.unique,
                ).create(bind=sqlite_engine, checkfirst=True)

        tables_to_copy.append((src_table, dst_table))

    with pg_engine.connect() as pg_conn, sqlite_engine.begin() as sq_conn:
        for src_table, dst_table in tables_to_copy:
            t_name = src_table.name
            extra_stats[t_name] = {"inserted": 0, "skipped": 0}
            pk_cols = [c.name for c in src_table.primary_key.columns]

            existing_pks: set[tuple[Any, ...]] = set()
            if pk_cols:
                pk_rows = sq_conn.execute(
                    select(*[dst_table.c[k] for k in pk_cols])
                ).fetchall()
                existing_pks = {tuple(r) for r in pk_rows}

            batch: list[dict[str, Any]] = []
            result = pg_conn.execute(select(src_table))
            for row in result.mappings():
                row_dict = dict(row)
                if pk_cols:
                    pk_key = tuple(row_dict[k] for k in pk_cols)
                    if pk_key in existing_pks:
                        extra_stats[t_name]["skipped"] += 1
                        continue
                    existing_pks.add(pk_key)
                batch.append(row_dict)
                if len(batch) >= 1000:
                    sq_conn.execute(dst_table.insert(), batch)
                    extra_stats[t_name]["inserted"] += len(batch)
                    batch.clear()

            if batch:
                sq_conn.execute(dst_table.insert(), batch)
                extra_stats[t_name]["inserted"] += len(batch)

    return extra_stats


def _default_pg_url() -> str:
    from sqlalchemy.engine import URL

    user = os.getenv("PGUSER", "postgres")
    password = os.getenv("PGPASSWORD") or None
    host = os.getenv("PGHOST", "localhost")
    port = int(os.getenv("PGPORT", "5432"))
    db = os.getenv("PGDATABASE", "farmacia_bi")
    return URL.create(
        drivername="postgresql+psycopg2",
        username=user,
        password=password,
        host=host,
        port=port,
        database=db,
    ).render_as_string(hide_password=False)


def migrate_data(pg_url: str, sqlite_url: str) -> dict[str, dict[str, int]]:
    """Copia `users`, `refresh_tokens`, `one_time_tokens` y `audit_logs` desde PostgreSQL a SQLite."""
    sync_pg_url = _normalize_sync_url(pg_url)
    sync_sqlite_url = _normalize_sync_url(sqlite_url)

    _ensure_sqlite_parent_dir(sync_sqlite_url)
    pg_engine = create_engine(sync_pg_url, future=True)
    sqlite_engine = create_engine(
        sync_sqlite_url,
        connect_args={"check_same_thread": False},
        future=True,
    )
    if sqlite_engine.dialect.name == "sqlite":
        _attach_sqlite_pragmas(sqlite_engine)

    Base.metadata.create_all(bind=sqlite_engine)

    stats: dict[str, dict[str, int]] = {
        "users": {"inserted": 0, "skipped": 0},
        "refresh_tokens": {"inserted": 0, "skipped": 0},
        "one_time_tokens": {"inserted": 0, "skipped": 0},
        "audit_logs": {"inserted": 0, "skipped": 0},
    }

    pg_inspector = inspect(pg_engine)
    pg_tables = set(pg_inspector.get_table_names())

    with pg_engine.connect() as pg_conn, Session(bind=sqlite_engine) as dst:
        if "users" in pg_tables:
            user_cols = {c["name"] for c in pg_inspector.get_columns("users")}
            existing_user_ids = set(dst.scalars(select(User.id)).all())
            existing_email_hashes = set(dst.scalars(select(User.email_hash)).all())

            rows = pg_conn.execute(text("SELECT * FROM users")).mappings().all()
            for row in rows:
                uid = _to_uuid(row["id"])
                if uid is None:
                    continue
                if "email_encrypted" in user_cols and row.get("email_encrypted"):
                    email_encrypted = str(row["email_encrypted"])
                    email_hash = str(row.get("email_hash") or "")
                else:
                    plain_email = str(row.get("email") or "").strip().lower()
                    email_encrypted = encrypt_pii(plain_email) or ""
                    email_hash = str(row.get("email_hash") or compute_blind_index(plain_email))

                if "full_name_encrypted" in user_cols and row.get("full_name_encrypted"):
                    full_name_encrypted = str(row["full_name_encrypted"])
                else:
                    plain_name = str(row.get("full_name") or "").strip()
                    full_name_encrypted = encrypt_pii(plain_name) or ""

                if uid in existing_user_ids or email_hash in existing_email_hashes:
                    stats["users"]["skipped"] += 1
                    continue

                dst.add(
                    User(
                        id=uid,
                        email_encrypted=email_encrypted,
                        email_hash=email_hash,
                        password_hash=row["password_hash"],
                        full_name_encrypted=full_name_encrypted,
                        phone_encrypted=row.get("phone_encrypted"),
                        document_id_encrypted=row.get("document_id_encrypted"),
                        address_encrypted=row.get("address_encrypted"),
                        role=row.get("role", "user"),
                        is_active=bool(row.get("is_active", True)),
                        is_verified=bool(row.get("is_verified", False)),
                        failed_login_attempts=int(row.get("failed_login_attempts", 0)),
                        locked_until=_to_datetime(row.get("locked_until")),
                        created_at=_to_datetime(row.get("created_at")),
                        updated_at=_to_datetime(row.get("updated_at")),
                    )
                )
                existing_user_ids.add(uid)
                existing_email_hashes.add(email_hash)
                stats["users"]["inserted"] += 1
            dst.commit()

        if "refresh_tokens" in pg_tables:
            existing_rt_ids = set(dst.scalars(select(RefreshToken.id)).all())
            existing_user_ids = set(dst.scalars(select(User.id)).all())
            rows = pg_conn.execute(text("SELECT * FROM refresh_tokens")).mappings().all()
            for row in rows:
                rt_id = _to_uuid(row["id"])
                rt_uid = _to_uuid(row["user_id"])
                if rt_id is None or rt_id in existing_rt_ids or rt_uid not in existing_user_ids:
                    stats["refresh_tokens"]["skipped"] += 1
                    continue
                dst.add(
                    RefreshToken(
                        id=rt_id,
                        user_id=rt_uid,
                        token_hash=row["token_hash"],
                        family_id=row["family_id"],
                        replaced_by_hash=row.get("replaced_by_hash"),
                        ip_address=row.get("ip_address"),
                        user_agent=row.get("user_agent"),
                        is_revoked=bool(row.get("is_revoked", False)),
                        revoked_at=_to_datetime(row.get("revoked_at")),
                        expires_at=_to_datetime(row["expires_at"]),
                        created_at=_to_datetime(row.get("created_at")),
                    )
                )
                stats["refresh_tokens"]["inserted"] += 1
            dst.commit()

        if "one_time_tokens" in pg_tables:
            existing_ott_ids = set(dst.scalars(select(OneTimeToken.id)).all())
            existing_user_ids = set(dst.scalars(select(User.id)).all())
            rows = pg_conn.execute(text("SELECT * FROM one_time_tokens")).mappings().all()
            for row in rows:
                ott_id = _to_uuid(row["id"])
                ott_uid = _to_uuid(row["user_id"])
                if ott_id is None or ott_id in existing_ott_ids or ott_uid not in existing_user_ids:
                    stats["one_time_tokens"]["skipped"] += 1
                    continue
                dst.add(
                    OneTimeToken(
                        id=ott_id,
                        user_id=ott_uid,
                        token_hash=row["token_hash"],
                        token_type=row["token_type"],
                        is_used=bool(row.get("is_used", False)),
                        used_at=_to_datetime(row.get("used_at")),
                        expires_at=_to_datetime(row["expires_at"]),
                        created_at=_to_datetime(row.get("created_at")),
                    )
                )
                stats["one_time_tokens"]["inserted"] += 1
            dst.commit()

        if "audit_logs" in pg_tables:
            existing_log_ids = set(dst.scalars(select(AuditLog.id)).all())
            existing_user_ids = set(dst.scalars(select(User.id)).all())
            rows = pg_conn.execute(text("SELECT * FROM audit_logs")).mappings().all()
            for row in rows:
                log_id = _to_uuid(row["id"])
                if log_id is None or log_id in existing_log_ids:
                    stats["audit_logs"]["skipped"] += 1
                    continue
                uid = _to_uuid(row.get("user_id"))
                if uid is not None and uid not in existing_user_ids:
                    uid = None
                raw_details: Any = row.get("details")
                safe_details = sanitize_audit_details(raw_details if isinstance(raw_details, dict) else {})
                dst.add(
                    AuditLog(
                        id=log_id,
                        user_id=uid,
                        event_type=row["event_type"],
                        ip_address=row.get("ip_address"),
                        user_agent=row.get("user_agent"),
                        details=safe_details,
                        created_at=_to_datetime(row.get("created_at")),
                    )
                )
                stats["audit_logs"]["inserted"] += 1
            dst.commit()

    extra_stats = _migrate_remaining_tables(
        pg_engine=pg_engine,
        sqlite_engine=sqlite_engine,
        skip_tables={"alembic_version", "users", "refresh_tokens", "one_time_tokens", "audit_logs"},
    )
    stats.update(extra_stats)

    pg_engine.dispose()
    sqlite_engine.dispose()
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Migra usuarios, tokens y audit_logs desde PostgreSQL hacia SQLite."
    )
    parser.add_argument(
        "--pg-url",
        default=_default_pg_url(),
        help="URL de conexión PostgreSQL origen (por defecto lee PG* del entorno/.env).",
    )
    parser.add_argument(
        "--sqlite-url",
        default=settings.DATABASE_URL,
        help="URL de conexión SQLite destino (por defecto DATABASE_URL).",
    )
    args = parser.parse_args()

    stats = migrate_data(pg_url=args.pg_url, sqlite_url=args.sqlite_url)
    print("Migración PostgreSQL -> SQLite completada:")
    for table, counts in stats.items():
        print(f"  - {table}: {counts['inserted']} insertados, {counts['skipped']} omitidos")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
