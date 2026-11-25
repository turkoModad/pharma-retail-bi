"""
Configuración de base de datos asíncrona con SQLAlchemy 2.0.

Provee:
- `Base(DeclarativeBase)`: Clase base declarativa para todos los modelos ORM.
- `engine`: Motor asíncrono configurado con pool de conexiones de producción.
- `AsyncSessionLocal`: Fábrica de sesiones asíncronas (`expire_on_commit=False`).
- `get_db()`: Dependencia generadora asíncrona para inyección en FastAPI.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from sqlalchemy import create_engine as _sa_create_sync_engine, event
from sqlalchemy.engine import Engine, Result
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings


class Base(DeclarativeBase):
    """Clase base declarativa de SQLAlchemy 2.0 para todos los modelos del dominio."""


def _ensure_sqlite_parent_dir(database_url: str) -> None:
    """Crea el directorio padre si la URL de SQLite apunta a un archivo en disco."""
    if not database_url.startswith("sqlite") or ":memory:" in database_url:
        return
    if ":////" in database_url:
        raw_path = "/" + database_url.split(":////", 1)[1].split("?", 1)[0]
    elif ":///" in database_url:
        raw_path = database_url.split(":///", 1)[1].split("?", 1)[0]
    else:
        return
    if raw_path and raw_path != ":memory:":
        Path(raw_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def _apply_sqlite_pragmas(dbapi_connection: Any, _connection_record: Any) -> None:
    """Configura PRAGMAs de rendimiento, durabilidad e integridad referencial en SQLite."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA secure_delete=ON;")
        cursor.execute("PRAGMA temp_store=MEMORY;")
        cursor.execute("PRAGMA cache_size=-8000;")
    finally:
        cursor.close()


def _attach_sqlite_pragmas(sync_engine: Engine) -> None:
    """Registra el evento `connect` para aplicar PRAGMAs en cada conexión SQLite."""
    event.listen(sync_engine, "connect", _apply_sqlite_pragmas)


def _normalize_sync_url(url: str) -> str:
    """Convierte una URL de driver asíncrono a su equivalente síncrono para adaptadores de fallback."""
    if url.startswith("sqlite+aiosqlite://"):
        return url.replace("sqlite+aiosqlite://", "sqlite://", 1)
    if url.startswith("postgresql+asyncpg://"):
        return url.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)
    return url


class _FallbackAsyncConnection:
    """Adaptador asíncrono sobre una conexión síncrona de SQLAlchemy 2.0."""

    def __init__(self, sync_conn: Any) -> None:
        self._sync_conn = sync_conn

    async def run_sync(
        self, fn: Callable[..., Any], *args: Any, **kwargs: Any
    ) -> Any:
        return fn(self._sync_conn, *args, **kwargs)

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Result[Any]:
        return self._sync_conn.execute(statement, *args, **kwargs)

    async def commit(self) -> None:
        self._sync_conn.commit()

    async def rollback(self) -> None:
        self._sync_conn.rollback()

    async def close(self) -> None:
        self._sync_conn.close()


class _FallbackBeginContext:
    """Context manager asíncrono para transacciones de motor (`async with engine.begin() as conn:`)."""

    def __init__(self, sync_engine: Engine) -> None:
        self._sync_engine = sync_engine
        self._ctx: Any = None
        self._conn: _FallbackAsyncConnection | None = None

    async def __aenter__(self) -> _FallbackAsyncConnection:
        self._ctx = self._sync_engine.begin()
        sync_conn = self._ctx.__enter__()
        self._conn = _FallbackAsyncConnection(sync_conn)
        return self._conn

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        if self._ctx is not None:
            return self._ctx.__exit__(exc_type, exc_val, exc_tb)
        return False


class _FallbackConnectContext:
    """Context manager asíncrono para conexiones de motor (`async with engine.connect() as conn:`)."""

    def __init__(self, sync_engine: Engine) -> None:
        self._sync_engine = sync_engine
        self._ctx: Any = None

    async def __aenter__(self) -> _FallbackAsyncConnection:
        self._ctx = self._sync_engine.connect()
        sync_conn = self._ctx.__enter__()
        return _FallbackAsyncConnection(sync_conn)

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        if self._ctx is not None:
            return self._ctx.__exit__(exc_type, exc_val, exc_tb)
        return False


class _FallbackAsyncEngine:
    """Adaptador compatible con `AsyncEngine` respaldado por `Engine` de SQLAlchemy 2.0."""

    def __init__(self, sync_engine: Engine, url: str) -> None:
        self.sync_engine = sync_engine
        self.url = sync_engine.url
        self._raw_url = url

    def begin(self) -> _FallbackBeginContext:
        return _FallbackBeginContext(self.sync_engine)

    def connect(self) -> _FallbackConnectContext:
        return _FallbackConnectContext(self.sync_engine)

    async def dispose(self) -> None:
        self.sync_engine.dispose()


class _FallbackAsyncTransaction:
    """Context manager asíncrono para `async with session.begin():`."""

    def __init__(self, session: _FallbackAsyncSession) -> None:
        self._session = session

    async def __aenter__(self) -> _FallbackAsyncSession:
        return self._session

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        if exc_type is not None:
            await self._session.rollback()
        else:
            await self._session.commit()
        return False


class _FallbackAsyncSession:
    """
    Adaptador compatible con `AsyncSession` de SQLAlchemy 2.0 cuando `greenlet`
    o drivers asíncronos C-extension no están presentes en el entorno local.
    """

    def __init__(
        self, bind: _FallbackAsyncEngine | Engine | None = None, **kwargs: Any
    ) -> None:
        sync_bind = (
            bind.sync_engine if isinstance(bind, _FallbackAsyncEngine) else bind
        )
        self._sync_session = Session(bind=sync_bind, **kwargs)

    async def __aenter__(self) -> _FallbackAsyncSession:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    def begin(self) -> _FallbackAsyncTransaction:
        return _FallbackAsyncTransaction(self)

    def add(self, instance: object, _warn: bool = True) -> None:
        self._sync_session.add(instance, _warn=_warn)

    def add_all(self, instances: Any) -> None:
        self._sync_session.add_all(instances)

    async def delete(self, instance: object) -> None:
        self._sync_session.delete(instance)

    async def execute(
        self, statement: Any, params: Any = None, **kwargs: Any
    ) -> Result[Any]:
        return self._sync_session.execute(statement, params=params, **kwargs)

    async def scalar(
        self, statement: Any, params: Any = None, **kwargs: Any
    ) -> Any:
        return self._sync_session.scalar(statement, params=params, **kwargs)

    async def scalars(
        self, statement: Any, params: Any = None, **kwargs: Any
    ) -> Any:
        return self._sync_session.scalars(statement, params=params, **kwargs)

    async def get(self, entity: Any, ident: Any, **kwargs: Any) -> Any:
        return self._sync_session.get(entity, ident, **kwargs)

    async def flush(self, objects: Any = None) -> None:
        self._sync_session.flush(objects=objects)

    async def commit(self) -> None:
        self._sync_session.commit()

    async def rollback(self) -> None:
        self._sync_session.rollback()

    async def refresh(
        self,
        instance: object,
        attribute_names: Any = None,
        with_for_update: Any = None,
    ) -> None:
        self._sync_session.refresh(
            instance,
            attribute_names=attribute_names,
            with_for_update=with_for_update,
        )

    async def close(self) -> None:
        self._sync_session.close()


def _create_fallback_async_engine(url: str, **kwargs: Any) -> _FallbackAsyncEngine:
    """Crea un motor compatible con `AsyncEngine` usando SQLAlchemy síncrono."""
    sync_url = _normalize_sync_url(url)
    engine_kwargs = dict(kwargs)
    if sync_url.startswith("sqlite"):
        engine_kwargs.pop("pool_size", None)
        engine_kwargs.pop("max_overflow", None)
        engine_kwargs.pop("pool_recycle", None)
        engine_kwargs.pop("pool_pre_ping", None)
        connect_args = dict(engine_kwargs.get("connect_args") or {})
        connect_args.setdefault("check_same_thread", False)
        engine_kwargs["connect_args"] = connect_args
        if ":memory:" in sync_url:
            engine_kwargs.setdefault("poolclass", StaticPool)

    try:
        if sync_url.startswith("sqlite"):
            _ensure_sqlite_parent_dir(sync_url)
        sync_engine = _sa_create_sync_engine(sync_url, **engine_kwargs)
    except ModuleNotFoundError:
        sync_engine = _sa_create_sync_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    if sync_engine.dialect.name == "sqlite":
        _attach_sqlite_pragmas(sync_engine)
    return _FallbackAsyncEngine(sync_engine=sync_engine, url=url)


if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import (
        AsyncEngine,
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    _HAS_NATIVE_ASYNCIO: bool
else:
    try:
        from sqlalchemy.ext.asyncio import (
            AsyncEngine,
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )

        _HAS_NATIVE_ASYNCIO = True
    except ImportError:
        _HAS_NATIVE_ASYNCIO = False
        AsyncEngine = _FallbackAsyncEngine
        AsyncSession = _FallbackAsyncSession
        create_async_engine = _create_fallback_async_engine

        def async_sessionmaker(
            bind: Any = None,
            class_: Any = _FallbackAsyncSession,
            expire_on_commit: bool = False,
            **kwargs: Any,
        ) -> Callable[..., _FallbackAsyncSession]:
            """Fábrica de sesiones asíncronas compatible con `sqlalchemy.ext.asyncio.async_sessionmaker`."""

            def _factory(**session_kwargs: Any) -> _FallbackAsyncSession:
                merged = {
                    "bind": bind,
                    "expire_on_commit": expire_on_commit,
                    **kwargs,
                    **session_kwargs,
                }
                return class_(**merged)

            return _factory


def _build_engine(database_url: str) -> Any:
    """Construye el motor asíncrono principal ajustando parámetros de pool según el dialecto."""
    is_sqlite = database_url.startswith("sqlite")
    engine_kwargs: dict[str, Any] = {
        "echo": bool(settings.DEBUG),
        "future": True,
    }
    if not is_sqlite:
        engine_kwargs.update(
            {
                "pool_pre_ping": True,
                "pool_size": 10,
                "max_overflow": 20,
                "pool_recycle": 1800,
            }
        )
    else:
        _ensure_sqlite_parent_dir(database_url)
        engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 5.0}
        if ":memory:" in database_url:
            engine_kwargs["poolclass"] = StaticPool

    if _HAS_NATIVE_ASYNCIO:
        try:
            async_eng = create_async_engine(database_url, **engine_kwargs)
            if is_sqlite:
                _attach_sqlite_pragmas(async_eng.sync_engine)
            return async_eng
        except ModuleNotFoundError:
            return _create_fallback_async_engine(database_url, **engine_kwargs)
    return _create_fallback_async_engine(database_url, **engine_kwargs)


engine = _build_engine(settings.DATABASE_URL)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependencia asíncrona de FastAPI que provee una sesión `AsyncSession`
    por petición y garantiza su cierre ordenado al finalizar.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
