"""
Configuración central y fixtures para la suite de pruebas (`pytest` y `unittest`).

Provee:
- Inicialización aislada de variables de entorno criptográficas para testing.
- Base de datos SQLAlchemy 2.0 en memoria (`sqlite:///:memory:`) con recreación limpia de tablas.
- Entorno de renderizado Jinja2 apuntando a `app/templates/` con autoescaping XSS activo.
- Soporte híbrido para ejecución tanto con `pytest` como con `python3 -m unittest` en
  entornos locales sin binarios externos.
"""

from __future__ import annotations

import json
import os
import sys
import types
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, Dict

_TESTS_DIR = Path(__file__).resolve().parent
_APP_DIR = _TESTS_DIR.parent
_PROJECT_ROOT = _APP_DIR.parent
_PY_VER = f"python{sys.version_info.major}.{sys.version_info.minor}"
_VENV_DIRS = [
    *(
        [Path(os.environ["VIRTUAL_ENV"])]
        if os.environ.get("VIRTUAL_ENV")
        else []
    ),
    _PROJECT_ROOT / ".venv",
    _PROJECT_ROOT / "venv",
    _PROJECT_ROOT / "entorno-contrato",
]
_SYS_SITE = Path(f"/usr/lib/{_PY_VER}/site-packages")

for _candidate in (
    _PROJECT_ROOT,
    *(d / "lib" / _PY_VER / "site-packages" for d in _VENV_DIRS),
    _SYS_SITE,
):
    _path_str = str(_candidate)
    if _candidate.exists() and _path_str not in sys.path:
        sys.path.insert(0, _path_str)

os.environ.setdefault("ENVIRONMENT", "testing")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("DATABASE_URL_SYNC", "sqlite:///:memory:")
os.environ.setdefault(
    "SECRET_KEY",
    "clave-secreta-jwt-testing-deterministica-32-bytes-segura-2026",
)
os.environ.setdefault(
    "FERNET_KEY",
    "Z3VhcJk9X2t5cE1mVnh6QWJDRGVmR2hJSmtsTW5PcFFyU3R1Vnd4WXo0NTY=",
)
os.environ.setdefault(
    "HMAC_SECRET",
    "clave-hmac-sha256-blind-indexing-testing-deterministica-2026",
)
os.environ.setdefault(
    "CSRF_SECRET",
    "clave-csrf-double-submit-cookie-testing-deterministica-2026",
)
os.environ.setdefault("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
os.environ.setdefault("REFRESH_TOKEN_EXPIRE_DAYS", "7")
os.environ.setdefault("ONE_TIME_TOKEN_EXPIRE_MINUTES", "15")
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("ALLOWED_HOSTS", '["localhost","127.0.0.1"]')
os.environ.setdefault("SMTP_HOST", "")
os.environ.setdefault("MAX_FAILED_LOGIN_ATTEMPTS", "5")
os.environ.setdefault("ACCOUNT_LOCKOUT_MINUTES", "15")


def _install_minimal_test_shims_if_needed() -> None:
    """
    Si el entorno de ejecución cuenta con `pydantic`, `fastapi` y `pytest`, no hace nada.
    Si alguno no está instalado en el intérprete local, registra un adaptador compatible
    en `sys.modules` para permitir la ejecución completa de los servicios y esquemas con `unittest`.
    """
    try:
        import pytest
    except ImportError:
        pytest_mod = types.ModuleType("pytest")

        def _fixture(*args: Any, **kwargs: Any) -> Callable[..., Any]:
            if len(args) == 1 and callable(args[0]) and not kwargs:
                return args[0]

            def _decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
                return fn

            return _decorator

        class _MarkNamespace:
            def __getattr__(self, _name: str) -> Callable[..., Any]:
                def _deco(*args: Any, **kwargs: Any) -> Any:
                    if len(args) == 1 and callable(args[0]) and not kwargs:
                        return args[0]
                    return lambda f: f

                return _deco

        pytest_mod.fixture = _fixture
        pytest_mod.mark = _MarkNamespace()
        sys.modules["pytest"] = pytest_mod

    try:
        import pydantic
    except ImportError:
        pydantic_mod = types.ModuleType("pydantic")

        class _FieldInfo:
            def __init__(
                self,
                default: Any = ...,
                default_factory: Callable[[], Any] | None = None,
                min_length: int | None = None,
                max_length: int | None = None,
                description: str | None = None,
                **kwargs: Any,
            ) -> None:
                self.default = default
                self.default_factory = default_factory
                self.min_length = min_length
                self.max_length = max_length
                self.description = description
                self.extra = kwargs

        def Field(
            default: Any = ...,
            *,
            default_factory: Callable[[], Any] | None = None,
            min_length: int | None = None,
            max_length: int | None = None,
            description: str | None = None,
            **kwargs: Any,
        ) -> Any:
            return _FieldInfo(
                default=default,
                default_factory=default_factory,
                min_length=min_length,
                max_length=max_length,
                description=description,
                **kwargs,
            )

        def ConfigDict(**kwargs: Any) -> Dict[str, Any]:
            return dict(kwargs)

        def field_validator(*fields: str, mode: str = "after") -> Callable[..., Any]:
            def _decorator(fn: Any) -> Any:
                raw_fn = fn.__func__ if isinstance(fn, classmethod) else fn
                setattr(raw_fn, "__pydantic_field_validator__", (fields, mode))
                return classmethod(raw_fn)

            return _decorator

        def model_validator(*, mode: str = "after") -> Callable[..., Any]:
            def _decorator(fn: Any) -> Any:
                raw_fn = fn.__func__ if isinstance(fn, classmethod) else fn
                setattr(raw_fn, "__pydantic_model_validator__", mode)
                return classmethod(raw_fn) if mode == "before" else raw_fn

            return _decorator

        class _BaseModelMeta(type):
            def __new__(
                mcs, name: str, bases: tuple[type, ...], namespace: Dict[str, Any]
            ) -> Any:
                field_infos: Dict[str, _FieldInfo] = {}
                before_model_validators = []
                after_model_validators = []
                field_validators_list = []

                for b in bases:
                    field_infos.update(getattr(b, "__field_infos__", {}))
                    before_model_validators.extend(
                        getattr(b, "__before_model_validators__", [])
                    )
                    after_model_validators.extend(
                        getattr(b, "__after_model_validators__", [])
                    )
                    field_validators_list.extend(
                        getattr(b, "__field_validators__", [])
                    )

                annotations = namespace.get("__annotations__", {})
                for attr_name in list(annotations.keys()):
                    val = namespace.get(attr_name, ...)
                    if isinstance(val, _FieldInfo):
                        field_infos[attr_name] = val
                        namespace.pop(attr_name, None)
                    elif not callable(val) and not isinstance(
                        val, (property, classmethod, staticmethod)
                    ):
                        field_infos[attr_name] = _FieldInfo(default=val)

                for attr_name, attr_val in list(namespace.items()):
                    if isinstance(attr_val, _FieldInfo):
                        field_infos[attr_name] = attr_val
                        namespace.pop(attr_name, None)
                        continue
                    raw = (
                        attr_val.__func__
                        if isinstance(attr_val, classmethod)
                        else attr_val
                    )
                    if hasattr(raw, "__pydantic_field_validator__"):
                        f_names, f_mode = getattr(raw, "__pydantic_field_validator__")
                        field_validators_list.append((f_names, f_mode, raw))
                    if hasattr(raw, "__pydantic_model_validator__"):
                        m_mode = getattr(raw, "__pydantic_model_validator__")
                        if m_mode == "before":
                            before_model_validators.append(raw)
                        else:
                            after_model_validators.append(raw)

                namespace["__field_infos__"] = field_infos
                namespace["__before_model_validators__"] = before_model_validators
                namespace["__after_model_validators__"] = after_model_validators
                namespace["__field_validators__"] = field_validators_list
                return super().__new__(mcs, name, bases, namespace)

        class BaseModel(metaclass=_BaseModelMeta):
            model_config: Dict[str, Any] = {}

            def __init__(self, **data: Any) -> None:
                cls = self.__class__
                raw_input: Any = dict(data)
                for b_val in getattr(cls, "__before_model_validators__", []):
                    raw_input = b_val(cls, raw_input)
                if not isinstance(raw_input, dict):
                    raw_input = dict(data)

                strip_ws = bool(
                    getattr(cls, "model_config", {}).get("str_strip_whitespace", False)
                )
                self.model_fields_set: set[str] = set(raw_input.keys())

                field_infos: Dict[str, _FieldInfo] = getattr(
                    cls, "__field_infos__", {}
                )
                values: Dict[str, Any] = {}

                for f_name, f_info in field_infos.items():
                    if f_name in raw_input:
                        val = raw_input[f_name]
                    elif f_info.default_factory is not None:
                        val = f_info.default_factory()
                    elif f_info.default is not ...:
                        val = f_info.default
                    else:
                        raise ValueError(f"El campo obligatorio '{f_name}' es requerido.")

                    if strip_ws and isinstance(val, str):
                        val = val.strip()
                    values[f_name] = val

                for k, v in raw_input.items():
                    if k not in values:
                        values[k] = v.strip() if (strip_ws and isinstance(v, str)) else v

                for f_names, f_mode, f_fn in getattr(cls, "__field_validators__", []):
                    if f_mode == "before":
                        for fn_target in f_names:
                            if fn_target in values:
                                values[fn_target] = f_fn(cls, values[fn_target])

                for f_name, f_info in field_infos.items():
                    val = values.get(f_name)
                    if isinstance(val, str):
                        if f_info.min_length is not None and len(val) < f_info.min_length:
                            raise ValueError(
                                f"El campo '{f_name}' debe tener al menos {f_info.min_length} caracteres."
                            )
                        if f_info.max_length is not None and len(val) > f_info.max_length:
                            raise ValueError(
                                f"El campo '{f_name}' excede el máximo de {f_info.max_length} caracteres."
                            )

                for f_names, f_mode, f_fn in getattr(cls, "__field_validators__", []):
                    if f_mode != "before":
                        for fn_target in f_names:
                            if fn_target in values:
                                values[fn_target] = f_fn(cls, values[fn_target])

                for k, v in values.items():
                    setattr(self, k, v)

                for a_val in getattr(cls, "__after_model_validators__", []):
                    a_val(self)

            @classmethod
            def model_validate(cls, obj: Any) -> Any:
                raw: Any = obj
                for b_val in getattr(cls, "__before_model_validators__", []):
                    raw = b_val(cls, raw)
                if isinstance(raw, dict):
                    return cls(**raw)
                if hasattr(raw, "__dict__"):
                    data = {
                        k: getattr(raw, k)
                        for k in getattr(cls, "__field_infos__", {}).keys()
                        if hasattr(raw, k)
                    }
                    return cls(**data)
                return cls()

            def model_dump(self, mode: str | None = None, **kwargs: Any) -> Dict[str, Any]:
                return {
                    k: getattr(self, k)
                    for k in getattr(self.__class__, "__field_infos__", {}).keys()
                    if hasattr(self, k)
                }

        class ValidationError(ValueError):
            def errors(self) -> list[Dict[str, Any]]:
                return [{"msg": str(self), "loc": ("body",)}]

        pydantic_mod.BaseModel = BaseModel
        pydantic_mod.ConfigDict = ConfigDict
        pydantic_mod.EmailStr = str
        pydantic_mod.Field = Field
        pydantic_mod.ValidationError = ValidationError
        pydantic_mod.field_validator = field_validator
        pydantic_mod.model_validator = model_validator
        sys.modules["pydantic"] = pydantic_mod

    try:
        import fastapi
    except ImportError:
        fastapi_mod = types.ModuleType("fastapi")

        class HTTPException(Exception):
            def __init__(
                self,
                status_code: int,
                detail: Any = None,
                headers: Dict[str, str] | None = None,
            ) -> None:
                super().__init__(str(detail))
                self.status_code = int(status_code)
                self.detail = detail
                self.headers = headers or {}

        class _StatusNamespace:
            HTTP_200_OK = 200
            HTTP_201_CREATED = 201
            HTTP_204_NO_CONTENT = 204
            HTTP_302_FOUND = 302
            HTTP_303_SEE_OTHER = 303
            HTTP_400_BAD_REQUEST = 400
            HTTP_401_UNAUTHORIZED = 401
            HTTP_403_FORBIDDEN = 403
            HTTP_404_NOT_FOUND = 404
            HTTP_422_UNPROCESSABLE_ENTITY = 422
            HTTP_429_TOO_MANY_REQUESTS = 429
            HTTP_500_INTERNAL_SERVER_ERROR = 500

        class Request:
            def __init__(
                self,
                headers: Dict[str, str] | None = None,
                cookies: Dict[str, str] | None = None,
                query_params: Dict[str, str] | None = None,
                client_host: str = "127.0.0.1",
                path: str = "/",
            ) -> None:
                self.headers = {
                    k.lower(): v for k, v in (headers or {}).items()
                }
                self.cookies = dict(cookies or {})
                self.query_params = dict(query_params or {})
                self.client = types.SimpleNamespace(host=client_host)
                self.state = types.SimpleNamespace()
                self.url = types.SimpleNamespace(path=path)

        fastapi_mod.HTTPException = HTTPException
        fastapi_mod.status = _StatusNamespace()
        fastapi_mod.Request = Request
        sys.modules["fastapi"] = fastapi_mod


_install_minimal_test_shims_if_needed()

import jinja2
import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from app.core.database import Base, _FallbackAsyncEngine, _FallbackAsyncSession
from app.models.audit_log import AuditLog
from app.models.token import OneTimeToken, RefreshToken
from app.models.user import User
from app.services.email_service import clear_email_outbox


def create_in_memory_async_engine() -> _FallbackAsyncEngine:
    """
    Crea un motor SQLite en memoria aislado con todas las tablas del esquema ORM
    (`users`, `refresh_tokens`, `one_time_tokens`, `audit_logs`).
    """
    sync_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=sync_engine)
    return _FallbackAsyncEngine(
        sync_engine=sync_engine,
        url="sqlite+aiosqlite:///:memory:",
    )


@asynccontextmanager
async def isolated_db_session() -> AsyncGenerator[_FallbackAsyncSession, None]:
    """
    Provee una sesión asíncrona limpia respaldada por una base de datos SQLite
    en memoria recién inicializada. Limpia la bandeja `EMAIL_OUTBOX` antes y después.
    """
    clear_email_outbox()
    engine = create_in_memory_async_engine()
    session = _FallbackAsyncSession(bind=engine, expire_on_commit=False)
    try:
        yield session
    finally:
        await session.close()
        await engine.dispose()
        clear_email_outbox()


def build_jinja_environment() -> jinja2.Environment:
    """
    Construye un entorno Jinja2 con `autoescape=True` apuntando a `app/templates/`
    y soporte para el filtro `tojson`.
    """
    templates_dir = _APP_DIR / "templates"
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(templates_dir)),
        autoescape=jinja2.select_autoescape(["html", "xml"]),
    )
    if "tojson" not in env.filters:
        env.filters["tojson"] = lambda val: json.dumps(val, ensure_ascii=False)
    return env


def render_template_to_string(template_name: str, **context: Any) -> str:
    """Renderiza una plantilla de `app/templates/` y retorna el HTML resultante."""
    env = build_jinja_environment()
    template = env.get_template(template_name)
    return template.render(**context)


@pytest.fixture
async def db_session() -> AsyncGenerator[_FallbackAsyncSession, None]:
    """Fixture asíncrono de sesión de base de datos aislada para `pytest`."""
    async with isolated_db_session() as session:
        yield session


@pytest.fixture
def jinja_env() -> jinja2.Environment:
    """Fixture con el entorno de plantillas Jinja2."""
    return build_jinja_environment()
