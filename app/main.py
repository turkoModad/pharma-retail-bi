"""
Punto de entrada principal de la aplicación FastAPI (`app.main:app`).

Configura:
- Ciclo de vida asíncrono (`lifespan`) con verificación de esquema ORM.
- `CORSMiddleware` restrictivo (`settings.CORS_ORIGINS`).
- `SecurityHeadersMiddleware` (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- `AuditAndCSRFMiddleware` (extracción de IP/User-Agent y Double Submit Cookie CSRF).
- Montaje de archivos estáticos (`/static`) y plantillas SSR Jinja2.
- Registro de routers: `views`, `auth`, `users`, `admin` y endpoint `/health`.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import app.models
from app.core.config import settings, validate_production_security
from app.core.database import Base, engine
from app.core.limiter import limiter
from app.middlewares.audit_middleware import AuditAndCSRFMiddleware
from app.middlewares.security_headers import SecurityHeadersMiddleware
from app.routers import admin, auth, users, views

logger = logging.getLogger("app.main")

_STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """
    Inicializa los recursos de la aplicación al arrancar.
    En entornos de desarrollo/testing, asegura que las tablas existan si la BD es accesible.
    """
    validate_production_security(settings)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as exc:
        logger.debug("Omitiendo create_all automático en arranque (%s).", exc)
    yield


def create_application() -> FastAPI:
    """Fábrica de instancia `FastAPI` completamente configurada."""
    application = FastAPI(
        title=settings.APP_NAME,
        description=(
            "Plataforma de Autenticación Segura (Argon2id + JWT HttpOnly + Refresh Token Rotation), "
            "Cifrado de PII en reposo (Fernet), RBAC y Auditoría Forense (JSONB)."
        ),
        version="1.0.0",
        openapi_url=None if settings.is_production else "/openapi.json",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        lifespan=lifespan,
    )

    application.state.limiter = limiter

    application.add_middleware(SecurityHeadersMiddleware)

    application.add_middleware(AuditAndCSRFMiddleware)

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.CORS_ORIGINS),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Accept",
            "X-CSRF-Token",
            "X-Requested-With",
            "X-Refresh-Token",
        ],
        expose_headers=["Retry-After"],
    )

    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(settings.ALLOWED_HOSTS),
    )

    application.add_middleware(
        ProxyHeadersMiddleware,
        trusted_hosts=list(settings.TRUSTED_PROXIES),
    )

    if _STATIC_DIR.is_dir():
        application.mount(
            "/static",
            StaticFiles(directory=str(_STATIC_DIR)),
            name="static",
        )

    application.include_router(views.router)
    application.include_router(auth.router)
    application.include_router(users.router)
    application.include_router(admin.router)

    @application.get("/health", tags=["Monitoreo"])
    async def health_check() -> dict[str, Any]:
        """Endpoint de verificación de estado y salud del servicio."""
        return {
            "status": "ok",
            "service": settings.APP_NAME,
            "environment": settings.ENVIRONMENT,
        }

    return application


app = create_application()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        workers=1,
    )
