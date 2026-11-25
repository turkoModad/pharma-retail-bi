"""
Middleware de Cabeceras de Seguridad HTTP (OWASP Secure Headers).

Inyecta cabeceras defensivas en todas las respuestas HTTP para mitigar:
- Clickjacking (`X-Frame-Options: DENY`, `frame-ancestors 'none'`)
- MIME-sniffing (`X-Content-Type-Options: nosniff`)
- Ataques de downgrade TLS / MITM (`Strict-Transport-Security`)
- Cross-Site Scripting e inyección de recursos externos (`Content-Security-Policy`)
- Fuga de URLs sensibles en cabeceras Referer (`Referrer-Policy`)
- Acceso no autorizado a hardware del navegador (`Permissions-Policy`)
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

DEFAULT_CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data:; "
    "font-src 'self' https://cdn.jsdelivr.net data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware ASGI que añade cabeceras de seguridad endurecidas a cada respuesta."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)

        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )
        response.headers.setdefault("Content-Security-Policy", DEFAULT_CSP_POLICY)
        response.headers.setdefault(
            "Referrer-Policy", "strict-origin-when-cross-origin"
        )
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
        )
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")

        if request.url.path.startswith(("/auth", "/users", "/admin", "/profile", "/login", "/register")):
            response.headers.setdefault(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            response.headers.setdefault("Pragma", "no-cache")
            response.headers.setdefault("Expires", "0")

        return response
