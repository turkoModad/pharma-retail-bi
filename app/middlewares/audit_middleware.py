"""
Middleware Forense de Contexto de Auditoría (IP/User-Agent) y Protección CSRF (Double Submit Cookie).

Responsabilidades:
1. Extraer de manera confiable la dirección IP real del cliente (`X-Forwarded-For`, `X-Real-IP`, `client.host`)
   y el `User-Agent`, inyectándolos en `request.state.client_ip` y `request.state.user_agent`.
2. Garantizar que toda petición disponga de un token CSRF firmado con HMAC-SHA256 en
   `request.state.csrf_token` y en la cookie `csrf_token`.
3. Validar la protección CSRF (Double Submit Cookie) en peticiones mutadoras (`POST`, `PUT`,
   `PATCH`, `DELETE`) cuando se emplean sesiones basadas en cookies o formularios HTML,
   comparando en tiempo constante la cookie `csrf_token` contra la cabecera `X-CSRF-Token`
   o el campo de formulario `csrf_token`.
"""

from __future__ import annotations

import hmac
from urllib.parse import parse_qs

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import settings
from app.core.security import generate_csrf_token, verify_csrf_token_signature
from app.services.audit_service import extract_client_ip, extract_user_agent

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

PUBLIC_AUTH_ENTRY_PATHS = frozenset(
    {
        "/auth/login",
        "/auth/register",
        "/auth/forgot-password",
        "/auth/reset-password",
        "/auth/verify-email",
        "/auth/refresh",
    }
)


async def _extract_submitted_csrf_token(request: Request) -> str | None:
    """
    Obtiene el token CSRF enviado por el cliente desde:
    1. Cabecera `X-CSRF-Token` o `X-XSRF-Token`.
    2. Campo `csrf_token` en cuerpo `application/x-www-form-urlencoded` (sin consumir el stream).
    """
    header_token = request.headers.get("x-csrf-token") or request.headers.get("x-xsrf-token")
    if header_token and header_token.strip():
        return header_token.strip()

    content_type = (request.headers.get("content-type") or "").lower()
    if "application/x-www-form-urlencoded" in content_type:
        try:
            raw_body = await request.body()
            if raw_body:
                parsed = parse_qs(raw_body.decode("utf-8", errors="ignore"), keep_blank_values=True)
                values = parsed.get("csrf_token")
                if values and values[0]:
                    return values[0].strip()
        except Exception:
            return None

    return None


class AuditAndCSRFMiddleware(BaseHTTPMiddleware):
    """
    Middleware ASGI que inicializa metadatos forenses (`client_ip`, `user_agent`)
    y aplica protección CSRF de Doble Envío de Cookie (Double Submit Cookie).
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        request.state.client_ip = extract_client_ip(request)
        request.state.user_agent = extract_user_agent(request)

        cookie_csrf = request.cookies.get("csrf_token")
        cookie_csrf_valid = bool(cookie_csrf and verify_csrf_token_signature(cookie_csrf))

        if cookie_csrf_valid and cookie_csrf:
            request.state.csrf_token = cookie_csrf
            needs_new_cookie = False
        else:
            request.state.csrf_token = generate_csrf_token()
            needs_new_cookie = True

        method = request.method.upper()
        path = request.url.path.rstrip("/") or "/"

        if method in UNSAFE_METHODS:
            submitted_csrf = await _extract_submitted_csrf_token(request)
            auth_header = request.headers.get("authorization") or ""
            has_bearer_auth = auth_header.lower().startswith("bearer ")
            has_session_cookie = "access_token" in request.cookies
            content_type = (request.headers.get("content-type") or "").lower()
            is_form_submission = (
                "application/x-www-form-urlencoded" in content_type
                or "multipart/form-data" in content_type
            )
            is_public_auth_entry = path in PUBLIC_AUTH_ENTRY_PATHS

            if submitted_csrf is not None:
                if (
                    not cookie_csrf_valid
                    or not cookie_csrf
                    or not hmac.compare_digest(cookie_csrf, submitted_csrf)
                ):
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": "Fallo de validación CSRF: el token CSRF no coincide con la cookie de sesión o su firma es inválida."
                        },
                    )
            else:
                must_enforce_csrf = (
                    not is_public_auth_entry
                    and (
                        (has_session_cookie and not has_bearer_auth)
                        or is_form_submission
                    )
                )
                if must_enforce_csrf:
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": "Fallo de validación CSRF: falta el token CSRF en la cabecera 'X-CSRF-Token' o en el formulario."
                        },
                    )

        response = await call_next(request)

        has_csrf_set_cookie = any(
            "csrf_token=" in hdr for hdr in response.headers.getlist("set-cookie")
        )
        if needs_new_cookie and not has_csrf_set_cookie:
            samesite_val = (settings.COOKIE_SAMESITE or "lax").lower()
            response.set_cookie(
                key="csrf_token",
                value=request.state.csrf_token,
                httponly=False,
                secure=bool(settings.COOKIE_SECURE),
                samesite=samesite_val,
                domain=settings.COOKIE_DOMAIN,
                path="/",
                max_age=int(settings.REFRESH_TOKEN_EXPIRE_DAYS) * 86400,
            )

        return response


AuditMiddleware = AuditAndCSRFMiddleware
