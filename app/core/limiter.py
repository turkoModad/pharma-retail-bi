"""
Rate Limiter Sliding-Window en memoria para FastAPI.

Mitiga ataques de fuerza bruta, credential stuffing y denegación de servicio (DoS)
en endpoints críticos de autenticación (`/auth/login`, `/auth/register`,
`/auth/forgot-password`, `/auth/reset-password`, `/auth/refresh`).
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict, deque
from typing import TYPE_CHECKING, Any, Callable, Deque, Dict, Tuple

if TYPE_CHECKING:
    from fastapi import HTTPException, Request, status
    from slowapi import Limiter as SlowAPILimiter
    from slowapi.util import get_remote_address
else:
    try:
        from fastapi import HTTPException, Request, status
    except ImportError:
        class Request:
            headers: Dict[str, str]
            client: Any
            state: Any
            url: Any

        class HTTPException(Exception):
            def __init__(self, status_code: int, detail: Any = None, headers: Dict[str, str] | None = None) -> None:
                super().__init__(str(detail))
                self.status_code = int(status_code)
                self.detail = detail
                self.headers = headers or {}

        class status:
            HTTP_429_TOO_MANY_REQUESTS = 429

    try:
        from slowapi import Limiter as SlowAPILimiter
        from slowapi.util import get_remote_address

        HAS_SLOWAPI = True
    except ImportError:
        SlowAPILimiter = None
        get_remote_address = None
        HAS_SLOWAPI = False

if TYPE_CHECKING:
    HAS_SLOWAPI: bool


def get_client_ip(request: Request) -> str:
    """
    Extrae la dirección IP del cliente validando `TRUSTED_PROXIES` y `CF-Connecting-IP`.
    """
    from app.services.audit_service import extract_client_ip

    return extract_client_ip(request)


class SlidingWindowRateLimiter:
    """
    Implementación thread-safe de algoritmo Sliding Window en memoria
    indexado por `(ip_address, scope)`.
    """

    def __init__(self) -> None:
        self._buckets: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self.enabled: bool = True

    def check(
        self,
        ip_address: str,
        scope: str,
        max_requests: int,
        window_seconds: int,
    ) -> Tuple[bool, int, int]:
        """
        Evalúa si `(ip_address, scope)` puede realizar una petición adicional.

        Retorna:
            (allowed, remaining_requests, retry_after_seconds)
        """
        if not self.enabled:
            return True, max_requests, 0

        now = time.monotonic()
        cutoff = now - float(window_seconds)
        key = (ip_address or "127.0.0.1", scope)

        with self._lock:
            bucket = self._buckets[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= max_requests:
                oldest = bucket[0]
                retry_after = max(1, int(math.ceil(window_seconds - (now - oldest))))
                return False, 0, retry_after

            bucket.append(now)
            remaining = max(0, max_requests - len(bucket))
            return True, remaining, 0

    def reset(self) -> None:
        """Limpia todos los contadores en memoria (útil para suites de pruebas)."""
        with self._lock:
            self._buckets.clear()


sliding_window_limiter = SlidingWindowRateLimiter()

if HAS_SLOWAPI and SlowAPILimiter is not None:
    limiter = SlowAPILimiter(key_func=get_client_ip)
else:
    limiter = sliding_window_limiter


def check_rate_limit(
    request: Request,
    max_requests: int = 10,
    window_seconds: int = 60,
    scope: str = "default",
) -> None:
    """
    Verifica directamente el límite de peticiones para el `Request` actual.
    Lanza HTTP 429 con cabecera `Retry-After` si se excede la cuota.
    """
    ip_address = get_client_ip(request)
    effective_scope = scope or request.url.path
    allowed, remaining, retry_after = sliding_window_limiter.check(
        ip_address=ip_address,
        scope=effective_scope,
        max_requests=max_requests,
        window_seconds=window_seconds,
    )
    request.state.rate_limit_remaining = remaining
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Demasiadas solicitudes desde esta dirección IP. "
                f"Por favor, espere {retry_after} segundos antes de reintentar."
            ),
            headers={"Retry-After": str(retry_after)},
        )


def rate_limit(
    max_requests: int = 10,
    window_seconds: int = 60,
    scope: str = "default",
) -> Callable[[Request], None]:
    """
    Generador de dependencia FastAPI (`Depends(rate_limit(...))`) para aplicar
    Rate Limiting por ventana deslizante en endpoints específicos.
    """

    async def _rate_limit_dependency(request: Request) -> None:
        check_rate_limit(
            request=request,
            max_requests=max_requests,
            window_seconds=window_seconds,
            scope=scope,
        )

    return _rate_limit_dependency


def reset_rate_limiter() -> None:
    """
    Reinicia el estado del Rate Limiter en memoria.
    Debe ser invocado por fixtures de pruebas (`pytest`) para evitar interferencia entre tests.
    """
    sliding_window_limiter.reset()
    if HAS_SLOWAPI and hasattr(limiter, "reset"):
        try:
            limiter.reset()
        except Exception:
            pass
