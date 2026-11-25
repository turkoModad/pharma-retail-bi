"""
Servicio de Notificaciones por Correo Electrónico (SMTP con STARTTLS y Fallback de Desarrollo).

En entornos productivos con `settings.SMTP_HOST` configurado, envía correos multipart/alternative
(texto plano y HTML) vía SMTP con STARTTLS. En desarrollo o testing (`SMTP_HOST` vacío),
imprime claramente los enlaces de un solo uso en el logger/consola y almacena el registro
en una cola en memoria (`EMAIL_OUTBOX`) para facilitar pruebas automatizadas y QA.
"""

from __future__ import annotations

import logging
import smtplib
from collections import deque
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Deque, Dict

from app.core.config import settings

logger = logging.getLogger("app.email_service")

EMAIL_OUTBOX: Deque[Dict[str, Any]] = deque(maxlen=200)


def _get_base_url() -> str:
    base_url = getattr(settings, "APP_BASE_URL", "http://localhost:8000")
    return str(base_url).rstrip("/")


def _mask_email(email: str) -> str:
    local, sep, domain = (email or "").partition("@")
    if not sep:
        return "***"
    prefix = local[:1] if local else ""
    return f"{prefix}***@{domain}"


def _mask_name(name: str) -> str:
    cleaned = (name or "").strip()
    if not cleaned:
        return "***"
    return f"{cleaned[0]}***"


def _deliver_email(
    recipient_email: str,
    recipient_name: str,
    subject: str,
    plain_body: str,
    html_body: str,
    email_type: str,
    action_url: str,
    raw_token: str,
) -> Dict[str, Any]:
    """
    Despacha un correo electrónico vía SMTP o registra el enlace en consola/memoria
    cuando `SMTP_HOST` no está configurado.
    """
    smtp_host = getattr(settings, "SMTP_HOST", "") or ""
    smtp_port = int(getattr(settings, "SMTP_PORT", 587) or 587)
    smtp_user = getattr(settings, "SMTP_USER", "") or ""
    smtp_password = getattr(settings, "SMTP_PASSWORD", "") or ""
    from_email = getattr(settings, "SMTP_FROM_EMAIL", "no-reply@authsec.local") or "no-reply@authsec.local"
    from_name = getattr(settings, "SMTP_FROM_NAME", "Seguridad AuthSec") or "Seguridad AuthSec"
    use_tls = bool(getattr(settings, "SMTP_TLS", True))

    record: Dict[str, Any] = {
        "recipient": recipient_email,
        "full_name": recipient_name,
        "type": email_type,
        "subject": subject,
        "url": action_url,
        "token": raw_token,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "delivery": "console_fallback",
        "sent": True,
    }

    if smtp_host.strip():
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = recipient_email
        msg.attach(MIMEText(plain_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            with smtplib.SMTP(smtp_host.strip(), smtp_port, timeout=10) as server:
                server.ehlo()
                if use_tls:
                    server.starttls()
                    server.ehlo()
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                server.sendmail(from_email, [recipient_email], msg.as_string())
            record["delivery"] = "smtp"
        except Exception as exc:
            logger.warning(
                "Error enviando correo SMTP a %s (%s). Activando fallback en consola.",
                _mask_email(recipient_email),
                exc,
            )
            record["delivery"] = "console_fallback_after_smtp_error"

    if record["delivery"] != "smtp":
        logger.info(
            "\n======================================================================\n"
            "[EMAIL SERVICE - MODO DESARROLLO / FALLBACK]\n"
            "Tipo: %s\n"
            "Destinatario: %s <%s>\n"
            "Asunto: %s\n"
            "Enlace de acción (expira en 15 min): %s\n"
            "Token de un solo uso: %s\n"
            "======================================================================",
            email_type,
            _mask_name(recipient_name),
            _mask_email(recipient_email),
            subject,
            action_url,
            raw_token,
        )

    EMAIL_OUTBOX.append(record)
    return record


def send_verification_email(email: str, full_name: str, raw_token: str) -> Dict[str, Any]:
    """
    Envía el enlace de verificación de cuenta (expiración 15 minutos, un solo uso).
    """
    base_url = _get_base_url()
    verification_url = f"{base_url}/auth/verify-email?token={raw_token}"
    subject = "Verificación de cuenta — Plataforma de Seguridad"

    plain_body = (
        f"Hola {full_name},\n\n"
        f"Gracias por registrarte. Para activar tu cuenta, accede al siguiente enlace "
        f"(válido por 15 minutos y de un solo uso):\n\n"
        f"{verification_url}\n\n"
        f"Si no solicitaste este registro, puedes ignorar este mensaje.\n"
    )
    html_body = (
        f"<p>Hola <strong>{full_name}</strong>,</p>"
        f"<p>Para verificar tu cuenta, haz clic en el siguiente enlace "
        f"(válido durante <strong>15 minutos</strong> y de un solo uso):</p>"
        f"<p><a href='{verification_url}'>{verification_url}</a></p>"
        f"<p><small>Si no creaste esta cuenta, ignora este mensaje.</small></p>"
    )

    return _deliver_email(
        recipient_email=email,
        recipient_name=full_name,
        subject=subject,
        plain_body=plain_body,
        html_body=html_body,
        email_type="email_verification",
        action_url=verification_url,
        raw_token=raw_token,
    )


def send_password_reset_email(email: str, full_name: str, raw_token: str) -> Dict[str, Any]:
    """
    Envía el enlace de recuperación de contraseña (expiración 15 minutos, un solo uso).
    """
    base_url = _get_base_url()
    reset_url = f"{base_url}/reset-password?token={raw_token}"
    subject = "Recuperación de contraseña — Plataforma de Seguridad"

    plain_body = (
        f"Hola {full_name},\n\n"
        f"Hemos recibido una solicitud para restablecer tu contraseña. "
        f"Utiliza el siguiente enlace (válido por 15 minutos y de un solo uso):\n\n"
        f"{reset_url}\n\n"
        f"Si no realizaste esta solicitud, tu cuenta sigue protegida y puedes ignorar este correo.\n"
    )
    html_body = (
        f"<p>Hola <strong>{full_name}</strong>,</p>"
        f"<p>Para restablecer tu contraseña, accede al siguiente enlace "
        f"(válido durante <strong>15 minutos</strong> y de un solo uso):</p>"
        f"<p><a href='{reset_url}'>{reset_url}</a></p>"
        f"<p><small>Si no solicitaste este cambio, ignora este mensaje.</small></p>"
    )

    return _deliver_email(
        recipient_email=email,
        recipient_name=full_name,
        subject=subject,
        plain_body=plain_body,
        html_body=html_body,
        email_type="password_reset",
        action_url=reset_url,
        raw_token=raw_token,
    )


def get_last_sent_email(recipient: str | None = None, email_type: str | None = None) -> Dict[str, Any] | None:
    """
    Obtiene el último correo registrado en `EMAIL_OUTBOX` (filtrando opcionalmente
    por destinatario y/o tipo de correo). Útil para desarrollo y pruebas QA.
    """
    for item in reversed(EMAIL_OUTBOX):
        if recipient and item.get("recipient", "").lower() != recipient.strip().lower():
            continue
        if email_type and item.get("type") != email_type:
            continue
        return item
    return None


def clear_email_outbox() -> None:
    """Vacía la cola en memoria de correos emitidos."""
    EMAIL_OUTBOX.clear()
