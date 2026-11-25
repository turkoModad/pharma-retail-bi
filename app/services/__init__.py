"""
Exportación centralizada de servicios de negocio y seguridad.
"""

from app.services.audit_service import (
    extract_client_ip,
    extract_user_agent,
    log_audit_event,
    sanitize_audit_details,
)
from app.services.auth_service import (
    authenticate_user,
    logout_session,
    register_user,
    request_password_reset,
    reset_password_with_token,
    rotate_refresh_token,
    verify_email_token,
)
from app.services.email_service import (
    EMAIL_OUTBOX,
    clear_email_outbox,
    get_last_sent_email,
    send_password_reset_email,
    send_verification_email,
)
from app.services.user_service import (
    admin_update_user,
    change_own_password,
    enforce_anti_idor,
    get_user_recent_logins,
    list_all_users,
    list_audit_logs,
    update_own_profile,
)

__all__ = [
    "extract_client_ip",
    "extract_user_agent",
    "log_audit_event",
    "sanitize_audit_details",
    "authenticate_user",
    "logout_session",
    "register_user",
    "request_password_reset",
    "reset_password_with_token",
    "rotate_refresh_token",
    "verify_email_token",
    "EMAIL_OUTBOX",
    "clear_email_outbox",
    "get_last_sent_email",
    "send_password_reset_email",
    "send_verification_email",
    "admin_update_user",
    "change_own_password",
    "enforce_anti_idor",
    "get_user_recent_logins",
    "list_all_users",
    "list_audit_logs",
    "update_own_profile",
]
