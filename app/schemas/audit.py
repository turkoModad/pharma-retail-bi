"""
Esquemas Pydantic v2 para visualización y consulta de registros de auditoría (`audit_logs`).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict

try:
    from pydantic import BaseModel, ConfigDict, Field, field_validator
except ImportError:
    from app.tests.conftest import _install_minimal_test_shims_if_needed

    _install_minimal_test_shims_if_needed()
    from pydantic import BaseModel, ConfigDict, Field, field_validator


class AuditLogRead(BaseModel):
    """Representación de solo lectura de un evento forense en `audit_logs`."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID | int | str
    user_id: uuid.UUID | None = None
    event_type: str
    ip_address: str
    user_agent: str | None = None
    user_email: str | None = None
    user_name: str | None = None
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    @field_validator("event_type", mode="before")
    @classmethod
    def normalize_event_type(cls, value: Any) -> str:
        if isinstance(value, Enum):
            return str(value.value)
        return str(value)

    @field_validator("details", mode="before")
    @classmethod
    def ensure_dict_details(cls, value: Any) -> Dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        return {"raw": str(value)}
