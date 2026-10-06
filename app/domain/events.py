from datetime import datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


SourceType = Literal["http_access", "linux_auth"]


class Event(BaseModel):
    """Normalized security event used throughout IncidentScope."""

    event_id: UUID = Field(default_factory=uuid4)

    timestamp: datetime
    source_type: SourceType
    event_type: str

    source_ip: str | None = None
    destination_ip: str | None = None

    source_port: int | None = Field(default=None, ge=1, le=65535)
    destination_port: int | None = Field(default=None, ge=1, le=65535)

    hostname: str | None = None
    user: str | None = None

    method: str | None = None
    path: str | None = None
    status_code: int | None = Field(default=None, ge=100, le=599)
    user_agent: str | None = None

    action: str | None = None
    message: str | None = None

    raw_event: str
    metadata: dict[str, Any] = Field(default_factory=dict)
