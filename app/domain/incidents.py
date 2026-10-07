from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator

from app.domain.alerts import Severity


class Incident(BaseModel):
    """A correlated security incident supported by alerts and events."""

    incident_id: UUID = Field(default_factory=uuid4)

    incident_type: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Severity
    summary: str = Field(min_length=1)

    first_seen: datetime
    last_seen: datetime

    alert_ids: list[UUID] = Field(min_length=1)
    event_ids: list[UUID] = Field(min_length=1)

    source_ips: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_incident(self) -> "Incident":
        if self.last_seen < self.first_seen:
            raise ValueError(
                "last_seen cannot be earlier than first_seen"
            )

        if len(self.alert_ids) != len(set(self.alert_ids)):
            raise ValueError(
                "alert_ids must not contain duplicates"
            )

        if len(self.event_ids) != len(set(self.event_ids)):
            raise ValueError(
                "event_ids must not contain duplicates"
            )

        return self
