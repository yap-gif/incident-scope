from datetime import datetime
from typing import Any, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator


Severity = Literal["low", "medium", "high", "critical"]


class Alert(BaseModel):
    """Explainable security alert produced by a detection rule."""

    alert_id: UUID = Field(default_factory=uuid4)

    rule_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Severity
    description: str = Field(min_length=1)

    first_seen: datetime
    last_seen: datetime

    source_ip: str | None = None
    user: str | None = None

    event_ids: list[UUID] = Field(min_length=1)

    evidence: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_time_range(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError(
                "last_seen must be greater than or equal to first_seen"
            )

        return self
