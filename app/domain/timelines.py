from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


TimelineEntryType = Literal[
    "event",
    "alert",
]


class TimelineEntry(BaseModel):
    """One evidence-backed entry in an investigation timeline."""

    timestamp: datetime
    entry_type: TimelineEntryType
    evidence_id: UUID

    title: str = Field(min_length=1)
    description: str = Field(min_length=1)

    source_ip: str | None = None
    user: str | None = None

    details: dict[str, Any] = Field(
        default_factory=dict
    )
    tags: list[str] = Field(
        default_factory=list
    )


class InvestigationTimeline(BaseModel):
    """Chronological evidence timeline for one incident."""

    incident_id: UUID
    title: str = Field(min_length=1)

    entries: list[TimelineEntry] = Field(
        min_length=1
    )

    @model_validator(mode="after")
    def validate_timeline(
        self,
    ) -> "InvestigationTimeline":
        previous_timestamp: datetime | None = None

        evidence_refs: set[
            tuple[TimelineEntryType, UUID]
        ] = set()

        for entry in self.entries:
            if (
                previous_timestamp is not None
                and entry.timestamp < previous_timestamp
            ):
                raise ValueError(
                    "timeline entries must be chronological"
                )

            previous_timestamp = entry.timestamp

            evidence_ref = (
                entry.entry_type,
                entry.evidence_id,
            )

            if evidence_ref in evidence_refs:
                raise ValueError(
                    "timeline evidence must not be duplicated"
                )

            evidence_refs.add(evidence_ref)

        return self
