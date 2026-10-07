from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.domain.alerts import Severity
from app.domain.timelines import InvestigationTimeline


ReportVersion = Literal["1.0"]


class IncidentReport(BaseModel):
    """Machine-readable investigation report for one incident."""

    report_version: ReportVersion = "1.0"

    incident_id: UUID
    incident_type: str = Field(min_length=1)

    title: str = Field(min_length=1)
    severity: Severity
    summary: str = Field(min_length=1)

    first_seen: datetime
    last_seen: datetime

    source_ips: list[str] = Field(
        default_factory=list
    )
    users: list[str] = Field(
        default_factory=list
    )
    tags: list[str] = Field(
        default_factory=list
    )

    alert_ids: list[UUID] = Field(
        min_length=1
    )
    event_ids: list[UUID] = Field(
        min_length=1
    )

    timeline: InvestigationTimeline

    analyst_conclusion: str = Field(
        min_length=1
    )

    limitations: list[str] = Field(
        default_factory=list
    )

    @model_validator(mode="after")
    def validate_report(
        self,
    ) -> "IncidentReport":
        if self.last_seen < self.first_seen:
            raise ValueError(
                "last_seen cannot be earlier than first_seen"
            )

        if len(self.alert_ids) != len(
            set(self.alert_ids)
        ):
            raise ValueError(
                "alert_ids must not contain duplicates"
            )

        if len(self.event_ids) != len(
            set(self.event_ids)
        ):
            raise ValueError(
                "event_ids must not contain duplicates"
            )

        if self.timeline.incident_id != self.incident_id:
            raise ValueError(
                "timeline incident_id must match report incident_id"
            )

        timeline_alert_ids = {
            entry.evidence_id
            for entry in self.timeline.entries
            if entry.entry_type == "alert"
        }

        timeline_event_ids = {
            entry.evidence_id
            for entry in self.timeline.entries
            if entry.entry_type == "event"
        }

        if timeline_alert_ids != set(self.alert_ids):
            raise ValueError(
                "timeline alert evidence must match report alert_ids"
            )

        if timeline_event_ids != set(self.event_ids):
            raise ValueError(
                "timeline event evidence must match report event_ids"
            )

        return self
