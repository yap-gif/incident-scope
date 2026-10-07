from collections.abc import Sequence

from pydantic import BaseModel, Field

from app.correlation.defaults import (
    build_default_correlation_engine,
)
from app.domain.alerts import Alert
from app.domain.events import Event
from app.domain.incidents import Incident
from app.domain.timelines import InvestigationTimeline
from app.detection.defaults import (
    build_default_detection_engine,
)
from app.investigation.timeline_builder import (
    build_investigation_timeline,
)


class AnalysisResult(BaseModel):
    """Complete in-memory result of one analysis run."""

    events: list[Event] = Field(
        default_factory=list
    )
    alerts: list[Alert] = Field(
        default_factory=list
    )
    incidents: list[Incident] = Field(
        default_factory=list
    )
    timelines: list[InvestigationTimeline] = Field(
        default_factory=list
    )


def analyze_events(
    events: Sequence[Event],
) -> AnalysisResult:
    """Run the default IncidentScope analysis pipeline."""

    normalized_events = list(events)

    detection_engine = (
        build_default_detection_engine()
    )

    alerts = detection_engine.evaluate(
        normalized_events
    )

    correlation_engine = (
        build_default_correlation_engine()
    )

    incidents = correlation_engine.correlate(
        alerts
    )

    timelines = [
        build_investigation_timeline(
            incident,
            alerts,
            normalized_events,
        )
        for incident in incidents
    ]

    return AnalysisResult(
        events=normalized_events,
        alerts=alerts,
        incidents=incidents,
        timelines=timelines,
    )
