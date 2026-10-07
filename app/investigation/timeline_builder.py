from collections.abc import Sequence

from app.domain.alerts import Alert
from app.domain.events import Event
from app.domain.incidents import Incident
from app.domain.timelines import (
    InvestigationTimeline,
    TimelineEntry,
)


class TimelineEvidenceError(ValueError):
    """Raised when incident evidence cannot be resolved."""


def build_investigation_timeline(
    incident: Incident,
    alerts: Sequence[Alert],
    events: Sequence[Event],
) -> InvestigationTimeline:
    """Build a deterministic timeline from incident evidence."""

    alerts_by_id = {
        alert.alert_id: alert
        for alert in alerts
    }

    events_by_id = {
        event.event_id: event
        for event in events
    }

    missing_alert_ids = [
        alert_id
        for alert_id in incident.alert_ids
        if alert_id not in alerts_by_id
    ]

    if missing_alert_ids:
        missing = ", ".join(
            sorted(
                str(alert_id)
                for alert_id in missing_alert_ids
            )
        )

        raise TimelineEvidenceError(
            "missing supporting alert evidence: "
            f"{missing}"
        )

    missing_event_ids = [
        event_id
        for event_id in incident.event_ids
        if event_id not in events_by_id
    ]

    if missing_event_ids:
        missing = ", ".join(
            sorted(
                str(event_id)
                for event_id in missing_event_ids
            )
        )

        raise TimelineEvidenceError(
            "missing supporting event evidence: "
            f"{missing}"
        )

    entries: list[TimelineEntry] = []

    for event_id in incident.event_ids:
        event = events_by_id[event_id]

        entries.append(
            _build_event_entry(event)
        )

    for alert_id in incident.alert_ids:
        alert = alerts_by_id[alert_id]

        entries.append(
            _build_alert_entry(alert)
        )

    entry_type_order = {
        "event": 0,
        "alert": 1,
    }

    entries.sort(
        key=lambda entry: (
            entry.timestamp,
            entry_type_order[entry.entry_type],
            str(entry.evidence_id),
        )
    )

    return InvestigationTimeline(
        incident_id=incident.incident_id,
        title=(
            "Investigation Timeline: "
            f"{incident.title}"
        ),
        entries=entries,
    )


def _build_event_entry(
    event: Event,
) -> TimelineEntry:
    details = {
        "source_type": event.source_type,
        "event_type": event.event_type,
        "destination_ip": event.destination_ip,
        "source_port": event.source_port,
        "destination_port": event.destination_port,
        "hostname": event.hostname,
        "method": event.method,
        "path": event.path,
        "status_code": event.status_code,
        "user_agent": event.user_agent,
        "action": event.action,
        "raw_event": event.raw_event,
        "metadata": event.metadata,
    }

    return TimelineEntry(
        timestamp=event.timestamp,
        entry_type="event",
        evidence_id=event.event_id,
        title=(
            f"{event.source_type}: "
            f"{event.event_type}"
        ),
        description=(
            event.message
            or (
                f"Normalized {event.source_type} "
                f"event: {event.event_type}."
            )
        ),
        source_ip=event.source_ip,
        user=event.user,
        details=details,
        tags=[
            "event",
            event.source_type,
            event.event_type,
        ],
    )


def _build_alert_entry(
    alert: Alert,
) -> TimelineEntry:
    details = {
        "rule_id": alert.rule_id,
        "severity": alert.severity,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "supporting_event_ids": list(
            alert.event_ids
        ),
        "evidence": alert.evidence,
    }

    return TimelineEntry(
        timestamp=alert.last_seen,
        entry_type="alert",
        evidence_id=alert.alert_id,
        title=(
            f"{alert.rule_id}: "
            f"{alert.title}"
        ),
        description=alert.description,
        source_ip=alert.source_ip,
        user=alert.user,
        details=details,
        tags=[
            "alert",
            *alert.tags,
        ],
    )
