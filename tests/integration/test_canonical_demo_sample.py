from pathlib import Path

from app.application.analysis import (
    analyze_events,
)
from app.ingestion.batch import ingest_file


SAMPLE_PATH = Path(
    "samples/auth/suspicious-authentication.log"
)


def test_canonical_authentication_sample_produces_flagship_scenario() -> None:
    events = ingest_file(
        SAMPLE_PATH,
        source_type="linux_auth",
        year=2026,
    )

    assert len(events) == 6

    result = analyze_events(events)

    assert [
        alert.rule_id
        for alert in result.alerts
    ] == [
        "AUTH-001",
        "AUTH-002",
    ]

    assert len(result.incidents) == 1
    assert len(result.timelines) == 1

    incident = result.incidents[0]
    timeline = result.timelines[0]

    assert incident.incident_type == (
        "suspicious_authentication"
    )

    assert incident.severity == "high"

    assert incident.source_ips == [
        "203.0.113.20",
    ]

    assert incident.users == [
        "admin",
    ]

    assert set(
        incident.event_ids
    ) == {
        event.event_id
        for event in events
    }

    assert set(
        incident.alert_ids
    ) == {
        alert.alert_id
        for alert in result.alerts
    }

    assert timeline.incident_id == (
        incident.incident_id
    )

    assert len(timeline.entries) == 8

    timeline_event_ids = {
        entry.evidence_id
        for entry in timeline.entries
        if entry.entry_type == "event"
    }

    timeline_alert_ids = {
        entry.evidence_id
        for entry in timeline.entries
        if entry.entry_type == "alert"
    }

    assert timeline_event_ids == {
        event.event_id
        for event in events
    }

    assert timeline_alert_ids == {
        alert.alert_id
        for alert in result.alerts
    }
