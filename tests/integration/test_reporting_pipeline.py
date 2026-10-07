import json
from datetime import datetime, timedelta, timezone

from app.correlation.defaults import (
    build_default_correlation_engine,
)
from app.detection.defaults import (
    build_default_detection_engine,
)
from app.domain.events import Event
from app.domain.reports import IncidentReport
from app.investigation.report_builder import (
    build_incident_report,
)
from app.investigation.timeline_builder import (
    build_investigation_timeline,
)


BASE_TIME = datetime(
    2026,
    10,
    7,
    22,
    0,
    tzinfo=timezone.utc,
)


def make_auth_event(
    *,
    seconds: int,
    event_type: str,
    action: str,
) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(
            seconds=seconds
        ),
        source_type="linux_auth",
        event_type=event_type,
        source_ip="203.0.113.20",
        hostname="server-01",
        user="admin",
        action=action,
        raw_event=(
            f"synthetic {event_type} "
            f"at {seconds}"
        ),
    )


def build_authentication_events() -> list[Event]:
    events = [
        make_auth_event(
            seconds=40,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=10,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=30,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=50,
            event_type="authentication_success",
            action="success",
        ),
    ]

    return events


def test_full_security_analysis_pipeline_produces_report() -> None:
    events = build_authentication_events()

    detection_engine = build_default_detection_engine()

    alerts = detection_engine.evaluate(events)

    assert {
        alert.rule_id
        for alert in alerts
    } == {
        "AUTH-001",
        "AUTH-002",
    }

    correlation_engine = (
        build_default_correlation_engine()
    )

    incidents = correlation_engine.correlate(
        alerts
    )

    assert len(incidents) == 1

    incident = incidents[0]

    timeline = build_investigation_timeline(
        incident,
        alerts,
        events,
    )

    assert timeline.incident_id == (
        incident.incident_id
    )

    assert len(timeline.entries) == 8

    report = build_incident_report(
        incident,
        timeline,
        analyst_conclusion=(
            "The available evidence shows repeated "
            "authentication failures followed by a "
            "successful login from the same source IP."
        ),
        limitations=[
            (
                "The available authentication telemetry "
                "does not by itself prove that the account "
                "was compromised."
            ),
        ],
    )

    assert report.incident_id == (
        incident.incident_id
    )

    assert report.incident_type == (
        "suspicious_authentication"
    )

    assert report.severity == "high"

    assert report.source_ips == [
        "203.0.113.20",
    ]

    assert report.users == [
        "admin",
    ]

    assert report.timeline == timeline


def test_report_json_preserves_complete_evidence_chain() -> None:
    events = build_authentication_events()

    alerts = (
        build_default_detection_engine()
        .evaluate(events)
    )

    incidents = (
        build_default_correlation_engine()
        .correlate(alerts)
    )

    assert len(incidents) == 1

    incident = incidents[0]

    timeline = build_investigation_timeline(
        incident,
        alerts,
        events,
    )

    report = build_incident_report(
        incident,
        timeline,
        analyst_conclusion=(
            "The evidence supports suspicious "
            "authentication activity."
        ),
        limitations=[
            (
                "No endpoint telemetry is available "
                "to independently confirm compromise."
            ),
        ],
    )

    serialized = report.model_dump_json(
        indent=2
    )

    payload = json.loads(serialized)

    assert payload["report_version"] == "1.0"

    assert payload["incident_id"] == str(
        incident.incident_id
    )

    input_event_ids = {
        event.event_id
        for event in events
    }

    auth_alert_ids = {
        alert.alert_id
        for alert in alerts
        if alert.rule_id in {
            "AUTH-001",
            "AUTH-002",
        }
    }

    assert set(report.event_ids) == (
        input_event_ids
    )

    assert set(report.alert_ids) == (
        auth_alert_ids
    )

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

    assert timeline_event_ids == (
        input_event_ids
    )

    assert timeline_alert_ids == (
        auth_alert_ids
    )

    assert {
        entry["evidence_id"]
        for entry in payload["timeline"]["entries"]
        if entry["entry_type"] == "event"
    } == {
        str(event_id)
        for event_id in input_event_ids
    }

    assert {
        entry["evidence_id"]
        for entry in payload["timeline"]["entries"]
        if entry["entry_type"] == "alert"
    } == {
        str(alert_id)
        for alert_id in auth_alert_ids
    }

    restored = (
        IncidentReport.model_validate_json(
            serialized
        )
    )

    assert restored == report


def test_report_timeline_is_chronological() -> None:
    events = build_authentication_events()

    alerts = (
        build_default_detection_engine()
        .evaluate(events)
    )

    incident = (
        build_default_correlation_engine()
        .correlate(alerts)[0]
    )

    timeline = build_investigation_timeline(
        incident,
        alerts,
        events,
    )

    timestamps = [
        entry.timestamp
        for entry in timeline.entries
    ]

    assert timestamps == sorted(timestamps)

    assert timeline.entries[0].timestamp == (
        BASE_TIME
    )

    assert timeline.entries[-1].timestamp == (
        BASE_TIME + timedelta(seconds=50)
    )
