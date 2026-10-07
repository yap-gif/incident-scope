from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.domain.incidents import Incident
from app.domain.timelines import (
    InvestigationTimeline,
    TimelineEntry,
)
from app.investigation.report_builder import (
    build_incident_report,
)


BASE_TIME = datetime(
    2026,
    10,
    7,
    21,
    0,
    tzinfo=timezone.utc,
)


def make_incident_and_timeline():
    incident_id = uuid4()

    first_event_id = uuid4()
    second_event_id = uuid4()
    alert_id = uuid4()

    incident = Incident(
        incident_id=incident_id,
        incident_type="suspicious_authentication",
        title="Suspicious Authentication Activity",
        severity="high",
        summary=(
            "Repeated authentication failures were "
            "followed by a successful login."
        ),
        first_seen=BASE_TIME,
        last_seen=(
            BASE_TIME
            + timedelta(seconds=50)
        ),
        alert_ids=[
            alert_id,
        ],
        event_ids=[
            first_event_id,
            second_event_id,
        ],
        source_ips=[
            "203.0.113.20",
        ],
        users=[
            "admin",
        ],
        tags=[
            "authentication",
            "correlated",
        ],
    )

    timeline = InvestigationTimeline(
        incident_id=incident_id,
        title=(
            "Investigation Timeline: "
            "Suspicious Authentication Activity"
        ),
        entries=[
            TimelineEntry(
                timestamp=BASE_TIME,
                entry_type="event",
                evidence_id=first_event_id,
                title="Authentication Failure",
                description=(
                    "Synthetic authentication failure."
                ),
                source_ip="203.0.113.20",
                user="admin",
                details={},
                tags=["event"],
            ),
            TimelineEntry(
                timestamp=(
                    BASE_TIME
                    + timedelta(seconds=40)
                ),
                entry_type="event",
                evidence_id=second_event_id,
                title="Authentication Success",
                description=(
                    "Synthetic authentication success."
                ),
                source_ip="203.0.113.20",
                user="admin",
                details={},
                tags=["event"],
            ),
            TimelineEntry(
                timestamp=(
                    BASE_TIME
                    + timedelta(seconds=50)
                ),
                entry_type="alert",
                evidence_id=alert_id,
                title="AUTH-002 Alert",
                description=(
                    "Successful login after failure burst."
                ),
                source_ip="203.0.113.20",
                user="admin",
                details={
                    "rule_id": "AUTH-002",
                },
                tags=["alert"],
            ),
        ],
    )

    return incident, timeline


def test_build_report_from_incident_and_timeline() -> None:
    incident, timeline = make_incident_and_timeline()

    report = build_incident_report(
        incident,
        timeline,
        analyst_conclusion=(
            "The evidence shows a successful login "
            "following repeated authentication failures."
        ),
        limitations=[
            (
                "The available telemetry does not prove "
                "that the account was compromised."
            ),
        ],
    )

    assert report.incident_id == incident.incident_id
    assert report.incident_type == incident.incident_type
    assert report.title == incident.title
    assert report.severity == incident.severity
    assert report.summary == incident.summary

    assert report.first_seen == incident.first_seen
    assert report.last_seen == incident.last_seen

    assert report.timeline == timeline


def test_builder_preserves_incident_evidence_ids() -> None:
    incident, timeline = make_incident_and_timeline()

    report = build_incident_report(
        incident,
        timeline,
        analyst_conclusion="Evidence reviewed.",
    )

    assert report.alert_ids == incident.alert_ids
    assert report.event_ids == incident.event_ids


def test_builder_preserves_context_fields() -> None:
    incident, timeline = make_incident_and_timeline()

    report = build_incident_report(
        incident,
        timeline,
        analyst_conclusion="Evidence reviewed.",
    )

    assert report.source_ips == incident.source_ips
    assert report.users == incident.users
    assert report.tags == incident.tags


def test_builder_preserves_explicit_analysis() -> None:
    incident, timeline = make_incident_and_timeline()

    conclusion = (
        "The evidence supports suspicious "
        "authentication activity."
    )

    limitations = [
        "No endpoint telemetry is available.",
        "No MFA telemetry is available.",
    ]

    report = build_incident_report(
        incident,
        timeline,
        analyst_conclusion=conclusion,
        limitations=limitations,
    )

    assert report.analyst_conclusion == conclusion
    assert report.limitations == limitations


def test_builder_rejects_timeline_for_different_incident() -> None:
    incident, timeline = make_incident_and_timeline()

    invalid_timeline = timeline.model_copy(
        update={
            "incident_id": uuid4(),
        }
    )

    with pytest.raises(
        ValidationError,
        match=(
            "timeline incident_id must match "
            "report incident_id"
        ),
    ):
        build_incident_report(
            incident,
            invalid_timeline,
            analyst_conclusion="Evidence reviewed.",
        )


def test_builder_rejects_incomplete_timeline_evidence() -> None:
    incident, timeline = make_incident_and_timeline()

    incomplete_timeline = InvestigationTimeline(
        incident_id=incident.incident_id,
        title=timeline.title,
        entries=[
            timeline.entries[0],
            timeline.entries[2],
        ],
    )

    with pytest.raises(
        ValidationError,
        match=(
            "timeline event evidence must match "
            "report event_ids"
        ),
    ):
        build_incident_report(
            incident,
            incomplete_timeline,
            analyst_conclusion="Evidence reviewed.",
        )


def test_builder_output_is_deterministic() -> None:
    incident, timeline = make_incident_and_timeline()

    kwargs = {
        "analyst_conclusion": (
            "The evidence supports suspicious "
            "authentication activity."
        ),
        "limitations": [
            "Synthetic limitation.",
        ],
    }

    first_report = build_incident_report(
        incident,
        timeline,
        **kwargs,
    )

    second_report = build_incident_report(
        incident,
        timeline,
        **kwargs,
    )

    assert first_report == second_report

    assert (
        first_report.model_dump_json(indent=2)
        == second_report.model_dump_json(indent=2)
    )
