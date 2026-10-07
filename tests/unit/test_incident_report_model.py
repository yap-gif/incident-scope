import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.domain.reports import IncidentReport
from app.domain.timelines import (
    InvestigationTimeline,
    TimelineEntry,
)


BASE_TIME = datetime(
    2026,
    10,
    7,
    20,
    0,
    tzinfo=timezone.utc,
)


def make_report() -> IncidentReport:
    incident_id = uuid4()
    event_id = uuid4()
    alert_id = uuid4()

    timeline = InvestigationTimeline(
        incident_id=incident_id,
        title="Investigation Timeline",
        entries=[
            TimelineEntry(
                timestamp=BASE_TIME,
                entry_type="event",
                evidence_id=event_id,
                title="Authentication Failure",
                description=(
                    "Synthetic authentication failure."
                ),
                source_ip="203.0.113.20",
                user="admin",
                details={
                    "event_type": (
                        "authentication_failure"
                    ),
                },
                tags=["event"],
            ),
            TimelineEntry(
                timestamp=(
                    BASE_TIME
                    + timedelta(seconds=10)
                ),
                entry_type="alert",
                evidence_id=alert_id,
                title="AUTH-001 Alert",
                description=(
                    "Repeated authentication failures."
                ),
                source_ip="203.0.113.20",
                user="admin",
                details={
                    "rule_id": "AUTH-001",
                    "severity": "medium",
                },
                tags=["alert"],
            ),
        ],
    )

    return IncidentReport(
        incident_id=incident_id,
        incident_type="suspicious_authentication",
        title="Suspicious Authentication Activity",
        severity="high",
        summary=(
            "Repeated authentication failures were "
            "followed by suspicious authentication activity."
        ),
        first_seen=BASE_TIME,
        last_seen=(
            BASE_TIME
            + timedelta(seconds=10)
        ),
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
        alert_ids=[
            alert_id,
        ],
        event_ids=[
            event_id,
        ],
        timeline=timeline,
        analyst_conclusion=(
            "The available evidence shows repeated "
            "authentication failures associated with "
            "the incident."
        ),
        limitations=[
            (
                "The available telemetry does not by "
                "itself prove account compromise."
            ),
        ],
    )


def test_create_valid_incident_report() -> None:
    report = make_report()

    assert report.report_version == "1.0"

    assert report.incident_type == (
        "suspicious_authentication"
    )

    assert report.severity == "high"

    assert report.timeline.incident_id == (
        report.incident_id
    )

    assert len(report.alert_ids) == 1
    assert len(report.event_ids) == 1


def test_reject_reversed_report_time_range() -> None:
    report = make_report()

    with pytest.raises(
        ValidationError,
        match="last_seen cannot be earlier than first_seen",
    ):
        report.model_copy(
            update={
                "first_seen": (
                    BASE_TIME
                    + timedelta(seconds=20)
                ),
                "last_seen": BASE_TIME,
            }
        ).model_validate(
            report.model_copy(
                update={
                    "first_seen": (
                        BASE_TIME
                        + timedelta(seconds=20)
                    ),
                    "last_seen": BASE_TIME,
                }
            ).model_dump()
        )


def test_reject_duplicate_alert_ids() -> None:
    report = make_report()
    alert_id = report.alert_ids[0]

    data = report.model_dump()
    data["alert_ids"] = [
        alert_id,
        alert_id,
    ]

    with pytest.raises(
        ValidationError,
        match="alert_ids must not contain duplicates",
    ):
        IncidentReport.model_validate(data)


def test_reject_duplicate_event_ids() -> None:
    report = make_report()
    event_id = report.event_ids[0]

    data = report.model_dump()
    data["event_ids"] = [
        event_id,
        event_id,
    ]

    with pytest.raises(
        ValidationError,
        match="event_ids must not contain duplicates",
    ):
        IncidentReport.model_validate(data)


def test_reject_timeline_for_different_incident() -> None:
    report = make_report()

    data = report.model_dump()
    data["timeline"]["incident_id"] = uuid4()

    with pytest.raises(
        ValidationError,
        match=(
            "timeline incident_id must match "
            "report incident_id"
        ),
    ):
        IncidentReport.model_validate(data)


def test_reject_timeline_evidence_mismatch() -> None:
    report = make_report()

    data = report.model_dump()

    data["event_ids"] = [
        uuid4(),
    ]

    with pytest.raises(
        ValidationError,
        match=(
            "timeline event evidence must match "
            "report event_ids"
        ),
    ):
        IncidentReport.model_validate(data)


def test_json_serialization_round_trip() -> None:
    report = make_report()

    serialized = report.model_dump_json(
        indent=2
    )

    payload = json.loads(serialized)

    assert payload["report_version"] == "1.0"

    assert payload["incident_id"] == str(
        report.incident_id
    )

    serialized_first_seen = datetime.fromisoformat(
        payload["first_seen"].replace(
            "Z",
            "+00:00",
        )
    )

    assert serialized_first_seen == report.first_seen

    assert payload["timeline"]["incident_id"] == (
        str(report.incident_id)
    )

    assert payload["timeline"]["entries"][0][
        "entry_type"
    ] == "event"

    restored = IncidentReport.model_validate_json(
        serialized
    )

    assert restored == report

    assert isinstance(
        restored.incident_id,
        UUID,
    )
