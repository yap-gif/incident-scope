from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.domain.incidents import Incident


BASE_TIME = datetime(
    2026,
    10,
    6,
    12,
    0,
    tzinfo=timezone.utc,
)


def make_incident() -> Incident:
    return Incident(
        incident_type="suspicious_authentication",
        title="Suspicious Authentication Activity",
        severity="high",
        summary=(
            "Repeated authentication failures were followed "
            "by a successful login."
        ),
        first_seen=BASE_TIME,
        last_seen=BASE_TIME + timedelta(seconds=50),
        alert_ids=[
            uuid4(),
            uuid4(),
        ],
        event_ids=[
            uuid4(),
            uuid4(),
            uuid4(),
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


def test_create_valid_incident() -> None:
    incident = make_incident()

    assert incident.incident_type == (
        "suspicious_authentication"
    )
    assert incident.severity == "high"
    assert len(incident.alert_ids) == 2
    assert len(incident.event_ids) == 3
    assert incident.source_ips == [
        "203.0.113.20",
    ]
    assert incident.users == [
        "admin",
    ]


def test_incident_ids_are_generated_independently() -> None:
    first = make_incident()
    second = make_incident()

    assert first.incident_id != second.incident_id


def test_reject_reversed_time_range() -> None:
    with pytest.raises(
        ValidationError,
        match="last_seen cannot be earlier than first_seen",
    ):
        Incident(
            incident_type="test",
            title="Test Incident",
            severity="medium",
            summary="Synthetic incident.",
            first_seen=BASE_TIME + timedelta(seconds=10),
            last_seen=BASE_TIME,
            alert_ids=[uuid4()],
            event_ids=[uuid4()],
        )


def test_reject_duplicate_alert_ids() -> None:
    alert_id = uuid4()

    with pytest.raises(
        ValidationError,
        match="alert_ids must not contain duplicates",
    ):
        Incident(
            incident_type="test",
            title="Test Incident",
            severity="medium",
            summary="Synthetic incident.",
            first_seen=BASE_TIME,
            last_seen=BASE_TIME,
            alert_ids=[
                alert_id,
                alert_id,
            ],
            event_ids=[uuid4()],
        )


def test_reject_duplicate_event_ids() -> None:
    event_id = uuid4()

    with pytest.raises(
        ValidationError,
        match="event_ids must not contain duplicates",
    ):
        Incident(
            incident_type="test",
            title="Test Incident",
            severity="medium",
            summary="Synthetic incident.",
            first_seen=BASE_TIME,
            last_seen=BASE_TIME,
            alert_ids=[uuid4()],
            event_ids=[
                event_id,
                event_id,
            ],
        )


def test_reject_empty_supporting_evidence() -> None:
    with pytest.raises(ValidationError):
        Incident(
            incident_type="test",
            title="Test Incident",
            severity="medium",
            summary="Synthetic incident.",
            first_seen=BASE_TIME,
            last_seen=BASE_TIME,
            alert_ids=[],
            event_ids=[],
        )
