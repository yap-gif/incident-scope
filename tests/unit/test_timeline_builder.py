from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.domain.alerts import Alert
from app.domain.events import Event
from app.domain.incidents import Incident
from app.investigation.timeline_builder import (
    TimelineEvidenceError,
    build_investigation_timeline,
)


BASE_TIME = datetime(
    2026,
    10,
    7,
    19,
    0,
    tzinfo=timezone.utc,
)


def make_event(
    *,
    seconds: int,
    event_type: str = "authentication_failure",
    source_ip: str = "203.0.113.20",
) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(
            seconds=seconds
        ),
        source_type="linux_auth",
        event_type=event_type,
        source_ip=source_ip,
        hostname="server-01",
        user="admin",
        action=(
            "success"
            if event_type == "authentication_success"
            else "failure"
        ),
        message="Synthetic normalized event.",
        raw_event=(
            f"synthetic {event_type} "
            f"at {seconds}"
        ),
        metadata={
            "synthetic": True,
        },
    )


def make_alert(
    *,
    first_seconds: int,
    last_seconds: int,
    event_ids: list,
    rule_id: str = "AUTH-001",
) -> Alert:
    if rule_id == "AUTH-001":
        title = "Repeated Authentication Failures"
        severity = "medium"
    else:
        title = "Successful Login After Failure Burst"
        severity = "high"

    return Alert(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description="Synthetic security alert.",
        first_seen=BASE_TIME + timedelta(
            seconds=first_seconds
        ),
        last_seen=BASE_TIME + timedelta(
            seconds=last_seconds
        ),
        source_ip="203.0.113.20",
        user="admin",
        event_ids=event_ids,
        evidence={
            "synthetic": True,
        },
        tags=[
            "authentication",
        ],
    )


def make_incident(
    *,
    alert_ids: list,
    event_ids: list,
) -> Incident:
    return Incident(
        incident_type="suspicious_authentication",
        title="Suspicious Authentication Activity",
        severity="high",
        summary="Synthetic correlated incident.",
        first_seen=BASE_TIME,
        last_seen=BASE_TIME + timedelta(
            seconds=50
        ),
        alert_ids=alert_ids,
        event_ids=event_ids,
        source_ips=[
            "203.0.113.20",
        ],
        users=[
            "admin",
        ],
        tags=[
            "authentication",
        ],
    )


def test_builder_uses_only_incident_evidence() -> None:
    event = make_event(seconds=0)
    unrelated_event = make_event(seconds=100)

    alert = make_alert(
        first_seconds=0,
        last_seconds=10,
        event_ids=[
            event.event_id,
        ],
    )

    unrelated_alert = make_alert(
        first_seconds=100,
        last_seconds=110,
        event_ids=[
            unrelated_event.event_id,
        ],
    )

    incident = make_incident(
        alert_ids=[
            alert.alert_id,
        ],
        event_ids=[
            event.event_id,
        ],
    )

    timeline = build_investigation_timeline(
        incident,
        [
            unrelated_alert,
            alert,
        ],
        [
            unrelated_event,
            event,
        ],
    )

    assert {
        entry.evidence_id
        for entry in timeline.entries
    } == {
        event.event_id,
        alert.alert_id,
    }


def test_builder_orders_unsorted_evidence_chronologically() -> None:
    first_event = make_event(seconds=0)
    second_event = make_event(seconds=20)

    alert = make_alert(
        first_seconds=0,
        last_seconds=30,
        event_ids=[
            first_event.event_id,
            second_event.event_id,
        ],
    )

    incident = make_incident(
        alert_ids=[
            alert.alert_id,
        ],
        event_ids=[
            second_event.event_id,
            first_event.event_id,
        ],
    )

    timeline = build_investigation_timeline(
        incident,
        [alert],
        [
            second_event,
            first_event,
        ],
    )

    assert [
        entry.evidence_id
        for entry in timeline.entries
    ] == [
        first_event.event_id,
        second_event.event_id,
        alert.alert_id,
    ]


def test_event_precedes_alert_at_equal_timestamp() -> None:
    event = make_event(seconds=20)

    alert = make_alert(
        first_seconds=0,
        last_seconds=20,
        event_ids=[
            event.event_id,
        ],
    )

    incident = make_incident(
        alert_ids=[
            alert.alert_id,
        ],
        event_ids=[
            event.event_id,
        ],
    )

    timeline = build_investigation_timeline(
        incident,
        [alert],
        [event],
    )

    assert [
        entry.entry_type
        for entry in timeline.entries
    ] == [
        "event",
        "alert",
    ]


def test_missing_supporting_alert_fails_fast() -> None:
    event = make_event(seconds=0)

    incident = make_incident(
        alert_ids=[
            uuid4(),
        ],
        event_ids=[
            event.event_id,
        ],
    )

    with pytest.raises(
        TimelineEvidenceError,
        match="missing supporting alert evidence",
    ):
        build_investigation_timeline(
            incident,
            [],
            [event],
        )


def test_missing_supporting_event_fails_fast() -> None:
    missing_event_id = uuid4()

    alert = make_alert(
        first_seconds=0,
        last_seconds=10,
        event_ids=[
            missing_event_id,
        ],
    )

    incident = make_incident(
        alert_ids=[
            alert.alert_id,
        ],
        event_ids=[
            missing_event_id,
        ],
    )

    with pytest.raises(
        TimelineEvidenceError,
        match="missing supporting event evidence",
    ):
        build_investigation_timeline(
            incident,
            [alert],
            [],
        )


def test_event_entry_preserves_source_evidence() -> None:
    event = make_event(seconds=0)

    alert = make_alert(
        first_seconds=0,
        last_seconds=10,
        event_ids=[
            event.event_id,
        ],
    )

    incident = make_incident(
        alert_ids=[
            alert.alert_id,
        ],
        event_ids=[
            event.event_id,
        ],
    )

    timeline = build_investigation_timeline(
        incident,
        [alert],
        [event],
    )

    entry = next(
        entry
        for entry in timeline.entries
        if entry.entry_type == "event"
    )

    assert entry.evidence_id == event.event_id
    assert entry.timestamp == event.timestamp
    assert entry.source_ip == event.source_ip
    assert entry.user == event.user

    assert entry.details["source_type"] == (
        "linux_auth"
    )
    assert entry.details["event_type"] == (
        "authentication_failure"
    )
    assert entry.details["raw_event"] == (
        event.raw_event
    )


def test_alert_entry_preserves_alert_evidence() -> None:
    event = make_event(seconds=0)

    alert = make_alert(
        first_seconds=0,
        last_seconds=20,
        event_ids=[
            event.event_id,
        ],
    )

    incident = make_incident(
        alert_ids=[
            alert.alert_id,
        ],
        event_ids=[
            event.event_id,
        ],
    )

    timeline = build_investigation_timeline(
        incident,
        [alert],
        [event],
    )

    entry = next(
        entry
        for entry in timeline.entries
        if entry.entry_type == "alert"
    )

    assert entry.evidence_id == alert.alert_id
    assert entry.timestamp == alert.last_seen

    assert entry.details["rule_id"] == (
        "AUTH-001"
    )
    assert entry.details["severity"] == (
        "medium"
    )
    assert entry.details["first_seen"] == (
        "2026-10-07T19:00:00Z"
    )
    assert entry.details["last_seen"] == (
        "2026-10-07T19:00:20Z"
    )

    assert entry.details[
        "supporting_event_ids"
    ] == [
        str(event.event_id)
    ]


def test_builder_output_is_independent_of_input_order() -> None:
    first_event = make_event(seconds=0)
    second_event = make_event(seconds=10)

    alert = make_alert(
        first_seconds=0,
        last_seconds=20,
        event_ids=[
            first_event.event_id,
            second_event.event_id,
        ],
    )

    incident = make_incident(
        alert_ids=[
            alert.alert_id,
        ],
        event_ids=[
            first_event.event_id,
            second_event.event_id,
        ],
    )

    first_timeline = build_investigation_timeline(
        incident,
        [alert],
        [
            first_event,
            second_event,
        ],
    )

    second_timeline = build_investigation_timeline(
        incident,
        [alert],
        [
            second_event,
            first_event,
        ],
    )

    first_refs = [
        (
            entry.timestamp,
            entry.entry_type,
            entry.evidence_id,
        )
        for entry in first_timeline.entries
    ]

    second_refs = [
        (
            entry.timestamp,
            entry.entry_type,
            entry.evidence_id,
        )
        for entry in second_timeline.entries
    ]

    assert first_refs == second_refs


def test_timeline_details_are_json_round_trip_safe() -> None:
    metadata_reference = uuid4()
    evidence_reference = uuid4()

    event = make_event(seconds=0)

    event = event.model_copy(
        update={
            "metadata": {
                "observed_at": BASE_TIME,
                "reference_id": metadata_reference,
                "nested": {
                    "references": [
                        metadata_reference,
                    ],
                },
            },
        }
    )

    alert = make_alert(
        first_seconds=0,
        last_seconds=20,
        event_ids=[
            event.event_id,
        ],
    )

    alert = alert.model_copy(
        update={
            "evidence": {
                "observed_at": (
                    BASE_TIME
                    + timedelta(seconds=20)
                ),
                "reference_id": evidence_reference,
            },
        }
    )

    incident = make_incident(
        alert_ids=[
            alert.alert_id,
        ],
        event_ids=[
            event.event_id,
        ],
    )

    timeline = build_investigation_timeline(
        incident,
        [alert],
        [event],
    )

    event_entry = next(
        entry
        for entry in timeline.entries
        if entry.entry_type == "event"
    )

    alert_entry = next(
        entry
        for entry in timeline.entries
        if entry.entry_type == "alert"
    )

    assert event_entry.details[
        "metadata"
    ]["observed_at"] == (
        "2026-10-07T19:00:00Z"
    )

    assert event_entry.details[
        "metadata"
    ]["reference_id"] == str(
        metadata_reference
    )

    assert event_entry.details[
        "metadata"
    ]["nested"]["references"] == [
        str(metadata_reference)
    ]

    assert alert_entry.details[
        "first_seen"
    ] == "2026-10-07T19:00:00Z"

    assert alert_entry.details[
        "last_seen"
    ] == "2026-10-07T19:00:20Z"

    assert alert_entry.details[
        "supporting_event_ids"
    ] == [
        str(event.event_id)
    ]

    assert alert_entry.details[
        "evidence"
    ]["observed_at"] == (
        "2026-10-07T19:00:20Z"
    )

    assert alert_entry.details[
        "evidence"
    ]["reference_id"] == str(
        evidence_reference
    )

    serialized = timeline.model_dump_json()

    restored = type(
        timeline
    ).model_validate_json(
        serialized
    )

    assert restored == timeline
