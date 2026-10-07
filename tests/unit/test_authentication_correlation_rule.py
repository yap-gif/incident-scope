from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from app.correlation.rules.authentication import (
    SuspiciousAuthenticationCorrelationRule,
)
from app.domain.alerts import Alert


BASE_TIME = datetime(
    2026,
    10,
    7,
    10,
    0,
    tzinfo=timezone.utc,
)


def make_alert(
    *,
    rule_id: str,
    first_seconds: int,
    last_seconds: int,
    event_ids: list[UUID],
    source_ip: str | None = "203.0.113.20",
    user: str | None = "admin",
) -> Alert:
    if rule_id == "AUTH-001":
        title = "Repeated Authentication Failures"
        severity = "medium"
    elif rule_id == "AUTH-002":
        title = "Successful Login After Failure Burst"
        severity = "high"
    else:
        title = "Other Alert"
        severity = "low"

    return Alert(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description="Synthetic correlation test alert.",
        first_seen=BASE_TIME + timedelta(
            seconds=first_seconds
        ),
        last_seen=BASE_TIME + timedelta(
            seconds=last_seconds
        ),
        source_ip=source_ip,
        user=user,
        event_ids=event_ids,
        evidence={},
        tags=["synthetic"],
    )


def test_correlate_failure_burst_with_success() -> None:
    rule = SuspiciousAuthenticationCorrelationRule()

    failure_events = [
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    ]
    success_event = uuid4()

    failure_alert = make_alert(
        rule_id="AUTH-001",
        first_seconds=0,
        last_seconds=40,
        event_ids=failure_events,
    )

    success_alert = make_alert(
        rule_id="AUTH-002",
        first_seconds=10,
        last_seconds=50,
        event_ids=[
            *failure_events[1:],
            success_event,
        ],
    )

    incidents = rule.correlate(
        [
            success_alert,
            failure_alert,
        ]
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.incident_type == (
        "suspicious_authentication"
    )
    assert incident.severity == "high"
    assert incident.source_ips == [
        "203.0.113.20"
    ]
    assert incident.users == ["admin"]

    assert incident.alert_ids == [
        failure_alert.alert_id,
        success_alert.alert_id,
    ]

    assert incident.first_seen == BASE_TIME
    assert incident.last_seen == (
        BASE_TIME + timedelta(seconds=50)
    )

    assert incident.event_ids == [
        *failure_events,
        success_event,
    ]


def test_missing_auth_001_does_not_correlate() -> None:
    rule = SuspiciousAuthenticationCorrelationRule()

    shared_event = uuid4()

    success_alert = make_alert(
        rule_id="AUTH-002",
        first_seconds=0,
        last_seconds=10,
        event_ids=[shared_event],
    )

    assert rule.correlate([success_alert]) == []


def test_missing_auth_002_does_not_correlate() -> None:
    rule = SuspiciousAuthenticationCorrelationRule()

    failure_alert = make_alert(
        rule_id="AUTH-001",
        first_seconds=0,
        last_seconds=10,
        event_ids=[uuid4()],
    )

    assert rule.correlate([failure_alert]) == []


def test_different_source_ips_do_not_correlate() -> None:
    rule = SuspiciousAuthenticationCorrelationRule()

    shared_event = uuid4()

    failure_alert = make_alert(
        rule_id="AUTH-001",
        first_seconds=0,
        last_seconds=20,
        event_ids=[shared_event],
        source_ip="203.0.113.20",
    )

    success_alert = make_alert(
        rule_id="AUTH-002",
        first_seconds=0,
        last_seconds=30,
        event_ids=[shared_event],
        source_ip="198.51.100.7",
    )

    assert rule.correlate(
        [
            failure_alert,
            success_alert,
        ]
    ) == []


def test_alerts_without_shared_events_do_not_correlate() -> None:
    rule = SuspiciousAuthenticationCorrelationRule()

    failure_alert = make_alert(
        rule_id="AUTH-001",
        first_seconds=0,
        last_seconds=20,
        event_ids=[uuid4()],
    )

    success_alert = make_alert(
        rule_id="AUTH-002",
        first_seconds=0,
        last_seconds=30,
        event_ids=[uuid4()],
    )

    assert rule.correlate(
        [
            failure_alert,
            success_alert,
        ]
    ) == []


def test_failure_alert_after_success_does_not_correlate() -> None:
    rule = SuspiciousAuthenticationCorrelationRule()

    shared_event = uuid4()

    failure_alert = make_alert(
        rule_id="AUTH-001",
        first_seconds=40,
        last_seconds=50,
        event_ids=[shared_event],
    )

    success_alert = make_alert(
        rule_id="AUTH-002",
        first_seconds=0,
        last_seconds=30,
        event_ids=[shared_event],
    )

    assert rule.correlate(
        [
            failure_alert,
            success_alert,
        ]
    ) == []


def test_best_matching_failure_alert_is_selected() -> None:
    rule = SuspiciousAuthenticationCorrelationRule()

    first_shared = uuid4()
    second_shared = uuid4()
    third_shared = uuid4()
    success_event = uuid4()

    weaker_failure_alert = make_alert(
        rule_id="AUTH-001",
        first_seconds=0,
        last_seconds=20,
        event_ids=[
            first_shared,
        ],
    )

    stronger_failure_alert = make_alert(
        rule_id="AUTH-001",
        first_seconds=5,
        last_seconds=25,
        event_ids=[
            first_shared,
            second_shared,
            third_shared,
        ],
    )

    success_alert = make_alert(
        rule_id="AUTH-002",
        first_seconds=0,
        last_seconds=40,
        event_ids=[
            first_shared,
            second_shared,
            third_shared,
            success_event,
        ],
    )

    incidents = rule.correlate(
        [
            weaker_failure_alert,
            success_alert,
            stronger_failure_alert,
        ]
    )

    assert len(incidents) == 1

    assert incidents[0].alert_ids == [
        stronger_failure_alert.alert_id,
        success_alert.alert_id,
    ]


def test_multiple_success_alerts_create_independent_incidents() -> None:
    rule = SuspiciousAuthenticationCorrelationRule()

    first_failure_event = uuid4()
    second_failure_event = uuid4()

    first_failure_alert = make_alert(
        rule_id="AUTH-001",
        first_seconds=0,
        last_seconds=10,
        event_ids=[first_failure_event],
    )

    first_success_alert = make_alert(
        rule_id="AUTH-002",
        first_seconds=0,
        last_seconds=20,
        event_ids=[
            first_failure_event,
            uuid4(),
        ],
    )

    second_failure_alert = make_alert(
        rule_id="AUTH-001",
        first_seconds=100,
        last_seconds=110,
        event_ids=[second_failure_event],
    )

    second_success_alert = make_alert(
        rule_id="AUTH-002",
        first_seconds=100,
        last_seconds=120,
        event_ids=[
            second_failure_event,
            uuid4(),
        ],
    )

    incidents = rule.correlate(
        [
            second_success_alert,
            first_failure_alert,
            second_failure_alert,
            first_success_alert,
        ]
    )

    assert len(incidents) == 2

    assert incidents[0].last_seen == (
        BASE_TIME + timedelta(seconds=20)
    )
    assert incidents[1].last_seen == (
        BASE_TIME + timedelta(seconds=120)
    )
