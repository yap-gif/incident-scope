from datetime import datetime, timedelta, timezone

import pytest

from app.detection.rules.auth_success_after_failures import (
    SuccessfulLoginAfterFailureBurstRule,
)
from app.domain.events import Event


BASE_TIME = datetime(
    2026,
    10,
    6,
    10,
    20,
    tzinfo=timezone.utc,
)


def make_auth_event(
    *,
    seconds: int,
    event_type: str,
    source_ip: str = "203.0.113.20",
    user: str = "admin",
) -> Event:
    action = (
        "failure"
        if event_type == "authentication_failure"
        else "success"
    )

    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source_type="linux_auth",
        event_type=event_type,
        source_ip=source_ip,
        hostname="server-01",
        user=user,
        action=action,
        message=f"synthetic {event_type}",
        raw_event=f"synthetic event at {seconds}",
    )


def test_detect_success_after_failure_burst() -> None:
    rule = SuccessfulLoginAfterFailureBurstRule()

    events = [
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=40,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=50,
            event_type="authentication_success",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "AUTH-002"
    assert alert.severity == "high"
    assert alert.source_ip == "203.0.113.20"
    assert alert.user == "admin"
    assert alert.first_seen == events[0].timestamp
    assert alert.last_seen == events[3].timestamp
    assert alert.event_ids == [
        event.event_id
        for event in events
    ]
    assert alert.evidence["failure_count"] == 3
    assert alert.evidence["failure_threshold"] == 3
    assert alert.evidence["lookback_seconds"] == 120
    assert alert.evidence["successful_user"] == "admin"


def test_below_failure_threshold_does_not_alert() -> None:
    rule = SuccessfulLoginAfterFailureBurstRule()

    events = [
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=30,
            event_type="authentication_success",
        ),
    ]

    assert rule.evaluate(events) == []


def test_old_failures_outside_lookback_are_ignored() -> None:
    rule = SuccessfulLoginAfterFailureBurstRule()

    events = [
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=10,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=200,
            event_type="authentication_success",
        ),
    ]

    assert rule.evaluate(events) == []


def test_different_sources_are_not_combined() -> None:
    rule = SuccessfulLoginAfterFailureBurstRule()

    events = [
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
            source_ip="203.0.113.20",
        ),
        make_auth_event(
            seconds=10,
            event_type="authentication_failure",
            source_ip="203.0.113.20",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
            source_ip="198.51.100.9",
        ),
        make_auth_event(
            seconds=30,
            event_type="authentication_success",
            source_ip="203.0.113.20",
        ),
    ]

    assert rule.evaluate(events) == []


def test_success_before_failures_does_not_alert() -> None:
    rule = SuccessfulLoginAfterFailureBurstRule()

    events = [
        make_auth_event(
            seconds=0,
            event_type="authentication_success",
        ),
        make_auth_event(
            seconds=10,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=30,
            event_type="authentication_failure",
        ),
    ]

    assert rule.evaluate(events) == []


def test_multiple_failure_users_can_precede_success() -> None:
    rule = SuccessfulLoginAfterFailureBurstRule()

    events = [
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
            user="root",
        ),
        make_auth_event(
            seconds=10,
            event_type="authentication_failure",
            user="guest",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
            user="admin",
        ),
        make_auth_event(
            seconds=30,
            event_type="authentication_success",
            user="admin",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].user == "admin"
    assert alerts[0].evidence["failure_users"] == [
        "admin",
        "guest",
        "root",
    ]


def test_unsorted_events_are_processed_chronologically() -> None:
    rule = SuccessfulLoginAfterFailureBurstRule()

    events = [
        make_auth_event(
            seconds=50,
            event_type="authentication_success",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=40,
            event_type="authentication_failure",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].first_seen == BASE_TIME
    assert alerts[0].last_seen == BASE_TIME + timedelta(seconds=50)


def test_success_resets_failure_sequence() -> None:
    rule = SuccessfulLoginAfterFailureBurstRule()

    events = [
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=10,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=30,
            event_type="authentication_success",
        ),
        make_auth_event(
            seconds=40,
            event_type="authentication_success",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1


def test_two_independent_bursts_create_two_alerts() -> None:
    rule = SuccessfulLoginAfterFailureBurstRule()

    events = [
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=10,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=30,
            event_type="authentication_success",
        ),
        make_auth_event(
            seconds=60,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=70,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=80,
            event_type="authentication_failure",
        ),
        make_auth_event(
            seconds=90,
            event_type="authentication_success",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 2
    assert alerts[0].last_seen == BASE_TIME + timedelta(seconds=30)
    assert alerts[1].last_seen == BASE_TIME + timedelta(seconds=90)


def test_reject_invalid_rule_configuration() -> None:
    with pytest.raises(
        ValueError,
        match="failure_threshold must be at least 2",
    ):
        SuccessfulLoginAfterFailureBurstRule(
            failure_threshold=1
        )

    with pytest.raises(
        ValueError,
        match="lookback_seconds must be greater than 0",
    ):
        SuccessfulLoginAfterFailureBurstRule(
            lookback_seconds=0
        )
