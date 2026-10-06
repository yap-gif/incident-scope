from datetime import datetime, timedelta, timezone

from app.detection.rules.auth_failures import (
    RepeatedAuthenticationFailuresRule,
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


def make_auth_failure(
    *,
    seconds: int,
    source_ip: str = "203.0.113.20",
    user: str = "admin",
) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source_type="linux_auth",
        event_type="authentication_failure",
        source_ip=source_ip,
        hostname="server-01",
        user=user,
        action="failure",
        message=f"Failed password for {user}",
        raw_event=f"synthetic failure at {seconds}",
    )


def test_detect_exact_threshold_within_window() -> None:
    rule = RepeatedAuthenticationFailuresRule()

    events = [
        make_auth_failure(seconds=0),
        make_auth_failure(seconds=10),
        make_auth_failure(seconds=20),
        make_auth_failure(seconds=30),
        make_auth_failure(seconds=40),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "AUTH-001"
    assert alert.severity == "medium"
    assert alert.source_ip == "203.0.113.20"
    assert alert.user == "admin"
    assert alert.first_seen == events[0].timestamp
    assert alert.last_seen == events[4].timestamp
    assert alert.event_ids == [
        event.event_id
        for event in events
    ]
    assert alert.evidence["failure_count"] == 5
    assert alert.evidence["threshold"] == 5
    assert alert.evidence["window_seconds"] == 60


def test_below_threshold_does_not_alert() -> None:
    rule = RepeatedAuthenticationFailuresRule()

    events = [
        make_auth_failure(seconds=0),
        make_auth_failure(seconds=10),
        make_auth_failure(seconds=20),
        make_auth_failure(seconds=30),
    ]

    assert rule.evaluate(events) == []


def test_failures_outside_window_do_not_alert() -> None:
    rule = RepeatedAuthenticationFailuresRule()

    events = [
        make_auth_failure(seconds=0),
        make_auth_failure(seconds=20),
        make_auth_failure(seconds=40),
        make_auth_failure(seconds=60),
        make_auth_failure(seconds=80),
    ]

    assert rule.evaluate(events) == []


def test_failures_from_different_sources_are_not_combined() -> None:
    rule = RepeatedAuthenticationFailuresRule()

    events = [
        make_auth_failure(
            seconds=0,
            source_ip="203.0.113.20",
        ),
        make_auth_failure(
            seconds=10,
            source_ip="203.0.113.20",
        ),
        make_auth_failure(
            seconds=20,
            source_ip="203.0.113.20",
        ),
        make_auth_failure(
            seconds=30,
            source_ip="198.51.100.9",
        ),
        make_auth_failure(
            seconds=40,
            source_ip="198.51.100.9",
        ),
    ]

    assert rule.evaluate(events) == []


def test_non_failure_events_are_ignored() -> None:
    rule = RepeatedAuthenticationFailuresRule()

    events = [
        make_auth_failure(seconds=0),
        make_auth_failure(seconds=10),
        make_auth_failure(seconds=20),
        make_auth_failure(seconds=30),
        Event(
            timestamp=BASE_TIME + timedelta(seconds=40),
            source_type="linux_auth",
            event_type="authentication_success",
            source_ip="203.0.113.20",
            hostname="server-01",
            user="admin",
            action="success",
            raw_event="synthetic authentication success",
        ),
    ]

    assert rule.evaluate(events) == []


def test_unsorted_events_and_multiple_users_are_handled() -> None:
    rule = RepeatedAuthenticationFailuresRule()

    events = [
        make_auth_failure(
            seconds=40,
            user="root",
        ),
        make_auth_failure(
            seconds=0,
            user="admin",
        ),
        make_auth_failure(
            seconds=30,
            user="root",
        ),
        make_auth_failure(
            seconds=10,
            user="admin",
        ),
        make_auth_failure(
            seconds=20,
            user="admin",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.first_seen == BASE_TIME
    assert alert.last_seen == BASE_TIME + timedelta(seconds=40)
    assert alert.user is None
    assert alert.evidence["failure_count"] == 5
    assert alert.evidence["users"] == [
        "admin",
        "root",
    ]
