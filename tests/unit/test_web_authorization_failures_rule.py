from datetime import datetime, timedelta, timezone

import pytest

from app.detection.rules.web_authorization_failures import (
    RepeatedAuthorizationFailuresRule,
)
from app.domain.events import Event


BASE_TIME = datetime(
    2026,
    10,
    6,
    10,
    15,
    tzinfo=timezone.utc,
)


def make_http_event(
    *,
    seconds: int,
    status_code: int,
    source_ip: str = "203.0.113.15",
    path: str = "/admin",
) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source_type="http_access",
        event_type="http_request",
        source_ip=source_ip,
        method="GET",
        path=path,
        status_code=status_code,
        user_agent="synthetic-agent",
        raw_event=f"synthetic request at {seconds}",
    )


def test_detect_exact_threshold_within_window() -> None:
    rule = RepeatedAuthorizationFailuresRule()

    events = [
        make_http_event(seconds=0, status_code=401),
        make_http_event(seconds=10, status_code=403),
        make_http_event(seconds=20, status_code=401),
        make_http_event(seconds=30, status_code=403),
        make_http_event(seconds=40, status_code=403),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "WEB-002"
    assert alert.severity == "medium"
    assert alert.source_ip == "203.0.113.15"
    assert alert.first_seen == events[0].timestamp
    assert alert.last_seen == events[4].timestamp
    assert alert.event_ids == [
        event.event_id
        for event in events
    ]
    assert alert.evidence["failure_count"] == 5
    assert alert.evidence["threshold"] == 5
    assert alert.evidence["window_seconds"] == 60
    assert alert.evidence["status_codes"] == [401, 403]


def test_below_threshold_does_not_alert() -> None:
    rule = RepeatedAuthorizationFailuresRule()

    events = [
        make_http_event(seconds=0, status_code=403),
        make_http_event(seconds=10, status_code=403),
        make_http_event(seconds=20, status_code=403),
        make_http_event(seconds=30, status_code=403),
    ]

    assert rule.evaluate(events) == []


def test_failures_outside_window_do_not_alert() -> None:
    rule = RepeatedAuthorizationFailuresRule()

    events = [
        make_http_event(seconds=0, status_code=403),
        make_http_event(seconds=20, status_code=403),
        make_http_event(seconds=40, status_code=403),
        make_http_event(seconds=60, status_code=403),
        make_http_event(seconds=80, status_code=403),
    ]

    assert rule.evaluate(events) == []


def test_different_sources_are_not_combined() -> None:
    rule = RepeatedAuthorizationFailuresRule()

    events = [
        make_http_event(
            seconds=0,
            status_code=403,
            source_ip="203.0.113.15",
        ),
        make_http_event(
            seconds=10,
            status_code=403,
            source_ip="203.0.113.15",
        ),
        make_http_event(
            seconds=20,
            status_code=403,
            source_ip="203.0.113.15",
        ),
        make_http_event(
            seconds=30,
            status_code=403,
            source_ip="198.51.100.9",
        ),
        make_http_event(
            seconds=40,
            status_code=403,
            source_ip="198.51.100.9",
        ),
    ]

    assert rule.evaluate(events) == []


def test_non_failure_status_codes_are_ignored() -> None:
    rule = RepeatedAuthorizationFailuresRule()

    events = [
        make_http_event(seconds=0, status_code=403),
        make_http_event(seconds=10, status_code=403),
        make_http_event(seconds=20, status_code=403),
        make_http_event(seconds=30, status_code=403),
        make_http_event(seconds=40, status_code=404),
        make_http_event(seconds=50, status_code=500),
    ]

    assert rule.evaluate(events) == []


def test_unsorted_events_and_multiple_paths_are_handled() -> None:
    rule = RepeatedAuthorizationFailuresRule()

    events = [
        make_http_event(
            seconds=40,
            status_code=403,
            path="/private",
        ),
        make_http_event(
            seconds=0,
            status_code=401,
            path="/admin",
        ),
        make_http_event(
            seconds=30,
            status_code=403,
            path="/settings",
        ),
        make_http_event(
            seconds=10,
            status_code=401,
            path="/admin",
        ),
        make_http_event(
            seconds=20,
            status_code=403,
            path="/private",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.first_seen == BASE_TIME
    assert alert.last_seen == BASE_TIME + timedelta(seconds=40)
    assert alert.evidence["paths"] == [
        "/admin",
        "/private",
        "/settings",
    ]
    assert alert.evidence["status_codes"] == [401, 403]


def test_reject_invalid_rule_configuration() -> None:
    with pytest.raises(
        ValueError,
        match="threshold must be at least 2",
    ):
        RepeatedAuthorizationFailuresRule(
            threshold=1
        )

    with pytest.raises(
        ValueError,
        match="window_seconds must be greater than 0",
    ):
        RepeatedAuthorizationFailuresRule(
            window_seconds=0
        )
