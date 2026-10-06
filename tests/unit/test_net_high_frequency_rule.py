from datetime import datetime, timedelta, timezone

import pytest

from app.detection.rules.net_high_frequency import (
    HighFrequencySourceActivityRule,
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
    source_ip: str | None = "203.0.113.15",
) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source_type="http_access",
        event_type="http_request",
        source_ip=source_ip,
        method="GET",
        path="/",
        status_code=200,
        raw_event=f"synthetic HTTP event at {seconds}",
    )


def make_auth_event(
    *,
    seconds: int,
    source_ip: str | None = "203.0.113.15",
) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source_type="linux_auth",
        event_type="authentication_failure",
        source_ip=source_ip,
        hostname="server-01",
        user="admin",
        action="failure",
        raw_event=f"synthetic auth event at {seconds}",
    )


def test_detect_default_threshold_within_window() -> None:
    rule = HighFrequencySourceActivityRule()

    events = [
        make_http_event(
            seconds=index * 3,
        )
        for index in range(20)
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "NET-001"
    assert alert.severity == "low"
    assert alert.source_ip == "203.0.113.15"
    assert alert.evidence["event_count"] == 20
    assert alert.evidence["threshold"] == 20
    assert alert.evidence["window_seconds"] == 60


def test_below_threshold_does_not_alert() -> None:
    rule = HighFrequencySourceActivityRule(
        threshold=5
    )

    events = [
        make_http_event(seconds=0),
        make_http_event(seconds=10),
        make_http_event(seconds=20),
        make_http_event(seconds=30),
    ]

    assert rule.evaluate(events) == []


def test_events_outside_window_do_not_alert() -> None:
    rule = HighFrequencySourceActivityRule(
        threshold=4,
        window_seconds=30,
    )

    events = [
        make_http_event(seconds=0),
        make_http_event(seconds=20),
        make_http_event(seconds=40),
        make_http_event(seconds=60),
    ]

    assert rule.evaluate(events) == []


def test_different_sources_are_not_combined() -> None:
    rule = HighFrequencySourceActivityRule(
        threshold=4
    )

    events = [
        make_http_event(
            seconds=0,
            source_ip="203.0.113.15",
        ),
        make_http_event(
            seconds=10,
            source_ip="203.0.113.15",
        ),
        make_http_event(
            seconds=20,
            source_ip="198.51.100.9",
        ),
        make_http_event(
            seconds=30,
            source_ip="198.51.100.9",
        ),
    ]

    assert rule.evaluate(events) == []


def test_mixed_source_types_are_counted_together() -> None:
    rule = HighFrequencySourceActivityRule(
        threshold=4
    )

    events = [
        make_http_event(seconds=0),
        make_auth_event(seconds=10),
        make_http_event(seconds=20),
        make_auth_event(seconds=30),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.evidence["event_count"] == 4
    assert alert.evidence["source_types"] == [
        "http_access",
        "linux_auth",
    ]
    assert alert.evidence["event_types"] == [
        "authentication_failure",
        "http_request",
    ]


def test_events_without_source_ip_are_ignored() -> None:
    rule = HighFrequencySourceActivityRule(
        threshold=3
    )

    events = [
        make_http_event(
            seconds=0,
            source_ip=None,
        ),
        make_http_event(
            seconds=10,
            source_ip=None,
        ),
        make_http_event(
            seconds=20,
            source_ip=None,
        ),
    ]

    assert rule.evaluate(events) == []


def test_unsorted_events_are_processed_chronologically() -> None:
    rule = HighFrequencySourceActivityRule(
        threshold=4
    )

    events = [
        make_http_event(seconds=30),
        make_http_event(seconds=0),
        make_http_event(seconds=20),
        make_http_event(seconds=10),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.first_seen == BASE_TIME
    assert alert.last_seen == (
        BASE_TIME + timedelta(seconds=30)
    )


def test_reject_invalid_rule_configuration() -> None:
    with pytest.raises(
        ValueError,
        match="threshold must be at least 2",
    ):
        HighFrequencySourceActivityRule(
            threshold=1
        )

    with pytest.raises(
        ValueError,
        match="window_seconds must be greater than 0",
    ):
        HighFrequencySourceActivityRule(
            window_seconds=0
        )
