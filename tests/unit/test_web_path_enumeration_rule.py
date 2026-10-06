from datetime import datetime, timedelta, timezone

import pytest

from app.detection.rules.web_path_enumeration import (
    ScanningLikePathEnumerationRule,
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
    path: str,
    status_code: int = 404,
    source_ip: str = "203.0.113.15",
) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source_type="http_access",
        event_type="http_request",
        source_ip=source_ip,
        method="GET",
        path=path,
        status_code=status_code,
        user_agent="synthetic-scanner",
        raw_event=f"synthetic request for {path}",
    )


def test_detect_exact_unique_path_threshold() -> None:
    rule = ScanningLikePathEnumerationRule()

    events = [
        make_http_event(seconds=0, path="/admin"),
        make_http_event(seconds=5, path="/login"),
        make_http_event(seconds=10, path="/.env"),
        make_http_event(seconds=15, path="/backup"),
        make_http_event(seconds=20, path="/config"),
        make_http_event(seconds=25, path="/api"),
        make_http_event(seconds=30, path="/old"),
        make_http_event(seconds=35, path="/test"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "WEB-003"
    assert alert.severity == "medium"
    assert alert.source_ip == "203.0.113.15"
    assert alert.first_seen == events[0].timestamp
    assert alert.last_seen == events[-1].timestamp

    assert alert.evidence["unique_path_count"] == 8
    assert alert.evidence["unique_path_threshold"] == 8
    assert alert.evidence["window_seconds"] == 60


def test_below_unique_path_threshold_does_not_alert() -> None:
    rule = ScanningLikePathEnumerationRule()

    events = [
        make_http_event(
            seconds=index * 5,
            path=f"/path-{index}",
        )
        for index in range(7)
    ]

    assert rule.evaluate(events) == []


def test_duplicate_paths_do_not_increase_unique_count() -> None:
    rule = ScanningLikePathEnumerationRule(
        unique_path_threshold=3
    )

    events = [
        make_http_event(
            seconds=0,
            path="/admin",
        ),
        make_http_event(
            seconds=10,
            path="/ADMIN/",
        ),
        make_http_event(
            seconds=20,
            path="/admin?next=/dashboard",
        ),
        make_http_event(
            seconds=30,
            path="/login",
        ),
    ]

    assert rule.evaluate(events) == []


def test_paths_outside_window_do_not_alert() -> None:
    rule = ScanningLikePathEnumerationRule(
        unique_path_threshold=4,
        window_seconds=30,
    )

    events = [
        make_http_event(
            seconds=0,
            path="/one",
        ),
        make_http_event(
            seconds=20,
            path="/two",
        ),
        make_http_event(
            seconds=40,
            path="/three",
        ),
        make_http_event(
            seconds=60,
            path="/four",
        ),
    ]

    assert rule.evaluate(events) == []


def test_different_sources_are_not_combined() -> None:
    rule = ScanningLikePathEnumerationRule(
        unique_path_threshold=4
    )

    events = [
        make_http_event(
            seconds=0,
            path="/one",
            source_ip="203.0.113.15",
        ),
        make_http_event(
            seconds=10,
            path="/two",
            source_ip="203.0.113.15",
        ),
        make_http_event(
            seconds=20,
            path="/three",
            source_ip="198.51.100.9",
        ),
        make_http_event(
            seconds=30,
            path="/four",
            source_ip="198.51.100.9",
        ),
    ]

    assert rule.evaluate(events) == []


def test_successful_status_codes_are_ignored() -> None:
    rule = ScanningLikePathEnumerationRule(
        unique_path_threshold=3
    )

    events = [
        make_http_event(
            seconds=0,
            path="/one",
            status_code=404,
        ),
        make_http_event(
            seconds=10,
            path="/two",
            status_code=404,
        ),
        make_http_event(
            seconds=20,
            path="/three",
            status_code=200,
        ),
    ]

    assert rule.evaluate(events) == []


def test_unsorted_events_are_processed_chronologically() -> None:
    rule = ScanningLikePathEnumerationRule(
        unique_path_threshold=4
    )

    events = [
        make_http_event(
            seconds=30,
            path="/four",
        ),
        make_http_event(
            seconds=0,
            path="/one",
        ),
        make_http_event(
            seconds=20,
            path="/three",
        ),
        make_http_event(
            seconds=10,
            path="/two",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.first_seen == BASE_TIME
    assert alert.last_seen == (
        BASE_TIME + timedelta(seconds=30)
    )
    assert alert.evidence["paths"] == [
        "/four",
        "/one",
        "/three",
        "/two",
    ]


def test_reject_invalid_rule_configuration() -> None:
    with pytest.raises(
        ValueError,
        match="unique_path_threshold must be at least 2",
    ):
        ScanningLikePathEnumerationRule(
            unique_path_threshold=1
        )

    with pytest.raises(
        ValueError,
        match="window_seconds must be greater than 0",
    ):
        ScanningLikePathEnumerationRule(
            window_seconds=0
        )
