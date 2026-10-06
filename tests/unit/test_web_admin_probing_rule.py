from datetime import datetime, timedelta, timezone

from app.detection.rules.web_admin_probing import (
    SuspiciousAdministrativePathProbingRule,
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
    seconds: int = 0,
    path: str,
    source_ip: str = "203.0.113.15",
    status_code: int = 404,
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
        raw_event=f"synthetic request for {path}",
    )


def test_detect_admin_path() -> None:
    rule = SuspiciousAdministrativePathProbingRule()

    event = make_http_event(
        path="/admin",
    )

    alerts = rule.evaluate([event])

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert.rule_id == "WEB-001"
    assert alert.severity == "medium"
    assert alert.source_ip == "203.0.113.15"
    assert alert.event_ids == [event.event_id]
    assert alert.evidence["normalized_path"] == "/admin"
    assert alert.evidence["matched_pattern"] == "/admin"


def test_detect_nested_admin_path_with_query_string() -> None:
    rule = SuspiciousAdministrativePathProbingRule()

    event = make_http_event(
        path="/admin/login?next=/dashboard",
    )

    alerts = rule.evaluate([event])

    assert len(alerts) == 1
    assert alerts[0].evidence["normalized_path"] == "/admin/login"
    assert alerts[0].evidence["matched_pattern"] == "/admin"


def test_detect_case_insensitive_wordpress_admin_path() -> None:
    rule = SuspiciousAdministrativePathProbingRule()

    event = make_http_event(
        path="/WP-ADMIN/",
    )

    alerts = rule.evaluate([event])

    assert len(alerts) == 1
    assert alerts[0].evidence["normalized_path"] == "/wp-admin"
    assert alerts[0].evidence["matched_pattern"] == "/wp-admin"


def test_detect_sensitive_env_path() -> None:
    rule = SuspiciousAdministrativePathProbingRule()

    event = make_http_event(
        path="/.env",
        status_code=403,
    )

    alerts = rule.evaluate([event])

    assert len(alerts) == 1
    assert alerts[0].evidence["matched_pattern"] == "/.env"
    assert alerts[0].evidence["status_code"] == 403


def test_ignore_benign_path() -> None:
    rule = SuspiciousAdministrativePathProbingRule()

    event = make_http_event(
        path="/products",
        status_code=200,
    )

    assert rule.evaluate([event]) == []


def test_ignore_admin_lookalike_path() -> None:
    rule = SuspiciousAdministrativePathProbingRule()

    event = make_http_event(
        path="/administer",
    )

    assert rule.evaluate([event]) == []


def test_ignore_non_http_event() -> None:
    rule = SuspiciousAdministrativePathProbingRule()

    event = Event(
        timestamp=BASE_TIME,
        source_type="linux_auth",
        event_type="authentication_failure",
        source_ip="203.0.113.20",
        hostname="server-01",
        user="admin",
        action="failure",
        raw_event="synthetic authentication failure",
    )

    assert rule.evaluate([event]) == []


def test_multiple_matches_are_ordered_chronologically() -> None:
    rule = SuspiciousAdministrativePathProbingRule()

    later_event = make_http_event(
        seconds=30,
        path="/phpmyadmin",
    )

    earlier_event = make_http_event(
        seconds=10,
        path="/admin",
    )

    alerts = rule.evaluate(
        [
            later_event,
            earlier_event,
        ]
    )

    assert len(alerts) == 2

    assert alerts[0].first_seen == (
        BASE_TIME + timedelta(seconds=10)
    )
    assert alerts[0].event_ids == [
        earlier_event.event_id
    ]

    assert alerts[1].first_seen == (
        BASE_TIME + timedelta(seconds=30)
    )
    assert alerts[1].event_ids == [
        later_event.event_id
    ]
