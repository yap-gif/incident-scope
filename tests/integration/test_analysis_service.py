from datetime import datetime, timedelta, timezone

from app.application.analysis import (
    AnalysisResult,
    analyze_events,
)
from app.domain.events import Event


BASE_TIME = datetime(
    2026,
    10,
    7,
    23,
    30,
    tzinfo=timezone.utc,
)


def make_auth_event(
    *,
    seconds: int,
    event_type: str,
    action: str,
) -> Event:
    return Event(
        timestamp=(
            BASE_TIME
            + timedelta(seconds=seconds)
        ),
        source_type="linux_auth",
        event_type=event_type,
        source_ip="203.0.113.20",
        hostname="server-01",
        user="admin",
        action=action,
        raw_event=(
            f"synthetic {event_type} "
            f"at {seconds}"
        ),
    )


def build_authentication_events() -> list[Event]:
    return [
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=10,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=30,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=40,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=50,
            event_type="authentication_success",
            action="success",
        ),
    ]


def test_analysis_service_runs_complete_pipeline() -> None:
    events = build_authentication_events()

    result = analyze_events(events)

    assert isinstance(
        result,
        AnalysisResult,
    )

    assert result.events == events

    assert [
        alert.rule_id
        for alert in result.alerts
    ] == [
        "AUTH-001",
        "AUTH-002",
    ]

    assert len(result.incidents) == 1
    assert len(result.timelines) == 1

    incident = result.incidents[0]
    timeline = result.timelines[0]

    assert incident.incident_type == (
        "suspicious_authentication"
    )

    assert timeline.incident_id == (
        incident.incident_id
    )

    assert len(timeline.entries) == 8


def test_analysis_service_allows_no_detection() -> None:
    event = make_auth_event(
        seconds=0,
        event_type="authentication_failure",
        action="failure",
    )

    result = analyze_events(
        [event]
    )

    assert result.events == [event]
    assert result.alerts == []
    assert result.incidents == []
    assert result.timelines == []


def test_analysis_service_preserves_uncorrelated_alerts() -> None:
    event = Event(
        timestamp=BASE_TIME,
        source_type="http_access",
        event_type="http_request",
        source_ip="203.0.113.40",
        method="GET",
        path="/admin",
        status_code=404,
        raw_event="synthetic HTTP request",
    )

    result = analyze_events(
        [event]
    )

    assert len(result.events) == 1

    assert [
        alert.rule_id
        for alert in result.alerts
    ] == [
        "WEB-001",
    ]

    assert result.incidents == []
    assert result.timelines == []
