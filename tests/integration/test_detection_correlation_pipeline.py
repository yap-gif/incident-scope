from datetime import datetime, timedelta, timezone

from app.correlation.engine import CorrelationEngine
from app.correlation.rules.authentication import (
    SuspiciousAuthenticationCorrelationRule,
)
from app.detection.defaults import (
    build_default_detection_engine,
)
from app.domain.events import Event


BASE_TIME = datetime(
    2026,
    10,
    7,
    14,
    0,
    tzinfo=timezone.utc,
)


def make_auth_event(
    *,
    seconds: int,
    event_type: str,
    action: str,
    source_ip: str = "203.0.113.20",
    user: str = "admin",
) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source_type="linux_auth",
        event_type=event_type,
        source_ip=source_ip,
        hostname="server-01",
        user=user,
        action=action,
        raw_event=(
            f"synthetic {event_type} event "
            f"at {seconds} seconds"
        ),
    )


def test_authentication_events_flow_into_correlated_incident() -> None:
    events = [
        make_auth_event(
            seconds=40,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=0,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=20,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=10,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=30,
            event_type="authentication_failure",
            action="failure",
        ),
        make_auth_event(
            seconds=50,
            event_type="authentication_success",
            action="success",
        ),
    ]

    detection_engine = build_default_detection_engine()

    alerts = detection_engine.evaluate(events)

    auth_alerts = [
        alert
        for alert in alerts
        if alert.rule_id in {
            "AUTH-001",
            "AUTH-002",
        }
    ]

    assert len(auth_alerts) == 2
    assert {
        alert.rule_id
        for alert in auth_alerts
    } == {
        "AUTH-001",
        "AUTH-002",
    }

    correlation_engine = CorrelationEngine(
        [
            SuspiciousAuthenticationCorrelationRule(),
        ]
    )

    incidents = correlation_engine.correlate(alerts)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.incident_type == (
        "suspicious_authentication"
    )
    assert incident.title == (
        "Suspicious Authentication Activity"
    )
    assert incident.severity == "high"

    assert incident.first_seen == BASE_TIME
    assert incident.last_seen == (
        BASE_TIME + timedelta(seconds=50)
    )

    assert incident.source_ips == [
        "203.0.113.20",
    ]
    assert incident.users == [
        "admin",
    ]

    assert {
        alert.alert_id
        for alert in auth_alerts
    } == set(incident.alert_ids)

    input_event_ids = {
        event.event_id
        for event in events
    }

    assert set(incident.event_ids) == input_event_ids


def test_failure_burst_without_success_does_not_create_incident() -> None:
    events = [
        make_auth_event(
            seconds=index * 10,
            event_type="authentication_failure",
            action="failure",
        )
        for index in range(5)
    ]

    detection_engine = build_default_detection_engine()

    alerts = detection_engine.evaluate(events)

    assert {
        alert.rule_id
        for alert in alerts
    } == {
        "AUTH-001",
    }

    correlation_engine = CorrelationEngine(
        [
            SuspiciousAuthenticationCorrelationRule(),
        ]
    )

    incidents = correlation_engine.correlate(alerts)

    assert incidents == []
