from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.correlation.defaults import (
    build_default_correlation_engine,
)
from app.correlation.rules.authentication import (
    SuspiciousAuthenticationCorrelationRule,
)
from app.domain.alerts import Alert


BASE_TIME = datetime(
    2026,
    10,
    7,
    16,
    0,
    tzinfo=timezone.utc,
)


def make_alert(
    *,
    rule_id: str,
    first_seconds: int,
    last_seconds: int,
    event_ids: list,
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
        description="Synthetic default correlation test alert.",
        first_seen=BASE_TIME + timedelta(
            seconds=first_seconds
        ),
        last_seen=BASE_TIME + timedelta(
            seconds=last_seconds
        ),
        source_ip="203.0.113.20",
        user="admin",
        event_ids=event_ids,
        evidence={},
        tags=["synthetic"],
    )


def test_default_engine_registers_mvp_correlation_rule() -> None:
    engine = build_default_correlation_engine()

    assert len(engine.rules) == 1

    rule = engine.rules[0]

    assert isinstance(
        rule,
        SuspiciousAuthenticationCorrelationRule,
    )
    assert rule.correlation_id == "CORR-AUTH-001"


def test_default_engine_correlates_authentication_alerts() -> None:
    shared_event = uuid4()

    failure_alert = make_alert(
        rule_id="AUTH-001",
        first_seconds=0,
        last_seconds=40,
        event_ids=[
            shared_event,
            uuid4(),
        ],
    )

    success_alert = make_alert(
        rule_id="AUTH-002",
        first_seconds=10,
        last_seconds=50,
        event_ids=[
            shared_event,
            uuid4(),
        ],
    )

    engine = build_default_correlation_engine()

    incidents = engine.correlate(
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
        "203.0.113.20",
    ]
    assert set(incident.alert_ids) == {
        failure_alert.alert_id,
        success_alert.alert_id,
    }
