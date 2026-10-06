from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

import pytest

from app.detection.base import DetectionRule
from app.detection.engine import DetectionEngine
from app.detection.rules.auth_failures import (
    RepeatedAuthenticationFailuresRule,
)
from app.detection.rules.auth_success_after_failures import (
    SuccessfulLoginAfterFailureBurstRule,
)
from app.domain.alerts import Alert
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


class BrokenRule(DetectionRule):
    rule_id = "TEST-BROKEN"
    title = "Broken Rule"
    severity = "low"

    def evaluate(
        self,
        events: Sequence[Event],
    ) -> list[Alert]:
        raise RuntimeError("synthetic rule failure")


def test_empty_engine_returns_no_alerts() -> None:
    engine = DetectionEngine([])

    assert engine.evaluate([]) == []


def test_engine_rejects_duplicate_rule_ids() -> None:
    with pytest.raises(
        ValueError,
        match="unique rule_id",
    ):
        DetectionEngine(
            [
                RepeatedAuthenticationFailuresRule(),
                RepeatedAuthenticationFailuresRule(),
            ]
        )


def test_engine_runs_multiple_detection_rules() -> None:
    engine = DetectionEngine(
        [
            RepeatedAuthenticationFailuresRule(),
            SuccessfulLoginAfterFailureBurstRule(),
        ]
    )

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

    alerts = engine.evaluate(events)

    assert len(alerts) == 2
    assert [alert.rule_id for alert in alerts] == [
        "AUTH-001",
        "AUTH-002",
    ]


def test_engine_orders_alerts_deterministically() -> None:
    engine = DetectionEngine(
        [
            SuccessfulLoginAfterFailureBurstRule(),
            RepeatedAuthenticationFailuresRule(),
        ]
    )

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

    alerts = engine.evaluate(events)

    assert [alert.rule_id for alert in alerts] == [
        "AUTH-001",
        "AUTH-002",
    ]
    assert alerts[0].last_seen == BASE_TIME + timedelta(seconds=40)
    assert alerts[1].last_seen == BASE_TIME + timedelta(seconds=50)


def test_engine_does_not_swallow_rule_exceptions() -> None:
    engine = DetectionEngine([BrokenRule()])

    with pytest.raises(
        RuntimeError,
        match="synthetic rule failure",
    ):
        engine.evaluate([])
