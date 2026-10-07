from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.correlation.base import CorrelationRule
from app.correlation.engine import CorrelationEngine
from app.domain.alerts import Alert
from app.domain.incidents import Incident


BASE_TIME = datetime(
    2026,
    10,
    7,
    12,
    0,
    tzinfo=timezone.utc,
)


def make_incident(
    *,
    first_seconds: int,
    last_seconds: int,
    incident_type: str = "test_incident",
    title: str = "Test Incident",
    source_ip: str = "203.0.113.20",
    user: str = "admin",
) -> Incident:
    return Incident(
        incident_type=incident_type,
        title=title,
        severity="medium",
        summary="Synthetic correlation engine incident.",
        first_seen=BASE_TIME + timedelta(
            seconds=first_seconds
        ),
        last_seen=BASE_TIME + timedelta(
            seconds=last_seconds
        ),
        alert_ids=[uuid4()],
        event_ids=[uuid4()],
        source_ips=[source_ip],
        users=[user],
        tags=["synthetic"],
    )


class FirstCorrelationRule(CorrelationRule):
    correlation_id = "TEST-001"
    incident_type = "first_test"
    title = "First Test Correlation"

    def __init__(
        self,
        incidents: Sequence[Incident] = (),
    ) -> None:
        self._incidents = list(incidents)

    def correlate(
        self,
        alerts: Sequence[Alert],
    ) -> list[Incident]:
        return list(self._incidents)


class SecondCorrelationRule(CorrelationRule):
    correlation_id = "TEST-002"
    incident_type = "second_test"
    title = "Second Test Correlation"

    def __init__(
        self,
        incidents: Sequence[Incident] = (),
    ) -> None:
        self._incidents = list(incidents)

    def correlate(
        self,
        alerts: Sequence[Alert],
    ) -> list[Incident]:
        return list(self._incidents)


class DuplicateCorrelationRule(CorrelationRule):
    correlation_id = "TEST-001"
    incident_type = "duplicate_test"
    title = "Duplicate Test Correlation"

    def correlate(
        self,
        alerts: Sequence[Alert],
    ) -> list[Incident]:
        return []


class FailingCorrelationRule(CorrelationRule):
    correlation_id = "FAIL-001"
    incident_type = "failure_test"
    title = "Failure Test Correlation"

    def correlate(
        self,
        alerts: Sequence[Alert],
    ) -> list[Incident]:
        raise RuntimeError("correlation failed")


def test_engine_allows_no_rules() -> None:
    engine = CorrelationEngine([])

    assert engine.rules == ()
    assert engine.correlate([]) == []


def test_engine_preserves_rule_registration_order() -> None:
    first_rule = FirstCorrelationRule()
    second_rule = SecondCorrelationRule()

    engine = CorrelationEngine(
        [
            first_rule,
            second_rule,
        ]
    )

    assert engine.rules == (
        first_rule,
        second_rule,
    )


def test_engine_rejects_duplicate_correlation_ids() -> None:
    with pytest.raises(
        ValueError,
        match="duplicate correlation_id",
    ):
        CorrelationEngine(
            [
                FirstCorrelationRule(),
                DuplicateCorrelationRule(),
            ]
        )


def test_engine_collects_incidents_from_all_rules() -> None:
    first_incident = make_incident(
        first_seconds=0,
        last_seconds=10,
        incident_type="first_test",
    )

    second_incident = make_incident(
        first_seconds=20,
        last_seconds=30,
        incident_type="second_test",
    )

    engine = CorrelationEngine(
        [
            FirstCorrelationRule(
                [first_incident]
            ),
            SecondCorrelationRule(
                [second_incident]
            ),
        ]
    )

    incidents = engine.correlate([])

    assert len(incidents) == 2
    assert incidents == [
        first_incident,
        second_incident,
    ]


def test_engine_sorts_incidents_deterministically() -> None:
    later_incident = make_incident(
        first_seconds=30,
        last_seconds=40,
        incident_type="later",
    )

    earlier_incident = make_incident(
        first_seconds=0,
        last_seconds=10,
        incident_type="earlier",
    )

    middle_incident = make_incident(
        first_seconds=20,
        last_seconds=25,
        incident_type="middle",
    )

    engine = CorrelationEngine(
        [
            FirstCorrelationRule(
                [
                    later_incident,
                    earlier_incident,
                ]
            ),
            SecondCorrelationRule(
                [middle_incident]
            ),
        ]
    )

    incidents = engine.correlate([])

    assert incidents == [
        earlier_incident,
        middle_incident,
        later_incident,
    ]


def test_engine_surfaces_rule_exceptions() -> None:
    engine = CorrelationEngine(
        [
            FailingCorrelationRule(),
        ]
    )

    with pytest.raises(
        RuntimeError,
        match="correlation failed",
    ):
        engine.correlate([])
