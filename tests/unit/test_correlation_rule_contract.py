from collections.abc import Sequence

import pytest

from app.correlation.base import CorrelationRule
from app.domain.alerts import Alert
from app.domain.incidents import Incident


class ConcreteCorrelationRule(CorrelationRule):
    correlation_id = "TEST-001"
    incident_type = "test_incident"
    title = "Test Incident Correlation"

    def correlate(
        self,
        alerts: Sequence[Alert],
    ) -> list[Incident]:
        return []


def test_correlation_rule_is_abstract() -> None:
    with pytest.raises(TypeError):
        CorrelationRule()


def test_concrete_correlation_rule_can_be_instantiated() -> None:
    rule = ConcreteCorrelationRule()

    assert rule.correlation_id == "TEST-001"
    assert rule.incident_type == "test_incident"
    assert rule.title == "Test Incident Correlation"


def test_concrete_correlation_rule_returns_incident_list() -> None:
    rule = ConcreteCorrelationRule()

    incidents = rule.correlate([])

    assert incidents == []
