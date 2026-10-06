from collections.abc import Sequence

import pytest

from app.detection.base import DetectionRule
from app.domain.alerts import Alert
from app.domain.events import Event


class IncompleteRule(DetectionRule):
    rule_id = "TEST-001"
    title = "Incomplete Rule"
    severity = "low"


class EmptyRule(DetectionRule):
    rule_id = "TEST-002"
    title = "Empty Rule"
    severity = "low"

    def evaluate(
        self,
        events: Sequence[Event],
    ) -> list[Alert]:
        return []


def test_detection_rule_requires_evaluate_implementation() -> None:
    with pytest.raises(TypeError):
        IncompleteRule()


def test_concrete_detection_rule_follows_contract() -> None:
    rule = EmptyRule()

    alerts = rule.evaluate([])

    assert rule.rule_id == "TEST-002"
    assert rule.title == "Empty Rule"
    assert rule.severity == "low"
    assert alerts == []
