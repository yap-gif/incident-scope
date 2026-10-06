from collections.abc import Sequence

from app.detection.base import DetectionRule
from app.domain.alerts import Alert
from app.domain.events import Event


class DetectionEngine:
    """Run registered detection rules against normalized events."""

    def __init__(
        self,
        rules: Sequence[DetectionRule],
    ) -> None:
        rule_ids = [rule.rule_id for rule in rules]

        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError(
                "Detection rules must have unique rule_id values"
            )

        self._rules = tuple(rules)

    @property
    def rules(self) -> tuple[DetectionRule, ...]:
        return self._rules

    def evaluate(
        self,
        events: Sequence[Event],
    ) -> list[Alert]:
        """Evaluate all registered rules and return ordered alerts."""

        alerts: list[Alert] = []

        for rule in self._rules:
            alerts.extend(rule.evaluate(events))

        return sorted(
            alerts,
            key=lambda alert: (
                alert.first_seen,
                alert.last_seen,
                alert.rule_id,
                alert.source_ip or "",
                alert.user or "",
            ),
        )
