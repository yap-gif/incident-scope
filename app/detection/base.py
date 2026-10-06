from abc import ABC, abstractmethod
from collections.abc import Sequence

from app.domain.alerts import Alert, Severity
from app.domain.events import Event


class DetectionRule(ABC):
    """Base contract implemented by all IncidentScope detection rules."""

    rule_id: str
    title: str
    severity: Severity

    @abstractmethod
    def evaluate(
        self,
        events: Sequence[Event],
    ) -> list[Alert]:
        """Evaluate normalized events and return generated alerts."""
        raise NotImplementedError
