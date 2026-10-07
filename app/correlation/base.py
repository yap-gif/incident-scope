from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import ClassVar

from app.domain.alerts import Alert
from app.domain.incidents import Incident


class CorrelationRule(ABC):
    """Contract for transforming related alerts into incidents."""

    correlation_id: ClassVar[str]
    incident_type: ClassVar[str]
    title: ClassVar[str]

    @abstractmethod
    def correlate(
        self,
        alerts: Sequence[Alert],
    ) -> list[Incident]:
        """Correlate alerts into zero or more incidents."""
        raise NotImplementedError
