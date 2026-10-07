from collections.abc import Sequence

from app.correlation.base import CorrelationRule
from app.domain.alerts import Alert
from app.domain.incidents import Incident


class CorrelationEngine:
    """Run registered correlation rules against security alerts."""

    def __init__(
        self,
        rules: Sequence[CorrelationRule],
    ) -> None:
        seen_ids: set[str] = set()
        duplicate_ids: set[str] = set()

        for rule in rules:
            if rule.correlation_id in seen_ids:
                duplicate_ids.add(rule.correlation_id)

            seen_ids.add(rule.correlation_id)

        if duplicate_ids:
            duplicate_text = ", ".join(
                sorted(duplicate_ids)
            )

            raise ValueError(
                "duplicate correlation_id(s): "
                f"{duplicate_text}"
            )

        self._rules = tuple(rules)

    @property
    def rules(
        self,
    ) -> tuple[CorrelationRule, ...]:
        return self._rules

    def correlate(
        self,
        alerts: Sequence[Alert],
    ) -> list[Incident]:
        incidents: list[Incident] = []

        for rule in self._rules:
            incidents.extend(
                rule.correlate(alerts)
            )

        incidents.sort(
            key=lambda incident: (
                incident.first_seen,
                incident.last_seen,
                incident.incident_type,
                incident.title,
                tuple(sorted(incident.source_ips)),
                tuple(sorted(incident.users)),
            )
        )

        return incidents
