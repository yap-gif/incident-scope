from app.correlation.engine import CorrelationEngine
from app.correlation.rules.authentication import (
    SuspiciousAuthenticationCorrelationRule,
)


def build_default_correlation_engine() -> CorrelationEngine:
    """Build IncidentScope's canonical MVP correlation engine."""

    return CorrelationEngine(
        [
            SuspiciousAuthenticationCorrelationRule(),
        ]
    )
