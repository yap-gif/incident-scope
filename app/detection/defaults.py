from app.detection.engine import DetectionEngine
from app.detection.rules.auth_failures import (
    RepeatedAuthenticationFailuresRule,
)
from app.detection.rules.auth_success_after_failures import (
    SuccessfulLoginAfterFailureBurstRule,
)
from app.detection.rules.net_high_frequency import (
    HighFrequencySourceActivityRule,
)
from app.detection.rules.web_admin_probing import (
    SuspiciousAdministrativePathProbingRule,
)
from app.detection.rules.web_authorization_failures import (
    RepeatedAuthorizationFailuresRule,
)
from app.detection.rules.web_path_enumeration import (
    ScanningLikePathEnumerationRule,
)


def build_default_detection_engine() -> DetectionEngine:
    """Build IncidentScope's canonical MVP detection engine."""

    return DetectionEngine(
        [
            RepeatedAuthenticationFailuresRule(),
            SuccessfulLoginAfterFailureBurstRule(),
            SuspiciousAdministrativePathProbingRule(),
            RepeatedAuthorizationFailuresRule(),
            ScanningLikePathEnumerationRule(),
            HighFrequencySourceActivityRule(),
        ]
    )
