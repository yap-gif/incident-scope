from collections.abc import Sequence

from app.correlation.base import CorrelationRule
from app.domain.alerts import Alert
from app.domain.incidents import Incident


class SuspiciousAuthenticationCorrelationRule(CorrelationRule):
    """Correlate authentication failures with a subsequent success."""

    correlation_id = "CORR-AUTH-001"
    incident_type = "suspicious_authentication"
    title = "Suspicious Authentication Activity"

    def correlate(
        self,
        alerts: Sequence[Alert],
    ) -> list[Incident]:
        failure_alerts = [
            alert
            for alert in alerts
            if alert.rule_id == "AUTH-001"
            and alert.source_ip is not None
        ]

        success_alerts = sorted(
            (
                alert
                for alert in alerts
                if alert.rule_id == "AUTH-002"
                and alert.source_ip is not None
            ),
            key=lambda alert: (
                alert.last_seen,
                str(alert.alert_id),
            ),
        )

        incidents: list[Incident] = []
        used_failure_alert_ids = set()

        for success_alert in success_alerts:
            candidates = [
                failure_alert
                for failure_alert in failure_alerts
                if (
                    failure_alert.alert_id
                    not in used_failure_alert_ids
                    and self._is_match(
                        failure_alert,
                        success_alert,
                    )
                )
            ]

            if not candidates:
                continue

            failure_alert = max(
                candidates,
                key=lambda alert: (
                    self._shared_event_count(
                        alert,
                        success_alert,
                    ),
                    alert.last_seen,
                    str(alert.alert_id),
                ),
            )

            used_failure_alert_ids.add(
                failure_alert.alert_id
            )

            incidents.append(
                self._build_incident(
                    failure_alert,
                    success_alert,
                )
            )

        return incidents

    @staticmethod
    def _is_match(
        failure_alert: Alert,
        success_alert: Alert,
    ) -> bool:
        if failure_alert.source_ip != success_alert.source_ip:
            return False

        if failure_alert.last_seen > success_alert.last_seen:
            return False

        return bool(
            set(failure_alert.event_ids)
            & set(success_alert.event_ids)
        )

    @staticmethod
    def _shared_event_count(
        failure_alert: Alert,
        success_alert: Alert,
    ) -> int:
        return len(
            set(failure_alert.event_ids)
            & set(success_alert.event_ids)
        )

    def _build_incident(
        self,
        failure_alert: Alert,
        success_alert: Alert,
    ) -> Incident:
        event_ids = list(
            dict.fromkeys(
                [
                    *failure_alert.event_ids,
                    *success_alert.event_ids,
                ]
            )
        )

        users = sorted(
            {
                user
                for user in (
                    failure_alert.user,
                    success_alert.user,
                )
                if user is not None
            }
        )

        source_ip = success_alert.source_ip

        assert source_ip is not None

        first_seen = min(
            failure_alert.first_seen,
            success_alert.first_seen,
        )

        last_seen = max(
            failure_alert.last_seen,
            success_alert.last_seen,
        )

        return Incident(
            incident_type=self.incident_type,
            title=self.title,
            severity="high",
            summary=(
                "Repeated authentication failures were "
                "followed by a successful login from the "
                f"same source IP: {source_ip}."
            ),
            first_seen=first_seen,
            last_seen=last_seen,
            alert_ids=[
                failure_alert.alert_id,
                success_alert.alert_id,
            ],
            event_ids=event_ids,
            source_ips=[source_ip],
            users=users,
            tags=[
                "authentication",
                "correlated",
                "successful-login-after-failures",
            ],
        )
