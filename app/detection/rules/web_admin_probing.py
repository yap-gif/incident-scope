from collections.abc import Sequence
from urllib.parse import urlsplit

from app.detection.base import DetectionRule
from app.domain.alerts import Alert
from app.domain.events import Event


_ADMIN_PATH_PREFIXES = (
    "/admin",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
)

_SENSITIVE_EXACT_PATHS = (
    "/.env",
    "/server-status",
)


class SuspiciousAdministrativePathProbingRule(DetectionRule):
    """Detect requests targeting known administrative or sensitive paths."""

    rule_id = "WEB-001"
    title = "Suspicious Administrative Path Probing"
    severity = "medium"

    def evaluate(
        self,
        events: Sequence[Event],
    ) -> list[Alert]:
        alerts: list[Alert] = []

        ordered_events = sorted(
            events,
            key=lambda event: event.timestamp,
        )

        for event in ordered_events:
            if event.source_type != "http_access":
                continue

            if event.event_type != "http_request":
                continue

            if event.path is None:
                continue

            normalized_path = self._normalize_path(event.path)
            matched_pattern = self._match_path(normalized_path)

            if matched_pattern is None:
                continue

            alerts.append(
                Alert(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=(
                        "An HTTP request targeted a known "
                        f"administrative or sensitive path: "
                        f"{normalized_path}."
                    ),
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    source_ip=event.source_ip,
                    event_ids=[event.event_id],
                    evidence={
                        "path": event.path,
                        "normalized_path": normalized_path,
                        "matched_pattern": matched_pattern,
                        "method": event.method,
                        "status_code": event.status_code,
                    },
                    tags=[
                        "web",
                        "path-probing",
                    ],
                )
            )

        return alerts

    @staticmethod
    def _normalize_path(path: str) -> str:
        parsed_path = urlsplit(path).path or "/"
        normalized_path = parsed_path.lower()

        if normalized_path != "/":
            normalized_path = normalized_path.rstrip("/")

        return normalized_path

    @staticmethod
    def _match_path(
        normalized_path: str,
    ) -> str | None:
        if normalized_path in _SENSITIVE_EXACT_PATHS:
            return normalized_path

        for prefix in _ADMIN_PATH_PREFIXES:
            if (
                normalized_path == prefix
                or normalized_path.startswith(f"{prefix}/")
            ):
                return prefix

        return None
