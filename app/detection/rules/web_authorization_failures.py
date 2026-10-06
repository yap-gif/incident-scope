from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta

from app.detection.base import DetectionRule
from app.domain.alerts import Alert
from app.domain.events import Event


_ACCESS_FAILURE_STATUS_CODES = {
    401,
    403,
}


class RepeatedAuthorizationFailuresRule(DetectionRule):
    """Detect repeated HTTP access-control failures from one source IP."""

    rule_id = "WEB-002"
    title = "Repeated Authorization Failures"
    severity = "medium"

    def __init__(
        self,
        *,
        threshold: int = 5,
        window_seconds: int = 60,
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold must be at least 2")

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than 0"
            )

        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(
        self,
        events: Sequence[Event],
    ) -> list[Alert]:
        grouped_events: dict[str, list[Event]] = defaultdict(list)

        for event in events:
            if event.source_type != "http_access":
                continue

            if event.event_type != "http_request":
                continue

            if event.source_ip is None:
                continue

            if event.status_code not in _ACCESS_FAILURE_STATUS_CODES:
                continue

            grouped_events[event.source_ip].append(event)

        alerts: list[Alert] = []

        for source_ip, source_events in grouped_events.items():
            ordered_events = sorted(
                source_events,
                key=lambda event: event.timestamp,
            )

            matched_events = self._find_densest_window(
                ordered_events
            )

            if len(matched_events) < self.threshold:
                continue

            paths = sorted(
                {
                    event.path
                    for event in matched_events
                    if event.path is not None
                }
            )

            status_codes = sorted(
                {
                    event.status_code
                    for event in matched_events
                    if event.status_code is not None
                }
            )

            alerts.append(
                Alert(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=(
                        f"{len(matched_events)} HTTP access-control "
                        f"failures were observed from {source_ip} "
                        f"within {self.window_seconds} seconds."
                    ),
                    first_seen=matched_events[0].timestamp,
                    last_seen=matched_events[-1].timestamp,
                    source_ip=source_ip,
                    event_ids=[
                        event.event_id
                        for event in matched_events
                    ],
                    evidence={
                        "failure_count": len(matched_events),
                        "threshold": self.threshold,
                        "window_seconds": self.window_seconds,
                        "paths": paths,
                        "status_codes": status_codes,
                    },
                    tags=[
                        "web",
                        "access-control",
                    ],
                )
            )

        return alerts

    def _find_densest_window(
        self,
        events: Sequence[Event],
    ) -> list[Event]:
        if not events:
            return []

        window = timedelta(seconds=self.window_seconds)

        left = 0
        best_left = 0
        best_right = -1
        best_count = 0

        for right, event in enumerate(events):
            while (
                event.timestamp - events[left].timestamp > window
            ):
                left += 1

            count = right - left + 1

            if count > best_count:
                best_left = left
                best_right = right
                best_count = count

        if best_right < best_left:
            return []

        return list(events[best_left : best_right + 1])
