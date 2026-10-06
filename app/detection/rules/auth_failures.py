from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta

from app.detection.base import DetectionRule
from app.domain.alerts import Alert
from app.domain.events import Event


class RepeatedAuthenticationFailuresRule(DetectionRule):
    """Detect repeated SSH authentication failures from one source IP."""

    rule_id = "AUTH-001"
    title = "Repeated Authentication Failures"
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
            raise ValueError("window_seconds must be greater than 0")

        self.threshold = threshold
        self.window_seconds = window_seconds

    def evaluate(
        self,
        events: Sequence[Event],
    ) -> list[Alert]:
        grouped_events: dict[str, list[Event]] = defaultdict(list)

        for event in events:
            if event.source_type != "linux_auth":
                continue

            if event.event_type != "authentication_failure":
                continue

            if event.source_ip is None:
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

            users = sorted(
                {
                    event.user
                    for event in matched_events
                    if event.user is not None
                }
            )

            alert_user = users[0] if len(users) == 1 else None

            alerts.append(
                Alert(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=(
                        f"{len(matched_events)} authentication failures "
                        f"were observed from {source_ip} within "
                        f"{self.window_seconds} seconds."
                    ),
                    first_seen=matched_events[0].timestamp,
                    last_seen=matched_events[-1].timestamp,
                    source_ip=source_ip,
                    user=alert_user,
                    event_ids=[
                        event.event_id
                        for event in matched_events
                    ],
                    evidence={
                        "failure_count": len(matched_events),
                        "threshold": self.threshold,
                        "window_seconds": self.window_seconds,
                        "users": users,
                    },
                    tags=[
                        "authentication",
                        "ssh",
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
