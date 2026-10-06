from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta

from app.detection.base import DetectionRule
from app.domain.alerts import Alert
from app.domain.events import Event


class SuccessfulLoginAfterFailureBurstRule(DetectionRule):
    """Detect a successful SSH login following a burst of failures."""

    rule_id = "AUTH-002"
    title = "Successful Login After Failure Burst"
    severity = "high"

    def __init__(
        self,
        *,
        failure_threshold: int = 3,
        lookback_seconds: int = 120,
    ) -> None:
        if failure_threshold < 2:
            raise ValueError(
                "failure_threshold must be at least 2"
            )

        if lookback_seconds <= 0:
            raise ValueError(
                "lookback_seconds must be greater than 0"
            )

        self.failure_threshold = failure_threshold
        self.lookback_seconds = lookback_seconds

    def evaluate(
        self,
        events: Sequence[Event],
    ) -> list[Alert]:
        grouped_events: dict[str, list[Event]] = defaultdict(list)

        for event in events:
            if event.source_type != "linux_auth":
                continue

            if event.event_type not in (
                "authentication_failure",
                "authentication_success",
            ):
                continue

            if event.source_ip is None:
                continue

            grouped_events[event.source_ip].append(event)

        alerts: list[Alert] = []
        lookback = timedelta(seconds=self.lookback_seconds)

        for source_ip, source_events in grouped_events.items():
            ordered_events = sorted(
                source_events,
                key=lambda event: event.timestamp,
            )

            failures: list[Event] = []

            for event in ordered_events:
                if event.event_type == "authentication_failure":
                    failures.append(event)
                    continue

                cutoff = event.timestamp - lookback

                recent_failures = [
                    failure
                    for failure in failures
                    if cutoff <= failure.timestamp <= event.timestamp
                ]

                if len(recent_failures) >= self.failure_threshold:
                    failure_users = sorted(
                        {
                            failure.user
                            for failure in recent_failures
                            if failure.user is not None
                        }
                    )

                    matched_events = recent_failures + [event]

                    alerts.append(
                        Alert(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            description=(
                                f"A successful authentication from "
                                f"{source_ip} followed "
                                f"{len(recent_failures)} failures "
                                f"within {self.lookback_seconds} seconds."
                            ),
                            first_seen=recent_failures[0].timestamp,
                            last_seen=event.timestamp,
                            source_ip=source_ip,
                            user=event.user,
                            event_ids=[
                                matched_event.event_id
                                for matched_event in matched_events
                            ],
                            evidence={
                                "failure_count": len(recent_failures),
                                "failure_threshold": (
                                    self.failure_threshold
                                ),
                                "lookback_seconds": (
                                    self.lookback_seconds
                                ),
                                "failure_users": failure_users,
                                "successful_user": event.user,
                                "success_event_id": str(
                                    event.event_id
                                ),
                            },
                            tags=[
                                "authentication",
                                "ssh",
                            ],
                        )
                    )

                # A success closes the current authentication sequence.
                # Earlier failures must not trigger another later success.
                failures = []

        return alerts
