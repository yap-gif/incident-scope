from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import timedelta
from urllib.parse import urlsplit

from app.detection.base import DetectionRule
from app.domain.alerts import Alert
from app.domain.events import Event


_ENUMERATION_STATUS_CODES = {
    403,
    404,
}


class ScanningLikePathEnumerationRule(DetectionRule):
    """Detect scanning-like enumeration across many distinct web paths."""

    rule_id = "WEB-003"
    title = "Scanning-Like Path Enumeration"
    severity = "medium"

    def __init__(
        self,
        *,
        unique_path_threshold: int = 8,
        window_seconds: int = 60,
    ) -> None:
        if unique_path_threshold < 2:
            raise ValueError(
                "unique_path_threshold must be at least 2"
            )

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than 0"
            )

        self.unique_path_threshold = unique_path_threshold
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

            if event.path is None:
                continue

            if event.status_code not in _ENUMERATION_STATUS_CODES:
                continue

            grouped_events[event.source_ip].append(event)

        alerts: list[Alert] = []

        for source_ip, source_events in grouped_events.items():
            ordered_events = sorted(
                source_events,
                key=lambda event: event.timestamp,
            )

            matched_events = self._find_densest_unique_path_window(
                ordered_events
            )

            unique_paths = sorted(
                {
                    self._normalize_path(event.path)
                    for event in matched_events
                    if event.path is not None
                }
            )

            if len(unique_paths) < self.unique_path_threshold:
                continue

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
                        f"{source_ip} requested "
                        f"{len(unique_paths)} distinct denied or "
                        f"missing paths within "
                        f"{self.window_seconds} seconds."
                    ),
                    first_seen=matched_events[0].timestamp,
                    last_seen=matched_events[-1].timestamp,
                    source_ip=source_ip,
                    event_ids=[
                        event.event_id
                        for event in matched_events
                    ],
                    evidence={
                        "unique_path_count": len(unique_paths),
                        "unique_path_threshold": (
                            self.unique_path_threshold
                        ),
                        "window_seconds": self.window_seconds,
                        "paths": unique_paths,
                        "status_codes": status_codes,
                    },
                    tags=[
                        "web",
                        "enumeration",
                        "scanning",
                    ],
                )
            )

        return alerts

    def _find_densest_unique_path_window(
        self,
        events: Sequence[Event],
    ) -> list[Event]:
        if not events:
            return []

        window = timedelta(seconds=self.window_seconds)

        path_counts: Counter[str] = Counter()

        left = 0
        best_left = 0
        best_right = -1
        best_unique_count = 0

        for right, event in enumerate(events):
            assert event.path is not None

            normalized_path = self._normalize_path(event.path)
            path_counts[normalized_path] += 1

            while (
                event.timestamp - events[left].timestamp > window
            ):
                left_event = events[left]
                assert left_event.path is not None

                left_path = self._normalize_path(
                    left_event.path
                )

                path_counts[left_path] -= 1

                if path_counts[left_path] == 0:
                    del path_counts[left_path]

                left += 1

            unique_count = len(path_counts)

            if unique_count > best_unique_count:
                best_left = left
                best_right = right
                best_unique_count = unique_count

        if best_right < best_left:
            return []

        return list(
            events[best_left : best_right + 1]
        )

    @staticmethod
    def _normalize_path(path: str) -> str:
        parsed_path = urlsplit(path).path or "/"
        normalized_path = parsed_path.lower()

        if normalized_path != "/":
            normalized_path = normalized_path.rstrip("/")

        return normalized_path
