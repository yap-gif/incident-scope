from datetime import timezone, tzinfo

from app.domain.events import Event, SourceType
from app.ingestion.auth_parser import (
    LinuxAuthLogParseError,
    parse_linux_auth_log,
)
from app.ingestion.batch import (
    IngestionConfigurationError,
)
from app.ingestion.http_parser import (
    HttpAccessLogParseError,
    parse_http_access_log,
)


class TextIngestionLineError(ValueError):
    """Raised when an in-memory log line cannot be normalized."""

    def __init__(
        self,
        line_number: int,
        reason: str,
    ) -> None:
        self.line_number = line_number
        self.reason = reason

        super().__init__(
            f"line {line_number}: {reason}"
        )


def ingest_text(
    text: str,
    *,
    source_type: SourceType,
    year: int | None = None,
    timezone_info: tzinfo = timezone.utc,
) -> list[Event]:
    """Normalize supported in-memory log text into Events."""

    if source_type == "linux_auth" and year is None:
        raise IngestionConfigurationError(
            "year is required for linux_auth logs"
        )

    if source_type not in (
        "http_access",
        "linux_auth",
    ):
        raise IngestionConfigurationError(
            f"Unsupported source type: {source_type}"
        )

    normalized_text = text.removeprefix("\ufeff")

    events: list[Event] = []

    for line_number, raw_line in enumerate(
        normalized_text.splitlines(),
        start=1,
    ):
        if not raw_line.strip():
            continue

        try:
            if source_type == "http_access":
                event = parse_http_access_log(
                    raw_line
                )
            else:
                event = parse_linux_auth_log(
                    raw_line,
                    year=year,
                    timezone_info=timezone_info,
                )
        except (
            HttpAccessLogParseError,
            LinuxAuthLogParseError,
            ValueError,
        ) as exc:
            raise TextIngestionLineError(
                line_number,
                str(exc),
            ) from exc

        events.append(event)

    return events
