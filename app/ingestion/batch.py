from datetime import timezone, tzinfo
from pathlib import Path

from app.domain.events import Event, SourceType
from app.ingestion.auth_parser import (
    LinuxAuthLogParseError,
    parse_linux_auth_log,
)
from app.ingestion.http_parser import (
    HttpAccessLogParseError,
    parse_http_access_log,
)


class IngestionConfigurationError(ValueError):
    """Raised when batch-ingestion configuration is invalid."""


class IngestionLineError(ValueError):
    """Raised when a specific log line cannot be normalized."""

    def __init__(
        self,
        path: Path,
        line_number: int,
        reason: str,
    ) -> None:
        self.path = path
        self.line_number = line_number
        self.reason = reason

        super().__init__(
            f"{path}: line {line_number}: {reason}"
        )


def ingest_file(
    path: str | Path,
    *,
    source_type: SourceType,
    year: int | None = None,
    timezone_info: tzinfo = timezone.utc,
) -> list[Event]:
    """Read one log file and normalize supported lines into Events."""

    file_path = Path(path)

    if source_type == "linux_auth" and year is None:
        raise IngestionConfigurationError(
            "year is required for linux_auth logs"
        )

    if source_type not in ("http_access", "linux_auth"):
        raise IngestionConfigurationError(
            f"Unsupported source type: {source_type}"
        )

    events: list[Event] = []

    with file_path.open(
        "r",
        encoding="utf-8-sig",
    ) as log_file:
        for line_number, line in enumerate(log_file, start=1):
            raw_line = line.rstrip("\r\n")

            if not raw_line.strip():
                continue

            try:
                if source_type == "http_access":
                    event = parse_http_access_log(raw_line)
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
                raise IngestionLineError(
                    file_path,
                    line_number,
                    str(exc),
                ) from exc

            events.append(event)

    return events
