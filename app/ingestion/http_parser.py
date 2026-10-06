import re
from datetime import datetime
from typing import Final

from app.domain.events import Event


class HttpAccessLogParseError(ValueError):
    """Raised when an HTTP access-log line cannot be parsed."""


_COMBINED_LOG_PATTERN: Final[re.Pattern[str]] = re.compile(
    r'^(?P<source_ip>\S+) '
    r'\S+ '
    r'\S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>HTTP/\d(?:\.\d)?)" '
    r'(?P<status_code>\d{3}) '
    r'(?P<response_size>\d+|-) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"$'
)


def parse_http_access_log(line: str) -> Event:
    """Parse one Combined Log Format line into a normalized Event."""

    raw_line = line.rstrip("\r\n")

    match = _COMBINED_LOG_PATTERN.fullmatch(raw_line)
    if match is None:
        raise HttpAccessLogParseError("Invalid HTTP combined access-log format")

    try:
        timestamp = datetime.strptime(
            match.group("timestamp"),
            "%d/%b/%Y:%H:%M:%S %z",
        )
        status_code = int(match.group("status_code"))

        response_size_raw = match.group("response_size")
        response_size = (
            None if response_size_raw == "-" else int(response_size_raw)
        )
    except (TypeError, ValueError) as exc:
        raise HttpAccessLogParseError(
            "HTTP access-log line contains invalid field values"
        ) from exc

    return Event(
        timestamp=timestamp,
        source_type="http_access",
        event_type="http_request",
        source_ip=match.group("source_ip"),
        method=match.group("method"),
        path=match.group("path"),
        status_code=status_code,
        user_agent=match.group("user_agent"),
        raw_event=raw_line,
        metadata={
            "protocol": match.group("protocol"),
            "response_size": response_size,
            "referer": match.group("referer"),
        },
    )
