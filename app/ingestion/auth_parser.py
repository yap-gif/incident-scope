import re
from datetime import datetime, timezone, tzinfo
from typing import Final

from app.domain.events import Event


class LinuxAuthLogParseError(ValueError):
    """Raised when a Linux SSH authentication log line cannot be parsed."""


_SYSLOG_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<hostname>\S+) "
    r"sshd\[(?P<pid>\d+)\]: "
    r"(?P<message>.+)$"
)

_FAILED_PASSWORD_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^Failed password for "
    r"(?:(?P<invalid_user>invalid user) )?"
    r"(?P<user>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+) "
    r"(?P<protocol>\S+)$"
)

_ACCEPTED_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^Accepted (?P<auth_method>password|publickey) "
    r"for (?P<user>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+) "
    r"(?P<protocol>\S+)$"
)

_INVALID_USER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^Invalid user (?P<user>\S+) "
    r"from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+)$"
)


def parse_linux_auth_log(
    line: str,
    *,
    year: int,
    timezone_info: tzinfo = timezone.utc,
) -> Event:
    """Parse one supported OpenSSH auth.log line into a normalized Event."""

    raw_line = line.rstrip("\r\n")

    syslog_match = _SYSLOG_PATTERN.fullmatch(raw_line)
    if syslog_match is None:
        raise LinuxAuthLogParseError("Invalid Linux auth.log format")

    try:
        timestamp = datetime.strptime(
            (
                f"{year} "
                f"{syslog_match.group('month')} "
                f"{syslog_match.group('day')} "
                f"{syslog_match.group('time')}"
            ),
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone_info)
    except ValueError as exc:
        raise LinuxAuthLogParseError(
            "Linux auth.log line contains an invalid timestamp"
        ) from exc

    hostname = syslog_match.group("hostname")
    pid = int(syslog_match.group("pid"))
    message = syslog_match.group("message")

    failed_match = _FAILED_PASSWORD_PATTERN.fullmatch(message)
    if failed_match is not None:
        is_invalid_user = failed_match.group("invalid_user") is not None

        return Event(
            timestamp=timestamp,
            source_type="linux_auth",
            event_type="authentication_failure",
            source_ip=failed_match.group("source_ip"),
            source_port=int(failed_match.group("source_port")),
            hostname=hostname,
            user=failed_match.group("user"),
            action="failure",
            message=message,
            raw_event=raw_line,
            metadata={
                "process": "sshd",
                "pid": pid,
                "auth_method": "password",
                "protocol": failed_match.group("protocol"),
                "invalid_user": is_invalid_user,
            },
        )

    accepted_match = _ACCEPTED_PATTERN.fullmatch(message)
    if accepted_match is not None:
        return Event(
            timestamp=timestamp,
            source_type="linux_auth",
            event_type="authentication_success",
            source_ip=accepted_match.group("source_ip"),
            source_port=int(accepted_match.group("source_port")),
            hostname=hostname,
            user=accepted_match.group("user"),
            action="success",
            message=message,
            raw_event=raw_line,
            metadata={
                "process": "sshd",
                "pid": pid,
                "auth_method": accepted_match.group("auth_method"),
                "protocol": accepted_match.group("protocol"),
            },
        )

    invalid_user_match = _INVALID_USER_PATTERN.fullmatch(message)
    if invalid_user_match is not None:
        return Event(
            timestamp=timestamp,
            source_type="linux_auth",
            event_type="invalid_user",
            source_ip=invalid_user_match.group("source_ip"),
            source_port=int(invalid_user_match.group("source_port")),
            hostname=hostname,
            user=invalid_user_match.group("user"),
            action="failure",
            message=message,
            raw_event=raw_line,
            metadata={
                "process": "sshd",
                "pid": pid,
            },
        )

    raise LinuxAuthLogParseError(
        "Unsupported SSH authentication message"
    )
