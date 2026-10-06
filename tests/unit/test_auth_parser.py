from datetime import datetime, timezone

import pytest

from app.ingestion.auth_parser import (
    LinuxAuthLogParseError,
    parse_linux_auth_log,
)


def test_parse_failed_password() -> None:
    line = (
        "Oct  6 10:20:01 server-01 sshd[1234]: "
        "Failed password for admin from 203.0.113.20 port 54321 ssh2"
    )

    event = parse_linux_auth_log(line, year=2026)

    assert event.timestamp == datetime(
        2026, 10, 6, 10, 20, 1, tzinfo=timezone.utc
    )
    assert event.source_type == "linux_auth"
    assert event.event_type == "authentication_failure"
    assert event.source_ip == "203.0.113.20"
    assert event.source_port == 54321
    assert event.hostname == "server-01"
    assert event.user == "admin"
    assert event.action == "failure"
    assert event.metadata["auth_method"] == "password"
    assert event.metadata["invalid_user"] is False
    assert event.metadata["pid"] == 1234


def test_parse_failed_password_for_invalid_user() -> None:
    line = (
        "Oct  6 10:20:05 server-01 sshd[1235]: "
        "Failed password for invalid user guest "
        "from 198.51.100.9 port 40000 ssh2"
    )

    event = parse_linux_auth_log(line, year=2026)

    assert event.event_type == "authentication_failure"
    assert event.user == "guest"
    assert event.source_ip == "198.51.100.9"
    assert event.metadata["invalid_user"] is True


def test_parse_accepted_publickey() -> None:
    line = (
        "Oct  6 10:21:00 server-01 sshd[1240]: "
        "Accepted publickey for admin "
        "from 203.0.113.20 port 54325 ssh2"
    )

    event = parse_linux_auth_log(line, year=2026)

    assert event.event_type == "authentication_success"
    assert event.action == "success"
    assert event.user == "admin"
    assert event.source_ip == "203.0.113.20"
    assert event.metadata["auth_method"] == "publickey"


def test_parse_invalid_user() -> None:
    line = (
        "Oct  6 10:22:10 server-01 sshd[1250]: "
        "Invalid user oracle from 192.0.2.44 port 35555"
    )

    event = parse_linux_auth_log(line, year=2026)

    assert event.event_type == "invalid_user"
    assert event.user == "oracle"
    assert event.action == "failure"
    assert event.source_ip == "192.0.2.44"


def test_reject_unsupported_ssh_message() -> None:
    line = (
        "Oct  6 10:23:00 server-01 sshd[1260]: "
        "Connection closed by 203.0.113.50 port 50000"
    )

    with pytest.raises(LinuxAuthLogParseError):
        parse_linux_auth_log(line, year=2026)
