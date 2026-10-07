import pytest

from app.ingestion.batch import (
    IngestionConfigurationError,
)
from app.ingestion.text import (
    TextIngestionLineError,
    ingest_text,
)


def test_ingest_http_log_text() -> None:
    text = (
        "\ufeff"
        '203.0.113.15 - - '
        '[06/Oct/2026:10:15:21 +0000] '
        '"GET / HTTP/1.1" '
        '200 512 "-" "Mozilla/5.0"\n'
        "\n"
        '203.0.113.15 - - '
        '[06/Oct/2026:10:15:22 +0000] '
        '"GET /.env HTTP/1.1" '
        '403 128 "-" "scanner"\n'
    )

    events = ingest_text(
        text,
        source_type="http_access",
    )

    assert len(events) == 2

    assert events[0].source_type == (
        "http_access"
    )
    assert events[0].path == "/"
    assert events[0].status_code == 200

    assert events[1].path == "/.env"
    assert events[1].status_code == 403


def test_ingest_linux_auth_log_text() -> None:
    text = (
        "Oct  7 23:30:00 server-01 "
        "sshd[100]: Failed password for admin "
        "from 203.0.113.20 port 50000 ssh2\n"
        "Oct  7 23:30:10 server-01 "
        "sshd[101]: Accepted password for admin "
        "from 203.0.113.20 port 50001 ssh2\n"
    )

    events = ingest_text(
        text,
        source_type="linux_auth",
        year=2026,
    )

    assert len(events) == 2

    assert events[0].event_type == (
        "authentication_failure"
    )
    assert events[0].user == "admin"

    assert events[1].event_type == (
        "authentication_success"
    )
    assert events[1].user == "admin"


def test_linux_auth_text_requires_year() -> None:
    with pytest.raises(
        IngestionConfigurationError,
        match="year is required",
    ):
        ingest_text(
            (
                "Oct  7 23:30:00 server-01 "
                "sshd[100]: Failed password for admin "
                "from 203.0.113.20 port 50000 ssh2"
            ),
            source_type="linux_auth",
        )


def test_text_parse_failure_reports_line_number() -> None:
    text = (
        '203.0.113.15 - - '
        '[06/Oct/2026:10:15:21 +0000] '
        '"GET / HTTP/1.1" '
        '200 512 "-" "Mozilla/5.0"\n'
        "\n"
        "malformed log entry\n"
    )

    with pytest.raises(
        TextIngestionLineError
    ) as exc_info:
        ingest_text(
            text,
            source_type="http_access",
        )

    assert exc_info.value.line_number == 3

    assert "line 3" in str(
        exc_info.value
    )
