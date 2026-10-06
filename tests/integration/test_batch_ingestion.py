from pathlib import Path

import pytest

from app.ingestion.batch import (
    IngestionConfigurationError,
    IngestionLineError,
    ingest_file,
)


def test_ingest_http_sample_file() -> None:
    events = ingest_file(
        Path("samples/http/access.log"),
        source_type="http_access",
    )

    assert len(events) == 4

    assert events[0].source_type == "http_access"
    assert events[0].source_ip == "203.0.113.15"
    assert events[0].path == "/"
    assert events[0].status_code == 200

    assert events[3].path == "/.env"
    assert events[3].status_code == 403


def test_ingest_linux_auth_sample_file() -> None:
    events = ingest_file(
        Path("samples/auth/auth.log"),
        source_type="linux_auth",
        year=2026,
    )

    assert len(events) == 4

    assert events[0].event_type == "authentication_failure"
    assert events[0].user == "admin"

    assert events[2].event_type == "authentication_success"
    assert events[2].user == "admin"

    assert events[3].event_type == "invalid_user"
    assert events[3].user == "oracle"


def test_linux_auth_requires_year() -> None:
    with pytest.raises(
        IngestionConfigurationError,
        match="year is required",
    ):
        ingest_file(
            Path("samples/auth/auth.log"),
            source_type="linux_auth",
        )


def test_blank_lines_are_ignored(tmp_path: Path) -> None:
    log_file = tmp_path / "access.log"

    log_file.write_text(
        "\n"
        '203.0.113.15 - - [06/Oct/2026:10:15:21 +0000] '
        '"GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
        "\n",
        encoding="utf-8",
    )

    events = ingest_file(
        log_file,
        source_type="http_access",
    )

    assert len(events) == 1


def test_parse_failure_reports_line_number(tmp_path: Path) -> None:
    log_file = tmp_path / "access.log"

    log_file.write_text(
        '203.0.113.15 - - [06/Oct/2026:10:15:21 +0000] '
        '"GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
        "malformed log entry\n",
        encoding="utf-8",
    )

    with pytest.raises(IngestionLineError) as exc_info:
        ingest_file(
            log_file,
            source_type="http_access",
        )

    assert exc_info.value.line_number == 2
    assert exc_info.value.path == log_file
    assert "line 2" in str(exc_info.value)
