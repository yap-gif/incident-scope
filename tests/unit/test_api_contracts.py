import pytest
from pydantic import ValidationError

from app.api.contracts import AnalyzeRequest


def test_http_analysis_request_does_not_require_year() -> None:
    request = AnalyzeRequest(
        source_type="http_access",
        log_text=(
            '203.0.113.15 - - '
            '[06/Oct/2026:10:15:21 +0000] '
            '"GET / HTTP/1.1" '
            '200 512 "-" "Mozilla/5.0"'
        ),
    )

    assert request.source_type == (
        "http_access"
    )
    assert request.year is None
    assert request.timezone_offset_minutes == 0


def test_linux_auth_analysis_request_requires_year() -> None:
    with pytest.raises(
        ValidationError,
        match="year is required",
    ):
        AnalyzeRequest(
            source_type="linux_auth",
            log_text=(
                "Oct  7 23:30:00 server-01 "
                "sshd[100]: Failed password for admin "
                "from 203.0.113.20 port 50000 ssh2"
            ),
        )


def test_linux_auth_request_accepts_time_configuration() -> None:
    request = AnalyzeRequest(
        source_type="linux_auth",
        log_text=(
            "Oct  7 23:30:00 server-01 "
            "sshd[100]: Failed password for admin "
            "from 203.0.113.20 port 50000 ssh2"
        ),
        year=2026,
        timezone_offset_minutes=480,
    )

    assert request.year == 2026

    assert (
        request.timezone_offset_minutes
        == 480
    )
