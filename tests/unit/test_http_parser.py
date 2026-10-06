from datetime import datetime, timedelta, timezone

import pytest

from app.ingestion.http_parser import (
    HttpAccessLogParseError,
    parse_http_access_log,
)


def test_parse_valid_combined_log() -> None:
    line = (
        '203.0.113.15 - - [06/Oct/2026:10:15:21 +0000] '
        '"GET /admin HTTP/1.1" 404 153 "-" "example-agent"'
    )

    event = parse_http_access_log(line)

    assert event.timestamp == datetime(
        2026,
        10,
        6,
        10,
        15,
        21,
        tzinfo=timezone.utc,
    )
    assert event.source_type == "http_access"
    assert event.event_type == "http_request"
    assert event.source_ip == "203.0.113.15"
    assert event.method == "GET"
    assert event.path == "/admin"
    assert event.status_code == 404
    assert event.user_agent == "example-agent"
    assert event.metadata["protocol"] == "HTTP/1.1"
    assert event.metadata["response_size"] == 153
    assert event.metadata["referer"] == "-"


def test_parse_log_with_timezone_and_query_string() -> None:
    line = (
        '198.51.100.9 - - [06/Oct/2026:18:30:00 +0800] '
        '"POST /login?next=/dashboard HTTP/1.1" '
        '401 42 "https://example.test/" "Mozilla/5.0"'
    )

    event = parse_http_access_log(line)

    assert event.timestamp.utcoffset() == timedelta(hours=8)
    assert event.method == "POST"
    assert event.path == "/login?next=/dashboard"
    assert event.status_code == 401
    assert event.metadata["referer"] == "https://example.test/"


def test_parse_dash_response_size_as_none() -> None:
    line = (
        '192.0.2.40 - - [06/Oct/2026:10:20:00 +0000] '
        '"GET /.env HTTP/1.1" 403 - "-" "curl/8.0"'
    )

    event = parse_http_access_log(line)

    assert event.metadata["response_size"] is None


def test_reject_malformed_log() -> None:
    with pytest.raises(HttpAccessLogParseError):
        parse_http_access_log("this is not a valid access log")
