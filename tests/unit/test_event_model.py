from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.domain.events import Event


def test_create_http_event() -> None:
    event = Event(
        timestamp=datetime(2026, 10, 6, 10, 15, 21, tzinfo=timezone.utc),
        source_type="http_access",
        event_type="http_request",
        source_ip="203.0.113.15",
        method="GET",
        path="/admin",
        status_code=404,
        user_agent="example-agent",
        raw_event='203.0.113.15 - - "GET /admin HTTP/1.1" 404',
    )

    assert event.source_type == "http_access"
    assert event.event_type == "http_request"
    assert event.source_ip == "203.0.113.15"
    assert event.method == "GET"
    assert event.path == "/admin"
    assert event.status_code == 404
    assert event.event_id is not None


def test_create_linux_auth_event() -> None:
    event = Event(
        timestamp=datetime(2026, 10, 6, 10, 20, tzinfo=timezone.utc),
        source_type="linux_auth",
        event_type="authentication_failure",
        source_ip="203.0.113.20",
        hostname="server-01",
        user="admin",
        action="failure",
        message="Failed password for admin",
        raw_event="Failed password for admin from 203.0.113.20",
    )

    assert event.source_type == "linux_auth"
    assert event.user == "admin"
    assert event.action == "failure"
    assert event.method is None
    assert event.path is None


def test_reject_invalid_status_code() -> None:
    with pytest.raises(ValidationError):
        Event(
            timestamp=datetime.now(timezone.utc),
            source_type="http_access",
            event_type="http_request",
            status_code=999,
            raw_event="invalid",
        )


def test_reject_invalid_port() -> None:
    with pytest.raises(ValidationError):
        Event(
            timestamp=datetime.now(timezone.utc),
            source_type="http_access",
            event_type="http_request",
            source_port=70000,
            raw_event="invalid",
        )
