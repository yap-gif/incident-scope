from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_analyze_http_access_log() -> None:
    response = client.post(
        "/analyze",
        json={
            "source_type": "http_access",
            "log_text": (
                "203.0.113.40 - - "
                "[07/Oct/2026:23:30:00 +0000] "
                '"GET /admin HTTP/1.1" '
                '404 128 "-" "scanner"'
            ),
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert set(payload) == {
        "events",
        "alerts",
        "incidents",
        "timelines",
    }

    assert len(payload["events"]) == 1

    event = payload["events"][0]

    assert event["source_type"] == (
        "http_access"
    )
    assert event["event_type"] == (
        "http_request"
    )
    assert event["path"] == "/admin"

    assert [
        alert["rule_id"]
        for alert in payload["alerts"]
    ] == [
        "WEB-001",
    ]

    assert payload["incidents"] == []
    assert payload["timelines"] == []


def test_analyze_linux_auth_runs_complete_pipeline() -> None:
    log_text = "\n".join(
        [
            (
                "Oct  7 23:30:00 server-01 "
                "sshd[100]: Failed password for admin "
                "from 203.0.113.20 port 50000 ssh2"
            ),
            (
                "Oct  7 23:30:10 server-01 "
                "sshd[101]: Failed password for admin "
                "from 203.0.113.20 port 50001 ssh2"
            ),
            (
                "Oct  7 23:30:20 server-01 "
                "sshd[102]: Failed password for admin "
                "from 203.0.113.20 port 50002 ssh2"
            ),
            (
                "Oct  7 23:30:30 server-01 "
                "sshd[103]: Failed password for admin "
                "from 203.0.113.20 port 50003 ssh2"
            ),
            (
                "Oct  7 23:30:40 server-01 "
                "sshd[104]: Failed password for admin "
                "from 203.0.113.20 port 50004 ssh2"
            ),
            (
                "Oct  7 23:30:50 server-01 "
                "sshd[105]: Accepted password for admin "
                "from 203.0.113.20 port 50005 ssh2"
            ),
        ]
    )

    response = client.post(
        "/analyze",
        json={
            "source_type": "linux_auth",
            "log_text": log_text,
            "year": 2026,
            "timezone_offset_minutes": 0,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert len(payload["events"]) == 6

    assert [
        alert["rule_id"]
        for alert in payload["alerts"]
    ] == [
        "AUTH-001",
        "AUTH-002",
    ]

    assert len(payload["incidents"]) == 1
    assert len(payload["timelines"]) == 1

    incident = payload["incidents"][0]

    assert incident["incident_type"] == (
        "suspicious_authentication"
    )

    timeline = payload["timelines"][0]

    assert timeline["incident_id"] == (
        incident["incident_id"]
    )

    assert len(timeline["entries"]) == 8


def test_analyze_linux_auth_applies_timezone_offset() -> None:
    response = client.post(
        "/analyze",
        json={
            "source_type": "linux_auth",
            "log_text": (
                "Oct  7 23:30:00 server-01 "
                "sshd[100]: Failed password for admin "
                "from 203.0.113.20 port 50000 ssh2"
            ),
            "year": 2026,
            "timezone_offset_minutes": 480,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert len(payload["events"]) == 1

    timestamp = datetime.fromisoformat(
        payload["events"][0]["timestamp"].replace(
            "Z",
            "+00:00",
        )
    )

    assert timestamp.year == 2026

    assert timestamp.utcoffset() == timedelta(
        hours=8
    )

    assert payload["alerts"] == []
    assert payload["incidents"] == []
    assert payload["timelines"] == []


def test_analyze_rejects_missing_linux_auth_year() -> None:
    response = client.post(
        "/analyze",
        json={
            "source_type": "linux_auth",
            "log_text": (
                "Oct  7 23:30:00 server-01 "
                "sshd[100]: Failed password for admin "
                "from 203.0.113.20 port 50000 ssh2"
            ),
        },
    )

    assert response.status_code == 422

    payload = response.json()

    assert "detail" in payload

    assert any(
        "year is required for linux_auth logs"
        in str(item)
        for item in payload["detail"]
    )


def test_analyze_rejects_invalid_source_type() -> None:
    response = client.post(
        "/analyze",
        json={
            "source_type": "unknown_source",
            "log_text": "synthetic telemetry",
        },
    )

    assert response.status_code == 422


def test_analyze_rejects_empty_log_text() -> None:
    response = client.post(
        "/analyze",
        json={
            "source_type": "http_access",
            "log_text": "",
        },
    )

    assert response.status_code == 422


def test_analyze_reports_malformed_log_line() -> None:
    response = client.post(
        "/analyze",
        json={
            "source_type": "http_access",
            "log_text": (
                "203.0.113.15 - - "
                "[06/Oct/2026:10:15:21 +0000] "
                '"GET / HTTP/1.1" '
                '200 512 "-" "Mozilla/5.0"\n'
                "\n"
                "malformed log entry\n"
            ),
        },
    )

    assert response.status_code == 422

    assert response.json() == {
        "detail": {
            "code": "log_parse_error",
            "line_number": 3,
            "reason": (
                "Invalid HTTP combined "
                "access-log format"
            ),
        }
    }


def test_unexpected_analysis_failure_is_not_client_error(
    monkeypatch,
) -> None:
    def fail_ingestion(*args, **kwargs):
        raise RuntimeError(
            "synthetic internal failure"
        )

    monkeypatch.setattr(
        "app.api.routes.ingest_text",
        fail_ingestion,
    )

    non_raising_client = TestClient(
        app,
        raise_server_exceptions=False,
    )

    response = non_raising_client.post(
        "/analyze",
        json={
            "source_type": "http_access",
            "log_text": (
                "203.0.113.15 - - "
                "[06/Oct/2026:10:15:21 +0000] "
                '"GET / HTTP/1.1" '
                '200 512 "-" "Mozilla/5.0"'
            ),
        },
    )

    assert response.status_code == 500

    assert response.text == (
        "Internal Server Error"
    )

    assert response.headers[
        "content-type"
    ].startswith(
        "text/plain"
    )
