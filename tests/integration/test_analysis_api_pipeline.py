from datetime import datetime

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(
        value.replace(
            "Z",
            "+00:00",
        )
    )


def build_auth_log_text() -> str:
    return "\n".join(
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


def test_public_api_preserves_complete_evidence_chain() -> None:
    response = client.post(
        "/analyze",
        json={
            "source_type": "linux_auth",
            "log_text": build_auth_log_text(),
            "year": 2026,
            "timezone_offset_minutes": 0,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    events = payload["events"]
    alerts = payload["alerts"]
    incidents = payload["incidents"]
    timelines = payload["timelines"]

    assert len(events) == 6

    assert [
        alert["rule_id"]
        for alert in alerts
    ] == [
        "AUTH-001",
        "AUTH-002",
    ]

    assert len(incidents) == 1
    assert len(timelines) == 1

    incident = incidents[0]
    timeline = timelines[0]

    assert incident["incident_type"] == (
        "suspicious_authentication"
    )

    assert incident["severity"] == "high"

    assert timeline["incident_id"] == (
        incident["incident_id"]
    )

    event_ids = {
        event["event_id"]
        for event in events
    }

    alert_ids = {
        alert["alert_id"]
        for alert in alerts
    }

    assert set(
        incident["event_ids"]
    ) == event_ids

    assert set(
        incident["alert_ids"]
    ) == alert_ids

    timeline_event_ids = {
        entry["evidence_id"]
        for entry in timeline["entries"]
        if entry["entry_type"] == "event"
    }

    timeline_alert_ids = {
        entry["evidence_id"]
        for entry in timeline["entries"]
        if entry["entry_type"] == "alert"
    }

    assert timeline_event_ids == event_ids
    assert timeline_alert_ids == alert_ids

    assert len(timeline["entries"]) == 8


def test_public_api_timeline_order_is_deterministic() -> None:
    response = client.post(
        "/analyze",
        json={
            "source_type": "linux_auth",
            "log_text": build_auth_log_text(),
            "year": 2026,
            "timezone_offset_minutes": 0,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    timeline = payload["timelines"][0]

    entries = timeline["entries"]

    timestamps = [
        parse_timestamp(
            entry["timestamp"]
        )
        for entry in entries
    ]

    assert timestamps == sorted(
        timestamps
    )

    event_times = {
        event["action"]: parse_timestamp(
            event["timestamp"]
        )
        for event in payload["events"]
        if event["action"] == "success"
    }

    success_time = event_times["success"]

    entries_at_success = [
        entry
        for entry in entries
        if parse_timestamp(
            entry["timestamp"]
        ) == success_time
    ]

    assert [
        entry["entry_type"]
        for entry in entries_at_success
    ] == [
        "event",
        "alert",
    ]

    auth_001 = next(
        alert
        for alert in payload["alerts"]
        if alert["rule_id"] == "AUTH-001"
    )

    auth_001_time = parse_timestamp(
        auth_001["last_seen"]
    )

    entries_at_auth_001 = [
        entry
        for entry in entries
        if parse_timestamp(
            entry["timestamp"]
        ) == auth_001_time
    ]

    assert [
        entry["entry_type"]
        for entry in entries_at_auth_001
    ] == [
        "event",
        "alert",
    ]
