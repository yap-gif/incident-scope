from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.domain.alerts import Alert


def test_create_valid_alert() -> None:
    event_id = uuid4()

    alert = Alert(
        rule_id="AUTH-001",
        title="Repeated Authentication Failures",
        severity="medium",
        description=(
            "Multiple authentication failures were observed "
            "from the same source."
        ),
        first_seen=datetime(
            2026, 10, 6, 10, 20, 1, tzinfo=timezone.utc
        ),
        last_seen=datetime(
            2026, 10, 6, 10, 20, 30, tzinfo=timezone.utc
        ),
        source_ip="203.0.113.20",
        user="admin",
        event_ids=[event_id],
        evidence={
            "failure_count": 5,
            "window_seconds": 60,
        },
        tags=["authentication", "ssh"],
    )

    assert alert.rule_id == "AUTH-001"
    assert alert.severity == "medium"
    assert alert.source_ip == "203.0.113.20"
    assert alert.event_ids == [event_id]
    assert alert.evidence["failure_count"] == 5
    assert alert.alert_id is not None


def test_reject_alert_without_supporting_events() -> None:
    with pytest.raises(ValidationError):
        Alert(
            rule_id="AUTH-001",
            title="Repeated Authentication Failures",
            severity="medium",
            description="Test alert",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            event_ids=[],
        )


def test_reject_reversed_alert_time_range() -> None:
    with pytest.raises(
        ValidationError,
        match="last_seen must be greater than or equal to first_seen",
    ):
        Alert(
            rule_id="AUTH-001",
            title="Repeated Authentication Failures",
            severity="medium",
            description="Test alert",
            first_seen=datetime(
                2026, 10, 6, 10, 30, tzinfo=timezone.utc
            ),
            last_seen=datetime(
                2026, 10, 6, 10, 20, tzinfo=timezone.utc
            ),
            event_ids=[uuid4()],
        )


def test_reject_unknown_severity() -> None:
    with pytest.raises(ValidationError):
        Alert(
            rule_id="TEST-001",
            title="Invalid Severity",
            severity="urgent",
            description="Test alert",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            event_ids=[uuid4()],
        )
