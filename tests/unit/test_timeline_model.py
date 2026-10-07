from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.domain.timelines import (
    InvestigationTimeline,
    TimelineEntry,
)


BASE_TIME = datetime(
    2026,
    10,
    7,
    18,
    0,
    tzinfo=timezone.utc,
)


def make_entry(
    *,
    seconds: int,
    entry_type: str = "event",
    evidence_id=None,
    title: str = "Synthetic Evidence",
) -> TimelineEntry:
    return TimelineEntry(
        timestamp=BASE_TIME + timedelta(
            seconds=seconds
        ),
        entry_type=entry_type,
        evidence_id=evidence_id or uuid4(),
        title=title,
        description="Synthetic timeline evidence.",
        source_ip="203.0.113.20",
        user="admin",
        details={},
        tags=["synthetic"],
    )


def test_create_event_timeline_entry() -> None:
    evidence_id = uuid4()

    entry = make_entry(
        seconds=0,
        entry_type="event",
        evidence_id=evidence_id,
    )

    assert entry.entry_type == "event"
    assert entry.evidence_id == evidence_id
    assert entry.source_ip == "203.0.113.20"


def test_create_alert_timeline_entry() -> None:
    evidence_id = uuid4()

    entry = make_entry(
        seconds=10,
        entry_type="alert",
        evidence_id=evidence_id,
        title="AUTH-001 Alert",
    )

    assert entry.entry_type == "alert"
    assert entry.evidence_id == evidence_id


def test_create_valid_chronological_timeline() -> None:
    entries = [
        make_entry(seconds=0),
        make_entry(
            seconds=10,
            entry_type="alert",
        ),
        make_entry(seconds=20),
    ]

    timeline = InvestigationTimeline(
        incident_id=uuid4(),
        title="Suspicious Authentication Investigation",
        entries=entries,
    )

    assert timeline.entries == entries
    assert len(timeline.entries) == 3


def test_equal_timestamps_are_allowed() -> None:
    entries = [
        make_entry(seconds=0),
        make_entry(
            seconds=0,
            entry_type="alert",
        ),
    ]

    timeline = InvestigationTimeline(
        incident_id=uuid4(),
        title="Equal Timestamp Investigation",
        entries=entries,
    )

    assert len(timeline.entries) == 2


def test_reject_empty_timeline() -> None:
    with pytest.raises(ValidationError):
        InvestigationTimeline(
            incident_id=uuid4(),
            title="Empty Investigation",
            entries=[],
        )


def test_reject_non_chronological_entries() -> None:
    entries = [
        make_entry(seconds=20),
        make_entry(seconds=10),
    ]

    with pytest.raises(
        ValidationError,
        match="timeline entries must be chronological",
    ):
        InvestigationTimeline(
            incident_id=uuid4(),
            title="Invalid Investigation",
            entries=entries,
        )


def test_reject_duplicate_evidence_reference() -> None:
    evidence_id = uuid4()

    entries = [
        make_entry(
            seconds=0,
            entry_type="event",
            evidence_id=evidence_id,
        ),
        make_entry(
            seconds=10,
            entry_type="event",
            evidence_id=evidence_id,
        ),
    ]

    with pytest.raises(
        ValidationError,
        match="timeline evidence must not be duplicated",
    ):
        InvestigationTimeline(
            incident_id=uuid4(),
            title="Duplicate Evidence Investigation",
            entries=entries,
        )
