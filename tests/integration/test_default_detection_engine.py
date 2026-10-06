from datetime import datetime, timedelta, timezone

from app.detection.defaults import (
    build_default_detection_engine,
)
from app.domain.events import Event


BASE_TIME = datetime(
    2026,
    10,
    6,
    10,
    0,
    tzinfo=timezone.utc,
)


EXPECTED_RULE_IDS = {
    "AUTH-001",
    "AUTH-002",
    "WEB-001",
    "WEB-002",
    "WEB-003",
    "NET-001",
}


def make_auth_event(
    *,
    seconds: int,
    event_type: str,
    source_ip: str = "203.0.113.20",
) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source_type="linux_auth",
        event_type=event_type,
        source_ip=source_ip,
        hostname="server-01",
        user="admin",
        action=(
            "failure"
            if event_type == "authentication_failure"
            else "success"
        ),
        raw_event=f"synthetic auth event at {seconds}",
    )


def make_http_event(
    *,
    seconds: int,
    path: str,
    status_code: int,
    source_ip: str,
) -> Event:
    return Event(
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source_type="http_access",
        event_type="http_request",
        source_ip=source_ip,
        method="GET",
        path=path,
        status_code=status_code,
        raw_event=f"synthetic HTTP event for {path}",
    )


def test_default_engine_registers_all_mvp_rules() -> None:
    engine = build_default_detection_engine()

    assert len(engine.rules) == 6

    assert {
        rule.rule_id
        for rule in engine.rules
    } == EXPECTED_RULE_IDS


def test_default_engine_runs_all_six_rules_together() -> None:
    engine = build_default_detection_engine()

    events: list[Event] = []

    # AUTH-001 + AUTH-002
    for seconds in (0, 10, 20, 30, 40):
        events.append(
            make_auth_event(
                seconds=seconds,
                event_type="authentication_failure",
            )
        )

    events.append(
        make_auth_event(
            seconds=50,
            event_type="authentication_success",
        )
    )

    # WEB-001 + WEB-002 + WEB-003
    web_paths = [
        "/admin",
        "/login",
        "/backup",
        "/config",
        "/old",
        "/test",
        "/private",
        "/staging",
    ]

    for index, path in enumerate(web_paths):
        events.append(
            make_http_event(
                seconds=index * 5,
                path=path,
                status_code=403 if index < 5 else 404,
                source_ip="198.51.100.9",
            )
        )

    # NET-001 only
    for index in range(20):
        events.append(
            make_http_event(
                seconds=index * 3,
                path=f"/normal-{index}",
                status_code=200,
                source_ip="192.0.2.50",
            )
        )

    alerts = engine.evaluate(events)

    assert len(alerts) == 6

    assert {
        alert.rule_id
        for alert in alerts
    } == EXPECTED_RULE_IDS
