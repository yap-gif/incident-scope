import argparse
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_SAMPLE = Path(
    "samples/auth/suspicious-authentication.log"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the canonical IncidentScope "
            "suspicious-authentication demo."
        ),
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=(
            "IncidentScope API base URL "
            f"(default: {DEFAULT_BASE_URL})"
        ),
    )

    parser.add_argument(
        "--sample",
        type=Path,
        default=DEFAULT_SAMPLE,
        help=(
            "Linux auth log sample to analyze "
            f"(default: {DEFAULT_SAMPLE})"
        ),
    )

    parser.add_argument(
        "--year",
        type=int,
        default=2026,
        help="Year for Linux syslog timestamps.",
    )

    parser.add_argument(
        "--timezone-offset-minutes",
        type=int,
        default=0,
        help=(
            "Timezone offset for Linux syslog "
            "timestamps in minutes."
        ),
    )

    return parser.parse_args()


def load_sample(path: Path) -> str:
    try:
        return path.read_text(
            encoding="utf-8-sig"
        )
    except OSError as exc:
        raise RuntimeError(
            f"Could not read sample: {path}"
        ) from exc


def analyze(
    *,
    base_url: str,
    log_text: str,
    year: int,
    timezone_offset_minutes: int,
) -> dict:
    payload = {
        "source_type": "linux_auth",
        "log_text": log_text,
        "year": year,
        "timezone_offset_minutes": (
            timezone_offset_minutes
        ),
    }

    body = json.dumps(
        payload
    ).encode("utf-8")

    request = Request(
        (
            base_url.rstrip("/")
            + "/analyze"
        ),
        data=body,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urlopen(
            request,
            timeout=10,
        ) as response:
            return json.load(response)

    except HTTPError as exc:
        response_body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        raise RuntimeError(
            (
                "IncidentScope API returned "
                f"HTTP {exc.code}: "
                f"{response_body}"
            )
        ) from exc

    except URLError as exc:
        raise RuntimeError(
            (
                "Could not connect to IncidentScope "
                f"at {base_url}. "
                "Start the API with: "
                "python -m uvicorn "
                "app.main:app --reload"
            )
        ) from exc


def print_summary(result: dict) -> None:
    events = result["events"]
    alerts = result["alerts"]
    incidents = result["incidents"]
    timelines = result["timelines"]

    print("IncidentScope Canonical Demo")
    print("=" * 30)
    print(f"Events: {len(events)}")

    rule_ids = [
        alert["rule_id"]
        for alert in alerts
    ]

    print(
        "Alerts:",
        (
            ", ".join(rule_ids)
            if rule_ids
            else "none"
        ),
    )

    print(
        f"Incidents: {len(incidents)}"
    )

    if incidents:
        incident = incidents[0]

        print(
            "Incident type:",
            incident["incident_type"],
        )

        print(
            "Severity:",
            incident["severity"],
        )

        print(
            "Source IPs:",
            ", ".join(
                incident["source_ips"]
            ),
        )

        print(
            "Users:",
            ", ".join(
                incident["users"]
            ),
        )

    if timelines:
        print(
            "Timeline entries:",
            len(
                timelines[0]["entries"]
            ),
        )


def main() -> int:
    args = parse_args()

    try:
        log_text = load_sample(
            args.sample
        )

        result = analyze(
            base_url=args.base_url,
            log_text=log_text,
            year=args.year,
            timezone_offset_minutes=(
                args.timezone_offset_minutes
            ),
        )

        print_summary(result)

    except RuntimeError as exc:
        print(
            f"Demo failed: {exc}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
