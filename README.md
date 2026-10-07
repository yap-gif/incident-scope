# IncidentScope

IncidentScope is a defensive security event analysis and incident investigation platform built to turn raw security telemetry into explainable, evidence-linked findings.

It normalizes HTTP access logs and Linux SSH authentication logs, applies deterministic detection rules, correlates related alerts into incidents, builds investigation timelines, and exposes the complete machine-analysis workflow through FastAPI.

## Project Status

**Working MVP with a verified public analysis pipeline.**

- 161 automated tests passing
- reproducible Python 3.13 installation
- real Uvicorn startup verified
- public `POST /analyze` API verified
- canonical suspicious-authentication demo verified end-to-end
- detailed engineering history preserved in `docs/ENGINEERING-NOTES.md`

## Highlights

- Normalizes multiple telemetry sources into a shared `Event` model.
- Uses explicit, explainable detection rules rather than opaque scoring.
- Correlates alert evidence into higher-level security incidents.
- Preserves event and alert identifiers across the investigation chain.
- Builds deterministic investigation timelines from correlated evidence.
- Separates machine analysis from analyst-authored conclusions.
- Returns structured client errors for malformed telemetry.
- Provides a real HTTP API, OpenAPI schema, Swagger UI, and demo client.

## Canonical Security Demo

The bundled flagship scenario models repeated SSH authentication failures followed by a successful login from the same source.

Input behavior:

- five failed SSH authentication attempts
- one subsequent successful SSH authentication
- one source IP
- one targeted user account

With the API running:

```powershell
python scripts\demo.py
```

Expected result:

```text
IncidentScope Canonical Demo
==============================
Events: 6
Alerts: AUTH-001, AUTH-002
Incidents: 1
Incident type: suspicious_authentication
Severity: high
Source IPs: 203.0.113.20
Users: admin
Timeline entries: 8
```

The canonical sample is stored at:

```text
samples/auth/suspicious-authentication.log
```

The demo client sends the sample through the public `POST /analyze` endpoint instead of calling internal analysis functions directly.

## Architecture

Public machine-analysis path:

```text
HTTP JSON Request
    -> AnalyzeRequest
    -> In-Memory Log Ingestion
    -> Normalized Event[]
    -> DetectionEngine
    -> Alert[]
    -> CorrelationEngine
    -> Incident[]
    -> Timeline Builder
    -> InvestigationTimeline[]
    -> AnalysisResult
    -> HTTP JSON Response
```

Uploaded telemetry is analyzed in memory. The public analysis path does not require temporary log files or a persistence layer.

Analyst-enriched reporting is deliberately separate:

```text
Incident
    + InvestigationTimeline
    + Explicit Analyst Conclusion
    + Optional Limitations
    -> Report Builder
    -> IncidentReport
    -> JSON
```

This boundary prevents the machine-analysis API from inventing compromise claims, attribution, remediation, or analyst conclusions.

## Quick Start

IncidentScope requires Python 3.13 or newer.

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install runtime and development dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Verify the environment:

```powershell
python -m pip check
pytest -q
```

Current verified baseline:

```text
161 passed
No broken requirements found.
```

Start the API:

```powershell
python -m uvicorn app.main:app --reload
```

Useful local endpoints:

```text
GET  http://127.0.0.1:8000/health
POST http://127.0.0.1:8000/analyze
GET  http://127.0.0.1:8000/openapi.json
GET  http://127.0.0.1:8000/docs
```

Run the canonical demo in another PowerShell session:

```powershell
python scripts\demo.py
```

## Detection Coverage

| Rule | Purpose | Severity |
| --- | --- | --- |
| `AUTH-001` | Repeated authentication failures from the same source | Medium |
| `AUTH-002` | Successful login after a recent failure burst | High |
| `WEB-001` | Suspicious administrative-path probing | Medium |
| `WEB-002` | Repeated HTTP authorization failures | Medium |
| `WEB-003` | Scanning-like path enumeration | Medium |
| `NET-001` | High-frequency source activity | Low |

Current correlation coverage:

| Rule | Purpose |
| --- | --- |
| `CORR-AUTH-001` | Correlates repeated authentication failures with a subsequent successful login into a `suspicious_authentication` incident |

Detailed thresholds, evidence requirements, and implementation history are documented in `docs/ENGINEERING-NOTES.md`.

## Public API

Primary analysis endpoint:

```text
POST /analyze
```

The request contract accepts:

- `source_type`: `http_access` or `linux_auth`
- raw telemetry through `log_text`
- an explicit `year` for Linux syslog timestamps
- an optional timezone offset in minutes

The response contains:

- normalized events
- generated alerts
- correlated incidents
- investigation timelines

Malformed log lines fail fast with HTTP 422 and preserve the physical source line number and parser reason. Unexpected server errors are not disguised as client input errors.

## Engineering Quality

- 161 automated unit and integration tests
- deterministic detection and correlation ordering
- explicit domain validation with Pydantic
- evidence continuity across events, alerts, incidents, and timelines
- fail-fast malformed-input handling
- physical source-line preservation in ingestion errors
- deterministic timeline tie-breaking
- JSON-safe nested timeline details
- exact report JSON serialization round-trips
- clean-environment installation verification
- real HTTP server and canonical API demo verification

A known Starlette TestClient deprecation warning remains a dependency-maintenance item and does not currently affect runtime API behavior or the passing test suite.

## Technology

- Python 3.13
- FastAPI
- Pydantic
- pytest
- standard-library HTTP client for the demo script

## Project Structure

```text
app/
  api/             HTTP contracts and routes
  application/     analysis orchestration
  correlation/     correlation engine and rules
  detection/       detection engine and rules
  domain/          events, alerts, incidents, timelines, reports
  ingestion/       HTTP and Linux authentication parsing
  investigation/   timeline and report builders
  main.py          FastAPI application

docs/
  ENGINEERING-NOTES.md

samples/
  auth/
  http/

scripts/
  demo.py

tests/
  integration/
  unit/
```

## Scope and Limitations

The current MVP intentionally does not implement:

- persistent storage
- authentication or user accounts
- a frontend interface
- distributed processing
- automatic analyst conclusions
- automatic attribution or compromise claims
- AI-generated security judgments

Current telemetry coverage is limited to:

- Apache/Nginx-style HTTP access logs
- Linux/OpenSSH authentication logs

These boundaries are deliberate. Additional infrastructure should be added only when a demonstrated requirement justifies it.

## Design Principles

IncidentScope is intended to remain:

- defensive
- evidence-based
- explainable
- deterministic where practical
- testable
- reproducible
- small enough to understand end-to-end

The MVP deliberately avoids Redis, Kafka, Elasticsearch, microservices, and unnecessary distributed-system complexity.

## Documentation

For detailed domain behavior, detection semantics, correlation rules, milestone history, and implementation notes, see [Engineering Notes](docs/ENGINEERING-NOTES.md).
