# IncidentScope

IncidentScope is a defensive security event analysis and incident investigation platform.

It transforms raw security telemetry into normalized events, evaluates those events with explainable detection rules, correlates related alerts into incidents, builds investigation timelines, and exposes the analysis pipeline through a FastAPI HTTP interface.

## Status

Milestone 5 — Analysis API: **Complete**

Current test suite:

- 160 automated tests passing
- unit tests for domain models, ingestion, API contracts, detection, correlation, timelines, and reports
- integration tests for ingestion, analysis services, API endpoints, failure semantics, correlation, reporting, and the complete public analysis pipeline

## Quick Start

IncidentScope requires Python 3.13 or newer.

From the repository root, create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install IncidentScope together with its development dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Verify the environment and run the complete automated test suite:

```powershell
python -m pip check
pytest -q
```

The current verified baseline is:

```text
160 passed
No broken requirements found.
```

Start the FastAPI application:

```powershell
python -m uvicorn app.main:app --reload
```

By default, the local service is available at:

```text
http://127.0.0.1:8000
```

Useful endpoints:

```text
GET  /health
POST /analyze
GET  /openapi.json
GET  /docs
```

Verify the running service from another PowerShell session:

```powershell
Invoke-RestMethod `
    -Uri "http://127.0.0.1:8000/health" `
    -Method Get
```

Expected response:

```json
{
  "status": "ok",
  "service": "incident-scope"
}
```

The installation flow, package import, complete test suite, Uvicorn startup, health endpoint, OpenAPI document, Swagger UI, and real HTTP analysis request have all been verified from a clean Python 3.13 virtual environment.

## Current Capabilities

### Normalized Event Model

IncidentScope uses a shared `Event` domain model for different telemetry sources.

Supported source types:

- `http_access`
- `linux_auth`

Normalized fields include:

- event ID
- timestamp
- source type
- event type
- source and destination network fields
- hostname and user
- HTTP request fields
- authentication action
- original raw event
- source-specific metadata

### HTTP Access Log Ingestion

Supported format:

- Apache/Nginx-style Combined Log Format

Extracted data includes:

- source IP
- timestamp
- HTTP method
- request path
- status code
- user agent
- protocol
- response size
- referer

### Linux SSH Authentication Ingestion

Supported OpenSSH authentication events include:

- failed password
- failed password for invalid user
- accepted password
- accepted public key
- invalid user

Traditional syslog timestamps do not contain a year, so the ingestion caller must provide the year explicitly rather than IncidentScope guessing it.

### Batch File Ingestion

IncidentScope can ingest complete HTTP or Linux authentication log files and produce normalized `Event` objects.

Current ingestion behavior:

- blank lines are ignored
- malformed supported-source lines fail explicitly
- parse failures include the file and line number
- Linux authentication logs require an explicit year
- files are read using UTF-8 with optional BOM support

### Detection Engine

IncidentScope evaluates normalized events through a common `DetectionRule` contract.

The `DetectionEngine`:

- runs multiple registered rules against the same event collection
- rejects duplicate rule IDs
- collects generated alerts
- returns alerts in deterministic chronological order
- surfaces rule failures instead of silently suppressing them

A canonical default ruleset provides the complete MVP rule configuration from one entry point.

### Alert Model

Detection rules produce structured `Alert` objects containing:

- alert ID
- rule ID
- title
- severity
- description
- first-seen and last-seen timestamps
- source IP
- affected user when applicable
- supporting event IDs
- explainable evidence
- tags

Alerts must contain at least one supporting event and cannot have a reversed time range.

### Incident Model

Correlated security activity is represented by a structured `Incident` domain model.

An incident contains:

- incident ID
- incident type
- title
- severity
- summary
- first-seen and last-seen timestamps
- supporting alert IDs
- supporting event IDs
- source IPs
- affected users
- tags

Incident validation requires supporting alert and event evidence, rejects duplicate evidence IDs, and prevents reversed time ranges.

### Correlation Engine

IncidentScope correlates structured alerts through a common `CorrelationRule` contract.

The `CorrelationEngine`:

- runs registered correlation rules against the same alert collection
- rejects duplicate correlation IDs
- collects generated incidents
- returns incidents in deterministic chronological order
- surfaces correlation failures instead of silently suppressing them

A canonical default correlation engine provides the complete MVP correlation configuration from one entry point.

### Analysis API

IncidentScope exposes its analysis engine through FastAPI.

The public analysis endpoint is:

    POST /analyze

The request contract supports:

- `http_access` telemetry
- `linux_auth` telemetry
- raw in-memory log text
- an explicit year for Linux authentication logs
- configurable timezone offsets for Linux authentication timestamps

The response is a structured `AnalysisResult` containing:

- normalized events
- detection alerts
- correlated incidents
- investigation timelines

Request-schema validation failures return HTTP 422.

Malformed log telemetry returns a structured HTTP 422 response containing:

- `code`
- `line_number`
- parser `reason`

Unexpected internal failures are not converted into client errors and remain server failures.

FastAPI also exposes:

- `/openapi.json`
- `/docs`
- `/health`

The analysis endpoint intentionally does not generate analyst conclusions or `IncidentReport` objects automatically. Report generation remains a separate analyst-enriched workflow requiring an explicit conclusion and optional limitations.

### Investigation Timeline

IncidentScope can transform incident evidence into a deterministic investigation timeline.

The timeline builder:

- uses only alerts and events explicitly referenced by the incident
- fails fast when required supporting evidence is missing
- orders entries chronologically
- places event evidence before alert evidence at equal timestamps
- preserves direct references to event and alert evidence
- normalizes open-ended detail fields into JSON-safe values

Top-level timeline timestamps and evidence IDs remain strongly typed, while nested detail values use stable JSON-native representations.

### Incident Report

IncidentScope produces a versioned machine-readable `IncidentReport`.

A report contains:

- incident identity and type
- severity and summary
- first-seen and last-seen timestamps
- source IPs and affected users
- supporting alert IDs
- supporting event IDs
- the complete investigation timeline
- an explicit analyst conclusion
- explicit limitations

The report validates that its timeline references the same incident and contains exactly the alert and event evidence declared by the report.

Report generation does not automatically invent conclusions, attribution, compromise claims, or remediation. Analyst conclusions and limitations must be supplied explicitly.

Report JSON output is deterministic for the same report object and supports exact JSON serialization and validation round-trips.

## Detection Rules

### AUTH-001 — Repeated Authentication Failures

Severity: `medium`

Detects at least 5 Linux authentication failures from the same source IP within 60 seconds.

### AUTH-002 — Successful Login After Failure Burst

Severity: `high`

Detects a successful Linux authentication after at least 3 failures from the same source IP within the preceding 120 seconds.

### WEB-001 — Suspicious Administrative Path Probing

Severity: `medium`

Detects HTTP requests targeting known administrative or sensitive paths such as:

- `/admin`
- `/administrator`
- `/wp-admin`
- `/phpmyadmin`
- `/.env`
- `/server-status`

Path matching is case-insensitive, ignores query strings and trailing slashes, and supports nested administrative paths.

### WEB-002 — Repeated Authorization Failures

Severity: `medium`

Detects at least 5 HTTP access-control failures using status codes 401 or 403 from the same source IP within 60 seconds.

### WEB-003 — Scanning-Like Path Enumeration

Severity: `medium`

Detects requests to at least 8 distinct denied or missing paths from the same source IP within 60 seconds.

Relevant HTTP status codes:

- 403
- 404

Path normalization prevents case changes, trailing slashes, or query strings from artificially increasing the unique-path count.

### NET-001 — High-Frequency Source Activity

Severity: `low`

Detects at least 20 normalized events from the same source IP within 60 seconds.

This rule can aggregate activity across both supported telemetry sources:

- HTTP access events
- Linux authentication events

High-frequency activity is intentionally treated as a low-severity signal because high volume alone does not prove malicious behavior.

## Correlation Rules

### CORR-AUTH-001 — Suspicious Authentication Activity

Severity: `high`

Correlates:

- `AUTH-001` — Repeated Authentication Failures
- `AUTH-002` — Successful Login After Failure Burst

The alerts must:

- originate from the same non-null source IP
- share supporting event evidence
- preserve valid temporal ordering

When multiple failure alerts could support the same successful-login alert, the rule selects the strongest match using shared event evidence.

A single `AUTH-001` alert can support at most one incident. Once its failure-burst evidence is consumed, it cannot be reused to create another independent suspicious-authentication incident.

The resulting incident preserves supporting alert IDs and deduplicated event IDs so the incident can be traced back to its original evidence.

## Current Pipeline

Public analysis API:

    HTTP JSON Request
        ↓
    AnalyzeRequest
        ↓
    In-Memory Log Ingestion
        ↓
    Normalized Event[]
        ↓
    DetectionEngine
        ↓
    Alert[]
        ↓
    CorrelationEngine
        ↓
    Incident[]
        ↓
    Timeline Builder
        ↓
    InvestigationTimeline[]
        ↓
    AnalysisResult
        ↓
    HTTP JSON Response

The public `/analyze` endpoint executes this complete pipeline without writing uploaded telemetry to temporary files.

For Linux authentication telemetry, the request supplies the missing syslog year and an optional timezone offset. HTTP access logs retain the timezone information already present in the log line.

Malformed telemetry fails fast and preserves the physical source line number in a structured client-error response.

Analyst-enriched reporting remains a separate workflow:

    Incident
        +
    InvestigationTimeline
        +
    Explicit Analyst Conclusion
        +
    Optional Limitations
        ↓
    Report Builder
        ↓
    IncidentReport
        ↓
    JSON

This separation prevents the machine-analysis API from inventing compromise claims, attribution, analyst conclusions, or remediation.

Persistence, authentication, user accounts, and a frontend user interface are not implemented yet.

## Synthetic Sample Data

The repository includes synthetic telemetry for development and testing:

    samples/http/access.log
    samples/auth/auth.log

The sample IP addresses use documentation/example address ranges rather than production telemetry.

## Technology

- Python 3.13
- FastAPI
- Pydantic
- pytest
- SQLite planned for a later milestone

## Project Structure

    app/
    |-- api/
    |   |-- __init__.py
    |   |-- contracts.py
    |   `-- routes.py
    |-- application/
    |   |-- __init__.py
    |   `-- analysis.py
    |-- correlation/
    |   |-- rules/
    |   |   `-- authentication.py
    |   |-- base.py
    |   |-- defaults.py
    |   `-- engine.py
    |-- detection/
    |   |-- rules/
    |   |   |-- auth_failures.py
    |   |   |-- auth_success_after_failures.py
    |   |   |-- net_high_frequency.py
    |   |   |-- web_admin_probing.py
    |   |   |-- web_authorization_failures.py
    |   |   `-- web_path_enumeration.py
    |   |-- base.py
    |   |-- defaults.py
    |   `-- engine.py
    |-- domain/
    |   |-- alerts.py
    |   |-- events.py
    |   |-- incidents.py
    |   |-- reports.py
    |   `-- timelines.py
    |-- ingestion/
    |   |-- auth_parser.py
    |   |-- batch.py
    |   |-- http_parser.py
    |   `-- text.py
    |-- investigation/
    |   |-- report_builder.py
    |   `-- timeline_builder.py
    `-- main.py

    samples/
    |-- auth/
    |   `-- auth.log
    `-- http/
        `-- access.log

    tests/
    |-- integration/
    |   |-- test_analysis_api_pipeline.py
    |   |-- test_analysis_service.py
    |   |-- test_analyze_endpoint.py
    |   |-- test_batch_ingestion.py
    |   |-- test_default_correlation_engine.py
    |   |-- test_default_detection_engine.py
    |   |-- test_detection_correlation_pipeline.py
    |   `-- test_reporting_pipeline.py
    |-- unit/
    |   |-- test_alert_model.py
    |   |-- test_api_contracts.py
    |   |-- test_auth_failures_rule.py
    |   |-- test_auth_parser.py
    |   |-- test_auth_success_after_failures_rule.py
    |   |-- test_authentication_correlation_rule.py
    |   |-- test_correlation_engine.py
    |   |-- test_correlation_rule_contract.py
    |   |-- test_detection_engine.py
    |   |-- test_detection_rule_contract.py
    |   |-- test_event_model.py
    |   |-- test_http_parser.py
    |   |-- test_incident_model.py
    |   |-- test_incident_report_model.py
    |   |-- test_net_high_frequency_rule.py
    |   |-- test_report_builder.py
    |   |-- test_text_ingestion.py
    |   |-- test_timeline_builder.py
    |   |-- test_timeline_model.py
    |   |-- test_web_admin_probing_rule.py
    |   |-- test_web_authorization_failures_rule.py
    |   `-- test_web_path_enumeration_rule.py
    `-- test_health.py

## Milestones

### Milestone 0 — Repository Bootstrap

Complete.

### Milestone 1 — Normalized Event Engine

Complete.

Implemented:

- shared security event domain model
- HTTP access-log parser
- Linux SSH authentication parser
- synthetic telemetry samples
- batch file ingestion
- explicit ingestion error handling
- unit and integration tests

### Milestone 2 — Detection Engine

Complete.

Implemented:

- structured Alert domain model
- common DetectionRule contract
- DetectionEngine orchestration
- deterministic alert ordering
- canonical default ruleset
- AUTH-001
- AUTH-002
- WEB-001
- WEB-002
- WEB-003
- NET-001
- full six-rule integration testing

### Milestone 3 — Incident Correlation

Complete.

Implemented:

- structured Incident domain model
- common CorrelationRule contract
- CorrelationEngine orchestration
- deterministic incident ordering
- canonical default correlation engine
- `CORR-AUTH-001` suspicious-authentication correlation
- same-source and shared-evidence correlation requirements
- single-use authentication failure evidence
- alert and event evidence preservation
- complete detection-to-correlation integration testing

### Milestone 4 — Investigation Timeline and Reporting

Complete.

Implemented:

- structured TimelineEntry domain model
- structured InvestigationTimeline domain model
- deterministic timeline construction
- incident-scoped evidence resolution
- missing-evidence fail-fast behavior
- event-before-alert tie-breaking at equal timestamps
- JSON-safe nested timeline details
- structured IncidentReport version 1.0
- report-to-timeline evidence integrity validation
- explicit analyst conclusions
- explicit report limitations
- deterministic report JSON
- exact JSON serialization round-trips
- complete Event-to-Report integration testing

The implemented canonical authentication workflow demonstrates:

    6 normalized Events
        -> 2 Alerts
        -> 1 Incident
        -> 8 Timeline entries
        -> 1 IncidentReport
        -> JSON

The next project milestone has not started. Its scope will be defined after this Milestone 4 closeout rather than expanding the MVP automatically.

### Milestone 5 — Analysis API

Complete.

Implemented:

- reusable analysis application service
- in-memory HTTP access-log ingestion
- in-memory Linux authentication-log ingestion
- request validation through `AnalyzeRequest`
- Linux auth year configuration
- Linux auth timezone-offset configuration
- `POST /analyze`
- structured `AnalysisResult` responses
- standalone-alert preservation
- correlated incident and timeline responses
- structured malformed-log HTTP 422 errors
- physical source-line preservation in parse errors
- parser-reason preservation
- server-error separation from client errors
- OpenAPI schema exposure
- Swagger documentation exposure
- end-to-end public API evidence-chain testing

The canonical authentication API workflow demonstrates:

    POST /analyze
        -> 6 normalized Events
        -> 2 Alerts
        -> 1 Incident
        -> 1 InvestigationTimeline
        -> 8 Timeline entries
        -> AnalysisResult JSON

The public API preserves event IDs and alert IDs through correlation and investigation-timeline construction.

`IncidentReport` generation remains separate because analyst conclusions and limitations must be supplied explicitly rather than generated automatically.

The next project milestone has not started. Its scope will be selected after a new project re-baseline rather than automatically adding persistence, a frontend, or additional detection rules.

## Design Principles

IncidentScope is intended to remain:

- defensive
- evidence-based
- explainable
- testable
- reproducible
- intentionally small enough to understand end-to-end

The project does not use AI, distributed systems, Redis, Kafka, Elasticsearch, or microservices in the MVP unless a demonstrated requirement justifies them.
