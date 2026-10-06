# IncidentScope

IncidentScope is a defensive security event analysis and incident investigation platform.

It transforms raw security telemetry into normalized events that can later be evaluated by explainable detection rules, correlated into incidents, and reviewed through investigation timelines and structured reports.

## Status

Milestone 1 — Normalized Event Engine: **Complete**

Current test suite:

- 19 automated tests passing
- unit tests for domain models and parsers
- integration tests for file ingestion

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

## Current Pipeline

    Raw Log File
        ↓
    Line Reader
        ↓
    Source-Specific Parser
        ↓
    Normalized Event
        ↓
    Event[]

Detection logic is intentionally not part of the ingestion layer.

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
- SQLite planned for later milestones

## Project Structure

    app/
    ├── domain/
    │   └── events.py
    ├── ingestion/
    │   ├── auth_parser.py
    │   ├── batch.py
    │   └── http_parser.py
    └── main.py

    samples/
    ├── auth/
    │   └── auth.log
    └── http/
        └── access.log

    tests/
    ├── integration/
    │   └── test_batch_ingestion.py
    ├── unit/
    │   ├── test_auth_parser.py
    │   ├── test_event_model.py
    │   └── test_http_parser.py
    └── test_health.py

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

Next.

Initial planned rules:

- `AUTH-001` — Repeated Authentication Failures
- `AUTH-002` — Successful Login After Failure Burst
- `WEB-001` — Suspicious Administrative Path Probing
- `WEB-002` — Repeated Authorization Failures
- `WEB-003` — Scanning-Like Path Enumeration
- `NET-001` — High-Frequency Source Activity

## Design Principles

IncidentScope is intended to remain:

- defensive
- evidence-based
- explainable
- testable
- reproducible
- intentionally small enough to understand end-to-end

The project does not use AI, distributed systems, Redis, Kafka, Elasticsearch, or microservices in the MVP unless a demonstrated requirement justifies them.
