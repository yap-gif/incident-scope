# IncidentScope

IncidentScope is a defensive security event analysis and incident investigation platform.

It transforms raw security telemetry into normalized events, evaluates those events with explainable detection rules, and produces structured security alerts that can later be correlated into incidents and investigation timelines.

## Status

Milestone 3 — Incident Correlation: **Complete**

Current test suite:

- 107 automated tests passing
- unit tests for domain models, parsers, detection rules, correlation rules, and engine behavior
- integration tests for file ingestion, default detection, default correlation, and the complete detection-to-correlation pipeline

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

    Raw Log File
        ↓
    Line Reader
        ↓
    Source-Specific Parser
        ↓
    Normalized Event[]
        ↓
    DetectionEngine
        ↓
    DetectionRule[]
        ↓
    Alert[]
        ↓
    CorrelationEngine
        ↓
    CorrelationRule[]
        ↓
    Incident[]

The canonical MVP pipeline can transform normalized authentication events into explainable alerts and then correlate those alerts into a suspicious-authentication incident while preserving supporting alert and event evidence.

Investigation timelines, structured analyst reports, persistence, and user interfaces are not implemented yet.

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
    |   `-- incidents.py
    |-- ingestion/
    |   |-- auth_parser.py
    |   |-- batch.py
    |   `-- http_parser.py
    `-- main.py

    samples/
    |-- auth/
    |   `-- auth.log
    `-- http/
        `-- access.log

    tests/
    |-- integration/
    |   |-- test_batch_ingestion.py
    |   |-- test_default_correlation_engine.py
    |   |-- test_default_detection_engine.py
    |   `-- test_detection_correlation_pipeline.py
    |-- unit/
    |   |-- test_alert_model.py
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
    |   |-- test_net_high_frequency_rule.py
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

Next.

Planned direction:

- derive chronological investigation timelines from incident evidence
- preserve links between incidents, alerts, and normalized events
- generate structured machine-readable incident reports
- provide concise analyst-oriented findings without inventing unsupported conclusions
- keep timeline and reporting logic independent from persistence and UI concerns

## Design Principles

IncidentScope is intended to remain:

- defensive
- evidence-based
- explainable
- testable
- reproducible
- intentionally small enough to understand end-to-end

The project does not use AI, distributed systems, Redis, Kafka, Elasticsearch, or microservices in the MVP unless a demonstrated requirement justifies them.
