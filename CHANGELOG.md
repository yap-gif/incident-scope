# Changelog

All notable changes to IncidentScope are documented in this file.

The project follows semantic versioning for release identifiers.

## [0.1.1] - 2026-10-08

### Added

- MIT License (2026, YAP SHI XIAN).

### Changed

- Bumped package and FastAPI version to 0.1.1.
- No functional changes to the detection or investigation pipeline.

## [0.1.0] - 2026-10-07

### Added

- normalized security event model for HTTP access and Linux authentication telemetry
- Apache/Nginx-style combined access-log ingestion
- Linux/OpenSSH authentication-log ingestion
- batch and in-memory telemetry ingestion
- six explainable detection rules:
  - `AUTH-001` repeated authentication failures
  - `AUTH-002` successful login after a failure burst
  - `WEB-001` suspicious administrative-path probing
  - `WEB-002` repeated authorization failures
  - `WEB-003` scanning-like path enumeration
  - `NET-001` high-frequency source activity
- deterministic detection engine
- incident domain model and correlation engine
- `CORR-AUTH-001` suspicious-authentication correlation
- investigation timeline generation
- structured incident-report generation with explicit analyst conclusions
- JSON-safe investigation evidence
- reusable analysis application service
- public `POST /analyze` FastAPI endpoint
- structured malformed-log HTTP 422 responses
- OpenAPI and Swagger documentation
- canonical suspicious-authentication sample
- one-command canonical API demo client
- portfolio-focused README
- detailed engineering notes
- GitHub Actions Python 3.13 quality-gate workflow

### Verification

- 161 automated unit and integration tests
- clean Python 3.13 installation verified
- dependency consistency verified with `pip check`
- Python source compilation verified with `compileall`
- real Uvicorn startup verified
- `/health`, `/openapi.json`, and `/docs` verified over HTTP
- canonical `POST /analyze` workflow verified over a real HTTP server
- canonical demo verified as:
  - 6 normalized events
  - 2 alerts (`AUTH-001`, `AUTH-002`)
  - 1 `suspicious_authentication` incident
  - 1 investigation timeline
  - 8 timeline entries

### Scope

The 0.1.0 MVP intentionally does not include:

- persistent storage
- user authentication or accounts
- a frontend application
- distributed processing
- automatic attribution or compromise claims
- AI-generated analyst conclusions

Supported telemetry is currently limited to:

- Apache/Nginx-style HTTP access logs
- Linux/OpenSSH authentication logs
