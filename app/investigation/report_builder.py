from collections.abc import Sequence

from app.domain.incidents import Incident
from app.domain.reports import IncidentReport
from app.domain.timelines import InvestigationTimeline


def build_incident_report(
    incident: Incident,
    timeline: InvestigationTimeline,
    *,
    analyst_conclusion: str,
    limitations: Sequence[str] = (),
) -> IncidentReport:
    """Build a validated report from an incident and its timeline."""

    return IncidentReport(
        incident_id=incident.incident_id,
        incident_type=incident.incident_type,
        title=incident.title,
        severity=incident.severity,
        summary=incident.summary,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        source_ips=list(incident.source_ips),
        users=list(incident.users),
        tags=list(incident.tags),
        alert_ids=list(incident.alert_ids),
        event_ids=list(incident.event_ids),
        timeline=timeline,
        analyst_conclusion=analyst_conclusion,
        limitations=list(limitations),
    )
