from datetime import timedelta, timezone

from fastapi import APIRouter

from app.api.contracts import AnalyzeRequest
from app.application.analysis import (
    AnalysisResult,
    analyze_events,
)
from app.ingestion.text import ingest_text


router = APIRouter()


@router.post(
    "/analyze",
    response_model=AnalysisResult,
)
def analyze(
    request: AnalyzeRequest,
) -> AnalysisResult:
    """Analyze one block of supported security telemetry."""

    timezone_info = timezone(
        timedelta(
            minutes=request.timezone_offset_minutes
        )
    )

    events = ingest_text(
        request.log_text,
        source_type=request.source_type,
        year=request.year,
        timezone_info=timezone_info,
    )

    return analyze_events(events)
