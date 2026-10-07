from datetime import timedelta, timezone

from fastapi import APIRouter, HTTPException

from app.api.contracts import (
    AnalyzeRequest,
    LogIngestionErrorDetail,
)
from app.application.analysis import (
    AnalysisResult,
    analyze_events,
)
from app.ingestion.text import (
    TextIngestionLineError,
    ingest_text,
)


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

    try:
        events = ingest_text(
            request.log_text,
            source_type=request.source_type,
            year=request.year,
            timezone_info=timezone_info,
        )
    except TextIngestionLineError as exc:
        error = LogIngestionErrorDetail(
            line_number=exc.line_number,
            reason=exc.reason,
        )

        raise HTTPException(
            status_code=422,
            detail=error.model_dump(),
        ) from exc

    return analyze_events(events)
