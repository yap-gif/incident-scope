from pydantic import (
    BaseModel,
    Field,
    model_validator,
)

from app.domain.events import SourceType


class AnalyzeRequest(BaseModel):
    """Request body for one IncidentScope analysis run."""

    source_type: SourceType

    log_text: str = Field(
        min_length=1
    )

    year: int | None = Field(
        default=None,
        ge=1,
        le=9999,
    )

    timezone_offset_minutes: int = Field(
        default=0,
        ge=-840,
        le=840,
    )

    @model_validator(mode="after")
    def validate_source_configuration(
        self,
    ) -> "AnalyzeRequest":
        if (
            self.source_type == "linux_auth"
            and self.year is None
        ):
            raise ValueError(
                "year is required for linux_auth logs"
            )

        return self
