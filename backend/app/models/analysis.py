from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator

RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
IndicatorSeverity = Literal["low", "medium", "high"]
AIStatus = Literal["used", "disabled", "fallback"]
HistoryInputType = Literal["message", "url", "screenshot"]


class MessageAnalysisRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)

    @field_validator("message")
    @classmethod
    def strip_message(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Message cannot be empty")
        return value


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def strip_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("URL cannot be empty")
        if any(char.isspace() for char in value):
            raise ValueError("URL cannot contain spaces")
        return value


class Indicator(BaseModel):
    code: str
    name: str
    description: str
    severity: IndicatorSeverity
    weight: int


class AIObservation(BaseModel):
    name: str
    description: str
    severity: IndicatorSeverity


class BaseAnalysisResponse(BaseModel):
    analysis_id: int | None = None
    summary: str
    category: str
    secondary_categories: list[str] = Field(default_factory=list)
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    indicators: list[Indicator]
    ai_observations: list[AIObservation] = Field(default_factory=list)
    ai_status: AIStatus = "disabled"
    ai_provider: str | None = None
    recommended_actions: list[str]
    disclaimer: str
    analysis_steps: list[str] = Field(default_factory=list)


class MessageAnalysisResponse(BaseAnalysisResponse):
    pass


class URLAnalysisResponse(BaseAnalysisResponse):
    normalized_url: str
    host: str
    uses_https: bool


class ScreenshotAnalysisResponse(BaseAnalysisResponse):
    extracted_text: str
    file_name: str
    image_type: str
    text_extraction_status: Literal["used"] = "used"
    text_extraction_provider: str


class HistoryListItem(BaseModel):
    id: int
    input_type: HistoryInputType
    input_content: str
    scam_category: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    created_at: str


class HistoryDetail(HistoryListItem):
    red_flags: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    result: dict[str, Any]
