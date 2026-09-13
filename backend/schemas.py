from typing import List, Optional, Literal
from pydantic import BaseModel, Field, field_validator

class MessageAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=8000, description="Suspicious text/message to analyze")

    @field_validator('text')
    def validate_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Message text must not be empty.")
        return v

class URLAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Suspicious URL string to analyze")

    @field_validator('url')
    def validate_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("URL string must not be empty.")
        return v

class IndicatorModel(BaseModel):
    name: str
    description: str
    weight: int

class AnalysisResultResponse(BaseModel):
    id: Optional[int] = None
    input_type: Literal["message", "url", "screenshot"]
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    scam_category: str
    category_confidence: Literal["low", "medium", "high"]
    indicators: List[IndicatorModel] = []
    detected_urls: List[str] = []
    extracted_text: Optional[str] = None
    explanation: str
    recommendations: List[str] = []
    disclaimer: str = (
        "ScamShield AI is an awareness and decision-support tool, not a guarantee of safety. "
        "Its analysis may be incomplete or incorrect. Users should independently verify suspicious requests "
        "through official channels and should never share passwords, OTPs, banking credentials, or other sensitive information."
    )
    created_at: str

class HistorySummaryResponse(BaseModel):
    id: int
    input_type: str
    risk_score: int
    risk_level: str
    scam_category: str
    created_at: str

class HealthCheckResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    ai_service: str = "template"
    ocr_available: bool = False
