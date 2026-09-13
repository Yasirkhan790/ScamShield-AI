from typing import Literal

from pydantic import BaseModel, Field, field_validator

AISeverity = Literal["low", "medium", "high"]

ALLOWED_SCAM_CATEGORIES = {
    "Phishing",
    "Impersonation",
    "Payment Scam",
    "Job Scam",
    "Investment Scam",
    "Prize/Lottery Scam",
    "Romance Scam",
    "Account Takeover",
    "Delivery/Package Scam",
    "Other / Suspicious",
    "No Strong Scam Pattern Detected",
}


class AIObservation(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    description: str = Field(..., min_length=1, max_length=300)
    severity: AISeverity


class AIScamAnalysis(BaseModel):
    summary: str = Field(..., min_length=1, max_length=700)
    category: str = Field(..., min_length=1, max_length=80)
    secondary_categories: list[str] = Field(default_factory=list, max_length=3)
    observations: list[AIObservation] = Field(default_factory=list, max_length=8)
    recommended_actions: list[str] = Field(default_factory=list, max_length=6)

    @field_validator("category")
    @classmethod
    def validate_category(cls, value: str) -> str:
        value = value.strip()
        if value not in ALLOWED_SCAM_CATEGORIES:
            raise ValueError("Unsupported scam category")
        return value

    @field_validator("secondary_categories")
    @classmethod
    def validate_secondary_categories(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            value = value.strip()
            if value in ALLOWED_SCAM_CATEGORIES and value not in cleaned:
                cleaned.append(value)
        return cleaned[:3]

    @field_validator("recommended_actions")
    @classmethod
    def clean_actions(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values if value.strip()]
        return cleaned[:6]
