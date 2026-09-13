import json
import re
from dataclasses import dataclass
from typing import Literal

from pydantic import ValidationError

from app.ai.prompts import build_message_prompt, build_url_prompt
from app.ai.provider import AIProviderError, get_ai_provider
from app.ai.schemas import AIScamAnalysis
from app.models.analysis import Indicator

AIStatus = Literal["used", "disabled", "fallback"]


@dataclass
class AIAnalysisResult:
    status: AIStatus
    provider: str | None
    analysis: AIScamAnalysis | None


@dataclass
class ImageTextExtractionResult:
    status: AIStatus
    provider: str | None
    text: str


def _indicator_context(indicators: list[Indicator]) -> str:
    if not indicators:
        return "No deterministic warning indicators were detected."
    return "\n".join(
        f"- {item.name}: {item.description} (severity={item.severity})"
        for item in indicators
    )


def _extract_json(raw: str) -> dict:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


def _run_ai(prompt: str) -> AIAnalysisResult:
    provider = get_ai_provider()
    if provider is None:
        return AIAnalysisResult(status="disabled", provider=None, analysis=None)

    try:
        raw = provider.generate_json(prompt)
        payload = _extract_json(raw)
        analysis = AIScamAnalysis.model_validate(payload)
        return AIAnalysisResult(status="used", provider=provider.name, analysis=analysis)
    except (AIProviderError, json.JSONDecodeError, ValidationError, TypeError, ValueError):
        return AIAnalysisResult(status="fallback", provider=provider.name, analysis=None)


def extract_text_from_image_with_ai(image_bytes: bytes, mime_type: str) -> ImageTextExtractionResult:
    provider = get_ai_provider()
    if provider is None:
        return ImageTextExtractionResult(status="disabled", provider=None, text="")

    try:
        text = provider.extract_text_from_image(image_bytes, mime_type).strip()
        if not text:
            return ImageTextExtractionResult(status="fallback", provider=provider.name, text="")
        return ImageTextExtractionResult(status="used", provider=provider.name, text=text[:10000])
    except (AIProviderError, TypeError, ValueError, AttributeError):
        return ImageTextExtractionResult(status="fallback", provider=provider.name, text="")


def analyze_message_with_ai(message: str, indicators: list[Indicator]) -> AIAnalysisResult:
    prompt = build_message_prompt(message, _indicator_context(indicators))
    return _run_ai(prompt)


def analyze_url_with_ai(url: str, indicators: list[Indicator]) -> AIAnalysisResult:
    prompt = build_url_prompt(url, _indicator_context(indicators))
    return _run_ai(prompt)
