from pathlib import Path

from app.ai.service import extract_text_from_image_with_ai
from app.models.analysis import ScreenshotAnalysisResponse
from app.services.message_analysis_service import analyze_message_content


class ScreenshotProcessingError(RuntimeError):
    def __init__(self, message: str, status_code: int = 422):
        super().__init__(message)
        self.status_code = status_code


def _safe_filename(value: str | None) -> str:
    if not value:
        return "screenshot"
    name = Path(value.replace("\\", "/")).name.strip()
    return name[:120] or "screenshot"


def analyze_screenshot_content(
    image_bytes: bytes,
    mime_type: str,
    file_name: str | None,
) -> ScreenshotAnalysisResponse:
    extraction = extract_text_from_image_with_ai(image_bytes, mime_type)

    if extraction.status == "disabled":
        raise ScreenshotProcessingError(
            "Screenshot analysis requires a configured multimodal AI provider. Set AI_PROVIDER, AI_API_KEY, and AI_MODEL, or use the Message scanner instead.",
            status_code=503,
        )

    if extraction.status != "used" or not extraction.text.strip():
        raise ScreenshotProcessingError(
            "ScamShield could not extract readable text from this screenshot. Try a clearer image or paste the message into the Message scanner.",
            status_code=422,
        )

    message_result = analyze_message_content(extraction.text)
    steps = [
        "Validated screenshot file and type",
        f"Extracted visible text with {extraction.provider} multimodal analysis",
        *message_result.analysis_steps,
    ]

    return ScreenshotAnalysisResponse(
        **message_result.model_dump(exclude={"analysis_steps"}),
        extracted_text=extraction.text,
        file_name=_safe_filename(file_name),
        image_type=mime_type,
        text_extraction_status="used",
        text_extraction_provider=extraction.provider or "ai",
        analysis_steps=steps,
    )
