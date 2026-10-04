from pathlib import Path

from app.ai.service import (
    extract_text_from_image_with_ai,
)

from app.models.analysis import (
    ScreenshotAnalysisResponse,
)

from app.services.local_ocr_service import (
    extract_text_with_local_ocr,
)

from app.services.message_analysis_service import (
    analyze_message_content,
)


class ScreenshotProcessingError(
    RuntimeError
):
    def __init__(
        self,
        message: str,
        status_code: int = 422,
    ):
        super().__init__(
            message
        )

        self.status_code = (
            status_code
        )


def _safe_filename(
    value: str | None,
) -> str:

    if not value:
        return "screenshot"

    name = Path(
        value.replace(
            "\\",
            "/",
        )
    ).name.strip()

    return (
        name[:120]
        or "screenshot"
    )


def analyze_screenshot_content(
    image_bytes: bytes,
    mime_type: str,
    file_name: str | None,
) -> ScreenshotAnalysisResponse:

    # ========================================================
    # 1. TRY CONFIGURED MULTIMODAL AI FIRST
    # ========================================================

    ai_extraction = (
        extract_text_from_image_with_ai(
            image_bytes,
            mime_type,
        )
    )

    extracted_text = ""

    extraction_provider = ""

    extraction_method = ""

    if (
        ai_extraction.status
        == "used"
        and ai_extraction.text.strip()
    ):
        extracted_text = (
            ai_extraction.text.strip()
        )

        extraction_provider = (
            ai_extraction.provider
            or "ai"
        )

        extraction_method = (
            "multimodal AI"
        )

    # ========================================================
    # 2. FREE LOCAL OCR FALLBACK
    # ========================================================

    if not extracted_text:

        local_extraction = (
            extract_text_with_local_ocr(
                image_bytes
            )
        )

        if (
            local_extraction.status
            == "used"
            and local_extraction.text.strip()
        ):
            extracted_text = (
                local_extraction.text.strip()
            )

            extraction_provider = (
                local_extraction.provider
                or "tesseract"
            )

            extraction_method = (
                "local OCR"
            )

    # ========================================================
    # 3. NOTHING COULD EXTRACT TEXT
    # ========================================================

    if not extracted_text:

        if (
            ai_extraction.status
            == "disabled"
        ):
            raise ScreenshotProcessingError(
                (
                    "Screenshot text extraction is unavailable. "
                    "Configure a multimodal AI provider or enable "
                    "LOCAL_OCR_ENABLED with Tesseract installed."
                ),
                status_code=503,
            )

        raise ScreenshotProcessingError(
            (
                "ScamShield could not extract readable text "
                "from this screenshot. Try a clearer image or "
                "paste the message into the Message scanner."
            ),
            status_code=422,
        )

    # ========================================================
    # 4. REUSE THE COMPLETE V2 MESSAGE PIPELINE
    # ========================================================

    message_result = (
        analyze_message_content(
            extracted_text
        )
    )

    steps = [
        "Validated screenshot file and type",

        (
            f"Extracted visible text with "
            f"{extraction_provider} "
            f"using {extraction_method}"
        ),

        *message_result.analysis_steps,
    ]

    # ========================================================
    # 5. FINAL SCREENSHOT RESPONSE
    # ========================================================

    return ScreenshotAnalysisResponse(
        **message_result.model_dump(
            exclude={
                "analysis_steps",
            }
        ),

        extracted_text=
            extracted_text,

        file_name=
            _safe_filename(
                file_name
            ),

        image_type=
            mime_type,

        text_extraction_status=
            "used",

        text_extraction_provider=
            extraction_provider,

        analysis_steps=
            steps,
    )