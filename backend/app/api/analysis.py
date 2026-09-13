from fastapi import APIRouter, File, HTTPException, UploadFile

from app.agents.scamshield_agent import scamshield_agent
from app.database.history_repository import save_analysis
from app.models.analysis import (
    MessageAnalysisRequest,
    MessageAnalysisResponse,
    ScreenshotAnalysisResponse,
    URLAnalysisRequest,
    URLAnalysisResponse,
)
from app.services.screenshot_analysis_service import ScreenshotProcessingError
from app.tools.image_validator import ImageValidationError, screenshot_max_bytes, validate_image_bytes

router = APIRouter(prefix="/api/analyze", tags=["analysis"])


@router.post("/message", response_model=MessageAnalysisResponse)
def analyze_message_endpoint(payload: MessageAnalysisRequest):
    result = scamshield_agent.analyze_message(payload.message)
    result.analysis_id = save_analysis("message", payload.message, result)
    return result


@router.post("/url", response_model=URLAnalysisResponse)
def analyze_url_endpoint(payload: URLAnalysisRequest):
    try:
        result = scamshield_agent.analyze_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    result.analysis_id = save_analysis("url", payload.url, result)
    return result


@router.post("/screenshot", response_model=ScreenshotAnalysisResponse)
async def analyze_screenshot_endpoint(file: UploadFile = File(...)):
    max_bytes = screenshot_max_bytes()
    image_bytes = await file.read(max_bytes + 1)

    if len(image_bytes) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Screenshot is too large. Maximum upload size is {max_bytes // (1024 * 1024)} MB.",
        )

    try:
        mime_type = validate_image_bytes(image_bytes, file.content_type or "")
        result = scamshield_agent.analyze_screenshot(image_bytes, mime_type, file.filename)
    except ImageValidationError as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except ScreenshotProcessingError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    finally:
        await file.close()

    result.analysis_id = save_analysis("screenshot", result.extracted_text, result)
    return result
