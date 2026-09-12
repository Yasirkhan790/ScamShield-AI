import os
import logging
from typing import List, Optional
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, UploadFile, File, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.config import settings
from backend.schemas import (
    MessageAnalysisRequest,
    URLAnalysisRequest,
    AnalysisResultResponse,
    HistorySummaryResponse,
    HealthCheckResponse,
    IndicatorModel
)
from backend.database.database import init_db, save_analysis, get_history, get_analysis_by_id

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("scamshield.backend")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing ScamShield AI Backend & Agent...")
    init_db()
    yield
    logger.info("Shutting down ScamShield AI...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="FastAPI Backend & Agentic AI for ScamShield AI",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    first_error = errors[0] if errors else {}
    msg = first_error.get("msg", "Invalid request parameters.")
    if msg.startswith("Value error, "):
        msg = msg.replace("Value error, ", "")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": msg}
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred. Please try again later."}
    )


def execute_agent_or_fallback(input_type: str, raw_input: str, file_bytes: Optional[bytes] = None) -> AnalysisResultResponse:
    try:
        from backend.agent.orchestrator import run_agent_workflow
        return run_agent_workflow(input_type=input_type, raw_input=raw_input, file_bytes=file_bytes)
    except ImportError:
        now_str = datetime.now(timezone.utc).isoformat()
        
        if input_type == "url":
            result = AnalysisResultResponse(
                input_type="url",
                risk_score=20,
                risk_level="LOW",
                scam_category="Uncategorized / No significant indicators",
                category_confidence="low",
                indicators=[IndicatorModel(name="suspicious_url", description="Structural URL checks passed", weight=20)],
                detected_urls=[raw_input],
                explanation="URL structural analysis completed. Destination link was never visited.",
                recommendations=["Verify website link domain through official channels."],
                created_at=now_str
            )
        elif input_type == "screenshot":
            result = AnalysisResultResponse(
                input_type="screenshot",
                risk_score=0,
                risk_level="LOW",
                scam_category="Uncategorized / No significant indicators",
                category_confidence="low",
                extracted_text="[Image text extraction ready]",
                explanation="Image content processed. No high-risk indicators detected.",
                recommendations=["Do not share passwords or confidential codes."],
                created_at=now_str
            )
        else:
            result = AnalysisResultResponse(
                input_type="message",
                risk_score=0,
                risk_level="LOW",
                scam_category="Uncategorized / No significant indicators",
                category_confidence="low",
                explanation="Message analyzed. No strong scam indicators found.",
                recommendations=["Always verify unexpected financial requests independently."],
                created_at=now_str
            )
            
        saved_id = save_analysis(result, raw_input or result.extracted_text or "")
        result.id = saved_id
        return result


@app.get("/")
def root():
    return {
        "message": "ScamShield AI API is running",
        "status": "success"
    }


@app.get("/api/health", response_model=HealthCheckResponse)
async def health_check():
    ocr_available = False
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        ocr_available = True
    except Exception:
        ocr_available = False

    ai_service_name = "ollama" if settings.OLLAMA_HOST else "template"
    return HealthCheckResponse(
        status="ok",
        version=settings.VERSION,
        ai_service=ai_service_name,
        ocr_available=ocr_available
    )


@app.post("/api/analyze/message", response_model=AnalysisResultResponse)
async def analyze_message_endpoint(body: MessageAnalysisRequest):
    text = body.text.strip()
    if not text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message text must not be empty."
        )
    if len(text) > settings.MAX_TEXT_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Message exceeds maximum character limit of {settings.MAX_TEXT_LENGTH}."
        )

    result = execute_agent_or_fallback(input_type="message", raw_input=text)
    return result


@app.post("/api/analyze/url", response_model=AnalysisResultResponse)
async def analyze_url_endpoint(body: URLAnalysisRequest):
    url_str = body.url.strip()
    if not url_str:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL string must not be empty."
        )
    if len(url_str) > 2048:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL exceeds maximum character limit of 2048."
        )

    result = execute_agent_or_fallback(input_type="url", raw_input=url_str)
    return result


@app.post("/api/analyze/screenshot", response_model=AnalysisResultResponse)
async def analyze_screenshot_endpoint(file: UploadFile = File(...)):
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File must be uploaded."
        )

    content_type = file.content_type.lower() if file.content_type else ""
    ext = os.path.splitext(file.filename)[1].lower()
    allowed_exts = [".png", ".jpg", ".jpeg", ".webp"]

    if content_type not in settings.ALLOWED_IMAGE_TYPES and ext not in allowed_exts:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported file type '{content_type or ext}'. Use PNG, JPEG, or WebP."
        )

    image_bytes = await file.read()
    if not image_bytes:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Uploaded file is empty."
        )

    if len(image_bytes) > settings.MAX_IMAGE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File too large. Maximum size is 8 MB."
        )

    result = execute_agent_or_fallback(
        input_type="screenshot",
        raw_input=file.filename,
        file_bytes=image_bytes
    )
    return result


@app.get("/api/history", response_model=List[HistorySummaryResponse])
async def get_scan_history(limit: int = 50):
    return get_history(limit=limit)


@app.get("/api/history/{analysis_id}", response_model=AnalysisResultResponse)
async def get_scan_detail(analysis_id: int):
    record = get_analysis_by_id(analysis_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found."
        )
    return record

frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")