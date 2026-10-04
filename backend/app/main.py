import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

# Load local .env values before application modules read
# configuration.
load_dotenv()


# ============================================================
# FASTAPI IMPORTS
# ============================================================

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# SCAMSHIELD IMPORTS
# ============================================================

from app.ai.provider import (
    get_ai_provider,
)

from app.api.analysis import (
    router as analysis_router,
)

from app.api.history import (
    router as history_router,
)

from app.database.history_repository import (
    initialize_database,
)

from app.ml.classifier import (
    ml_health,
)

from app.services.local_ocr_service import (
    local_ocr_health,
)


# ============================================================
# CORS CONFIGURATION
# ============================================================

def _cors_origins() -> list[str]:
    """
    Read allowed frontend origins from the CORS_ORIGINS
    environment variable.

    Example:

    CORS_ORIGINS=http://localhost:5173,https://your-app.vercel.app
    """

    raw = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173",
    )

    return [
        origin.strip()
        for origin in raw.split(",")
        if origin.strip()
    ]


# ============================================================
# APPLICATION LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(
    _: FastAPI,
):
    """
    Initialize ScamShield resources during application startup.

    Startup tasks:
    - Initialize SQLite history database
    - Load/cache trained ML classifier
    - Check local OCR configuration
    """

    # --------------------------------------------------------
    # Initialize history database
    # --------------------------------------------------------

    initialize_database()

    # --------------------------------------------------------
    # Load the frozen ML model into cache
    # --------------------------------------------------------

    ml_health()

    # --------------------------------------------------------
    # Check local OCR configuration
    # --------------------------------------------------------

    local_ocr_health()

    yield


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="ScamShield AI API",

    version="2.0.0",

    description=(
        "ScamShield AI V2 is a hybrid, multi-agent, "
        "explainable scam risk assessment API. "
        "It combines deterministic rules, trained machine "
        "learning, taxonomy-based evidence fusion, optional "
        "semantic AI, URL analysis, screenshot text extraction, "
        "local OCR fallback, and safety automation."
    ),

    lifespan=lifespan,
)


# ============================================================
# CORS MIDDLEWARE
# ============================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=_cors_origins(),

    allow_credentials=True,

    allow_methods=[
        "*",
    ],

    allow_headers=[
        "*",
    ],
)


# ============================================================
# API ROUTERS
# ============================================================

app.include_router(
    analysis_router
)

app.include_router(
    history_router
)


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():
    """
    Simple deployment verification endpoint.
    """

    return {
        "service": "ScamShield AI API",

        "version": "2.0.0",

        "status": "running",

        "health_endpoint": "/api/health",

        "docs_endpoint": "/docs",
    }


# ============================================================
# HEALTH ENDPOINT
# ============================================================

@app.get("/api/health")
def health_check():
    """
    ScamShield V2 health endpoint.

    Reports:
    - API readiness
    - Generative AI provider availability
    - Local OCR availability
    - Screenshot readiness
    - ML model readiness
    - ML model version
    - Frozen ML threshold
    - Enabled capabilities

    No secrets or API keys are returned.
    """

    # ========================================================
    # GENERATIVE / SEMANTIC AI
    # ========================================================

    provider = (
        get_ai_provider()
    )

    ai_ready = (
        provider is not None
    )

    ai_provider = (
        provider.name
        if provider
        else "disabled"
    )


    # ========================================================
    # TRAINED LOCAL ML
    # ========================================================

    ml = (
        ml_health()
    )


    # ========================================================
    # LOCAL OCR
    # ========================================================

    ocr = (
        local_ocr_health()
    )


    # ========================================================
    # SCREENSHOT READINESS
    #
    # Screenshot processing is considered ready when either:
    #
    # 1. a multimodal AI provider is configured
    #
    # OR
    #
    # 2. local Tesseract OCR is enabled and available
    # ========================================================

    screenshot_ready = (
        ai_ready
        or ocr["ready"]
    )


    # ========================================================
    # HEALTH RESPONSE
    # ========================================================

    return {
        # ----------------------------------------------------
        # CORE SERVICE
        # ----------------------------------------------------

        "status": "ok",

        "service": "ScamShield AI API",

        "version": "2.0.0",


        # ----------------------------------------------------
        # GENERATIVE / SEMANTIC AI
        # ----------------------------------------------------

        "ai_provider":
            ai_provider,

        "ai_ready":
            ai_ready,


        # ----------------------------------------------------
        # SCREENSHOT / OCR
        # ----------------------------------------------------

        "screenshot_ready":
            screenshot_ready,

        "local_ocr_enabled":
            ocr["enabled"],

        "local_ocr_ready":
            ocr["ready"],

        "local_ocr_provider":
            ocr["provider"],


        # ----------------------------------------------------
        # TRAINED LOCAL ML
        # ----------------------------------------------------

        "ml_status":
            ml["status"],

        "ml_ready":
            ml["ready"],

        "ml_model_version":
            ml["model_version"],

        "ml_selected_threshold":
            ml["selected_threshold"],


        # ----------------------------------------------------
        # AVAILABLE CAPABILITIES
        # ----------------------------------------------------

        "features": [
            "message-analysis",

            "url-analysis",

            "screenshot-analysis",

            "multi-agent-orchestration",

            "trained-local-ml-classifier",

            "v2-indicator-taxonomy",

            "evidence-fusion-agent",

            "deterministic-risk-agent",

            "mitigation-aware-analysis",

            "incident-automation",

            "multimodal-text-extraction",

            "local-tesseract-ocr-fallback",

            "structured-ai-analysis",

            "safe-ai-fallback",

            "deterministic-risk-engine",

            "sqlite-history",

            "privacy-safe-input-previews",

            "real-backend-agent-trace",

            "demo-ready-sample-cases",

            "configurable-cors",

            "release-smoke-check",
        ],
    }