import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Load local .env values before application modules read configuration.
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.ai.provider import get_ai_provider
from app.api.analysis import router as analysis_router
from app.api.history import router as history_router
from app.database.history_repository import initialize_database
from app.ml.classifier import ml_health


def _cors_origins() -> list[str]:
    raw = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173",
    )

    return [
        origin.strip()
        for origin in raw.split(",")
        if origin.strip()
    ]


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Initialize SQLite/history database.
    initialize_database()

    # Load/cache ML classifier during startup when enabled.
    # Calling ml_health() triggers the cached classifier loader.
    ml_health()

    yield


app = FastAPI(
    title="ScamShield AI API",
    version="2.0.0",
    description=(
        "Hybrid AI-assisted and explainable "
        "scam risk assessment API"
    ),
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Existing API routes
app.include_router(
    analysis_router
)

app.include_router(
    history_router
)


@app.get("/api/health")
def health_check():
    """
    Health endpoint.

    Reports:
    - Core API readiness
    - External AI provider readiness
    - Screenshot readiness
    - Local ML model readiness
    - ML model version
    - Frozen ML threshold

    No secrets are returned.
    """

    provider = get_ai_provider()

    ml = ml_health()

    ai_provider = (
        provider.name
        if provider
        else "disabled"
    )

    screenshot_ready = (
        provider is not None
    )

    return {
        "status": "ok",

        "service": "ScamShield AI API",

        "version": "2.0.0",

        # --------------------------------------------
        # External Generative AI
        # --------------------------------------------

        "ai_provider": ai_provider,

        "ai_ready": (
            provider is not None
        ),

        "screenshot_ready":
            screenshot_ready,

        # --------------------------------------------
        # Local trained ML classifier
        # --------------------------------------------

        "ml_status":
            ml["status"],

        "ml_ready":
            ml["ready"],

        "ml_model_version":
            ml["model_version"],

        "ml_selected_threshold":
            ml["selected_threshold"],

        # --------------------------------------------
        # Available capabilities
        # --------------------------------------------

        "features": [
            "message-analysis",
            "url-analysis",
            "screenshot-analysis",

            "trained-local-ml-classifier",

            "multimodal-text-extraction",

            "structured-ai-analysis",

            "deterministic-risk-engine",

            "sqlite-history",

            "privacy-safe-input-previews",

            "demo-ready-sample-cases",

            "configurable-cors",

            "release-smoke-check",
        ],
    }