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


def _cors_origins() -> list[str]:
    raw = os.getenv("CORS_ORIGINS", "http://localhost:5173")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="ScamShield AI API",
    version="1.0.0",
    description="AI-assisted, explainable scam risk assessment API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analysis_router)
app.include_router(history_router)


@app.get("/api/health")
def health_check():
    provider = get_ai_provider()
    return {
        "status": "ok",
        "service": "ScamShield AI API",
        "version": "1.0.0",
        "ai_provider": provider.name if provider else "disabled",
        "screenshot_ready": provider is not None,
        "features": [
            "message-analysis",
            "url-analysis",
            "screenshot-analysis",
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
