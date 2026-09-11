from fastapi import FastAPI
from pydantic import BaseModel

from backend.tools.message_analyzer import analyze_message
from backend.tools.risk_engine import calculate_risk


app = FastAPI(
    title="ScamShield AI",
    description="AI-powered scam awareness and risk analysis assistant",
    version="1.0.0",
)


class MessageRequest(BaseModel):
    message: str


@app.get("/")
def root():
    return {
        "message": "ScamShield AI API is running",
        "status": "success"
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ScamShield AI"
    }


@app.post("/api/analyze/message")
def analyze_scam_message(request: MessageRequest):

    analysis = analyze_message(request.message)

    risk = calculate_risk(analysis["indicators"])

    return {
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "indicators": analysis["indicators"],
        "matched_keywords": analysis["matched_keywords"],
    }