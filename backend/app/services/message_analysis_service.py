from app.ai.service import analyze_message_with_ai
from app.models.analysis import AIObservation, MessageAnalysisResponse
from app.tools.message_analyzer import analyze_message
from app.tools.risk_engine import calculate_risk
from app.tools.safety_advisor import generate_safety_advice
from app.tools.scam_classifier import classify_scam

DISCLAIMER = (
    "ScamShield provides an AI-assisted risk assessment based on available indicators. "
    "It cannot guarantee that content is safe or malicious. The score is an application-defined indicator, not a probability."
)


def build_summary(category: str, score: int, indicator_count: int) -> str:
    if indicator_count == 0:
        return "No strong scam pattern was detected from the deterministic indicators. Continue to verify unusual requests independently."
    return (
        f"The message shows {indicator_count} suspicious indicator(s) associated with {category}. "
        f"The application-defined risk score is {score}/100 and reflects detected signals, not a verified probability of fraud."
    )


def _merge_actions(base: list[str], extra: list[str]) -> list[str]:
    merged: list[str] = []
    for action in [*base, *extra]:
        normalized = action.strip()
        if normalized and normalized.lower() not in {item.lower() for item in merged}:
            merged.append(normalized)
    return merged[:6]


def analyze_message_content(message: str) -> MessageAnalysisResponse:
    indicators = analyze_message(message)
    score, level = calculate_risk(indicators)
    category, secondary = classify_scam(indicators)
    deterministic_actions = generate_safety_advice(indicators)

    ai_result = analyze_message_with_ai(message, indicators)
    summary = build_summary(category, score, len(indicators))
    ai_observations: list[AIObservation] = []
    actions = deterministic_actions

    if ai_result.analysis is not None:
        analysis = ai_result.analysis
        # AI can improve classification and explanation, but never the numeric score.
        category = analysis.category
        secondary = analysis.secondary_categories
        summary = analysis.summary
        ai_observations = [
            AIObservation(
                name=item.name,
                description=item.description,
                severity=item.severity,
            )
            for item in analysis.observations
        ]
        actions = _merge_actions(deterministic_actions, analysis.recommended_actions)

    return MessageAnalysisResponse(
        summary=summary,
        category=category,
        secondary_categories=secondary,
        risk_score=score,
        risk_level=level,
        indicators=indicators,
        ai_observations=ai_observations,
        ai_status=ai_result.status,
        ai_provider=ai_result.provider,
        recommended_actions=actions,
        disclaimer=DISCLAIMER,
        analysis_steps=[
            "Inspect message content",
            "Detect deterministic warning signals",
            "Calculate deterministic risk score",
            "Request structured AI analysis when configured",
            "Validate AI JSON and fall back safely if needed",
            "Generate final safety guidance",
        ],
    )
