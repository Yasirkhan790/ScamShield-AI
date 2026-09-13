from app.ai.service import analyze_url_with_ai
from app.models.analysis import AIObservation, URLAnalysisResponse
from app.tools.url_analyzer import analyze_url
from app.tools.url_risk_engine import calculate_url_risk
from app.tools.url_safety_advisor import generate_url_safety_advice

DISCLAIMER = (
    "ScamShield provides an AI-assisted heuristic risk assessment based on the submitted URL string and detected indicators. "
    "It does not prove that a website is safe or malicious and does not visit the destination."
)


def classify_url_risk(score: int, indicator_codes: set[str]) -> tuple[str, list[str]]:
    phishing_signals = {
        "domain_mismatch",
        "userinfo_obfuscation",
        "ip_address_host",
        "suspicious_keywords",
        "punycode_domain",
    }

    if score >= 60 and indicator_codes & phishing_signals:
        return "Phishing", ["Other / Suspicious"]
    if score >= 30:
        return "Other / Suspicious", []
    return "No Strong Scam Pattern Detected", []


def build_url_summary(category: str, score: int, indicator_count: int, host: str) -> str:
    if indicator_count == 0:
        return (
            f"No strong structural warning was detected in {host}. "
            "This result does not verify the destination or guarantee that the site is safe."
        )
    return (
        f"The URL contains {indicator_count} structural warning signal(s) associated with {category}. "
        f"The application-defined score is {score}/100 and reflects URL heuristics, not a verified probability of fraud."
    )


def _merge_actions(base: list[str], extra: list[str]) -> list[str]:
    merged: list[str] = []
    for action in [*base, *extra]:
        normalized = action.strip()
        if normalized and normalized.lower() not in {item.lower() for item in merged}:
            merged.append(normalized)
    return merged[:6]


def analyze_url_content(url: str) -> URLAnalysisResponse:
    normalized_url, host, uses_https, indicators = analyze_url(url)
    score, level = calculate_url_risk(indicators)
    codes = {item.code for item in indicators}
    category, secondary = classify_url_risk(score, codes)
    deterministic_actions = generate_url_safety_advice(indicators)

    ai_result = analyze_url_with_ai(normalized_url, indicators)
    summary = build_url_summary(category, score, len(indicators), host)
    ai_observations: list[AIObservation] = []
    actions = deterministic_actions

    if ai_result.analysis is not None:
        analysis = ai_result.analysis
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

    return URLAnalysisResponse(
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
        normalized_url=normalized_url,
        host=host,
        uses_https=uses_https,
        analysis_steps=[
            "Validate and normalize URL",
            "Inspect hostname, protocol, and obfuscation signals",
            "Calculate deterministic URL risk",
            "Request structured AI analysis when configured",
            "Validate AI JSON and fall back safely if needed",
            "Generate final safety guidance",
        ],
    )
