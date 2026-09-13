from app.models.analysis import Indicator, RiskLevel


def calculate_risk(indicators: list[Indicator]) -> tuple[int, RiskLevel]:
    codes = {indicator.code for indicator in indicators}
    score = sum(indicator.weight for indicator in indicators)

    # Compound-risk bonuses. These combinations are more concerning than
    # each signal in isolation, while keeping the calculation deterministic.
    if {"prize_claim", "payment_request"}.issubset(codes):
        score += 20
    if {"job_scam_signal", "payment_request"}.issubset(codes):
        score += 15
    if {"investment_claim", "payment_request"}.issubset(codes):
        score += 15
    if {"credential_request", "account_threat"}.issubset(codes):
        score += 10

    score = min(score, 100)

    if score <= 29:
        level: RiskLevel = "LOW"
    elif score <= 59:
        level = "MEDIUM"
    elif score <= 79:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return score, level
