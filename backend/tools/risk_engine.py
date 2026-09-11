RISK_WEIGHTS = {
    "Urgent language": 15,
    "Account threat": 15,
    "Verification request": 20,
    "Credential request": 25,
    "Payment request": 20,
    "Prize or reward": 15,
    "Suspicious link": 20,
}


def calculate_risk(indicators: list[str]) -> dict:
    """
    Calculate a deterministic scam risk score from detected indicators.
    """

    score = sum(
        RISK_WEIGHTS.get(indicator, 0)
        for indicator in indicators
    )

    score = min(score, 100)

    if score >= 80:
        risk_level = "CRITICAL"
    elif score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
    }