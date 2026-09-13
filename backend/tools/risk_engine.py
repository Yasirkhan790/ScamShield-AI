RISK_WEIGHTS = {
    "credential_request": 25,
    "otp_request": 25,
    "payment_request": 20,
    "suspicious_url": 20,
    "urgency": 15,
    "threat": 15,
    "account_suspension": 15,
    "prize_claim": 15,
    "job_offer_scam": 15,
    "investment_scam": 15,
    "impersonation": 10,
    "personal_info_request": 10,
    "emotional_pressure": 10,
    "limited_time_pressure": 10,
    "romance_pressure": 10,
}


RISK_LABELS = {
    "credential_request": "Requests your password or login credentials",
    "otp_request": "Requests a one-time password or verification code",
    "payment_request": "Requests money or a payment",
    "suspicious_url": "Contains a suspicious link",
    "urgency": "Uses urgent language to pressure you",
    "threat": "Uses threats or fear to pressure you",
    "account_suspension": "Claims your account may be suspended or closed",
    "prize_claim": "Claims you have won a prize or reward",
    "job_offer_scam": "Uses patterns commonly found in fake job offers",
    "investment_scam": "Uses patterns commonly found in investment scams",
    "impersonation": "Pretends to be a trusted person or organization",
    "personal_info_request": "Requests sensitive personal information",
    "emotional_pressure": "Uses emotional pressure to influence your decision",
    "limited_time_pressure": "Creates pressure through a limited deadline",
    "romance_pressure": "Uses patterns associated with romance scams",
}


CATEGORY_RULES = {
    "Phishing": {
        "urgency",
        "credential_request",
        "suspicious_url",
        "account_suspension",
    },
    "Financial scam": {
        "payment_request",
        "prize_claim",
        "investment_scam",
    },
    "Credential theft": {
        "credential_request",
        "otp_request",
    },
    "Prize/lottery scam": {
        "prize_claim",
        "payment_request",
    },
    "Account impersonation": {
        "impersonation",
        "account_suspension",
    },
    "Job scam": {
        "job_offer_scam",
    },
    "Investment scam": {
        "investment_scam",
    },
    "Payment scam": {
        "payment_request",
    },
    "Romance/social engineering scam": {
        "romance_pressure",
        "emotional_pressure",
    },
    "Other suspicious activity": set(),
}


def calculate_confidence(indicator_count: int) -> str:
    if indicator_count >= 4:
        return "high"
    elif indicator_count >= 2:
        return "medium"
    else:
        return "low"


def calculate_risk(indicators: list[str]) -> dict:
    """
    Calculate a deterministic scam risk score from detected indicators.
    Unknown indicators contribute zero and do not cause an error.
    """

    unique_indicators = list(dict.fromkeys(indicators))

    contributing_indicators = []

    for indicator in unique_indicators:
        weight = RISK_WEIGHTS.get(indicator, 0)

        if weight > 0:
            contributing_indicators.append({
                "indicator": indicator,
                "weight": weight,
                "label": RISK_LABELS[indicator],
            })

    score = sum(
        item["weight"]
        for item in contributing_indicators
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

    confidence = calculate_confidence(len(contributing_indicators))

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "confidence": confidence,
        "contributing_indicators": contributing_indicators,
    }


def classify_category(indicators: list[str]) -> dict:
    """
    Classify a scam based on detected indicators.
    """

    if not indicators:
        return {
            "category": "Uncategorized / No significant indicators",
            "confidence": "low",
        }

    unique_indicators = list(dict.fromkeys(indicators))

    best_category = None
    best_overlap = 0

    for category, required_indicators in CATEGORY_RULES.items():
        if not required_indicators:
            continue

        overlap = len(set(unique_indicators) & required_indicators)

        if overlap > best_overlap:
            best_overlap = overlap
            best_category = category

    if best_category is None:
        return {
            "category": "Other suspicious activity",
            "confidence": "medium",
        }

    if best_overlap >= 2:
        confidence = "high"
    else:
        confidence = "medium"

    return {
        "category": best_category,
        "confidence": confidence,
    }