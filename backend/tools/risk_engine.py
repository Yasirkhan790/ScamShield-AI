from typing import List, Dict, Any, Tuple, Union

try:
    from backend.schemas import IndicatorModel
except ImportError:
    from schemas import IndicatorModel

INDICATOR_WEIGHTS = {
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
    "romance_pressure": 10
}

CATEGORY_RULES = {
    "Credential theft": {"credential_request", "otp_request"},
    "Phishing": {"credential_request", "account_suspension", "suspicious_url"},
    "Prize/lottery scam": {"prize_claim", "payment_request"},
    "Account impersonation": {"impersonation", "account_suspension"},
    "Job scam": {"job_offer_scam", "payment_request"},
    "Investment scam": {"investment_scam", "payment_request"},
    "Payment scam": {"payment_request", "urgency"},
    "Romance/social engineering scam": {"romance_pressure", "emotional_pressure"},
    "Financial scam": {"payment_request", "personal_info_request"}
}

def calculate_risk(indicators: Union[List[Dict[str, Any]], List[str], List[IndicatorModel]]) -> Tuple[int, str, List[IndicatorModel]]:
    seen_names = set()
    total_score = 0
    final_indicators = []

    for ind in indicators:
        if isinstance(ind, dict):
            name = ind.get("name")
            desc = ind.get("description", "Suspicious signal detected")
        elif isinstance(ind, IndicatorModel):
            name = ind.name
            desc = ind.description
        else:
            name = str(ind)
            desc = f"Suspicious signal '{name}' detected"

        if not name or name in seen_names:
            continue
        seen_names.add(name)
        
        weight = INDICATOR_WEIGHTS.get(name, 0)
        total_score += weight
        final_indicators.append(IndicatorModel(
            name=name,
            description=desc,
            weight=weight
        ))

    score = min(total_score, 100)

    if score < 30:
        level = "LOW"
    elif score < 60:
        level = "MEDIUM"
    elif score < 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return score, level, final_indicators


def classify_category(indicators: Union[List[IndicatorModel], List[Dict[str, Any]], List[str]]) -> Tuple[str, str]:
    if not indicators:
        return "Uncategorized / No significant indicators", "low"

    fired_set = set()
    for ind in indicators:
        if isinstance(ind, IndicatorModel):
            fired_set.add(ind.name)
        elif isinstance(ind, dict):
            if ind.get("name"):
                fired_set.add(ind["name"])
        else:
            fired_set.add(str(ind))

    best_category = "Other suspicious activity"
    max_overlap = 0

    for cat_name, required_set in CATEGORY_RULES.items():
        overlap = len(fired_set.intersection(required_set))
        if overlap > max_overlap:
            max_overlap = overlap
            best_category = cat_name

    num_categories = len(fired_set)
    if num_categories <= 1:
        confidence = "low" if max_overlap < 1 else "medium"
    elif num_categories <= 3:
        confidence = "medium"
    else:
        confidence = "high"

    if max_overlap >= 2:
        confidence = "high"

    return best_category, confidence
