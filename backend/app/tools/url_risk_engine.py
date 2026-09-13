from app.models.analysis import Indicator, RiskLevel


def calculate_url_risk(indicators: list[Indicator]) -> tuple[int, RiskLevel]:
    codes = {indicator.code for indicator in indicators}
    score = sum(indicator.weight for indicator in indicators)

    if {"domain_mismatch", "suspicious_keywords"}.issubset(codes):
        score += 20
    if {"ip_address_host", "suspicious_keywords"}.issubset(codes):
        score += 15
    if {"url_shortener", "suspicious_keywords"}.issubset(codes):
        score += 10
    if {"userinfo_obfuscation", "domain_mismatch"}.issubset(codes):
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
