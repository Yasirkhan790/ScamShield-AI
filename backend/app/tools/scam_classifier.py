from app.models.analysis import Indicator


def classify_scam(indicators: list[Indicator]) -> tuple[str, list[str]]:
    codes = {item.code for item in indicators}
    ranked: list[str] = []

    if "prize_claim" in codes:
        ranked.append("Prize/Lottery Scam")
    if "investment_claim" in codes:
        ranked.append("Investment Scam")
    if "job_scam_signal" in codes:
        ranked.append("Job Scam")
    if "credential_request" in codes or "external_link" in codes:
        ranked.append("Phishing")
    if "impersonation_language" in codes or "account_threat" in codes:
        ranked.append("Impersonation")
    if "payment_request" in codes:
        ranked.append("Payment Scam")

    if not ranked:
        return "Other / Suspicious" if indicators else "No Strong Scam Pattern Detected", []

    return ranked[0], ranked[1:3]
