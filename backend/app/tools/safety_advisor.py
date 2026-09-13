from app.models.analysis import Indicator


def generate_safety_advice(indicators: list[Indicator]) -> list[str]:
    codes = {item.code for item in indicators}
    actions: list[str] = []

    if "external_link" in codes:
        actions.append("Do not open the link until you verify the sender and destination independently.")
    if "credential_request" in codes:
        actions.append("Do not share passwords, OTPs, PINs, card details, or login credentials.")
    if "payment_request" in codes:
        actions.append("Do not send money, gift cards, cryptocurrency, or fees before independent verification.")
    if "account_threat" in codes or "impersonation_language" in codes:
        actions.append("Contact the organization through its official website, app, phone number, or another trusted channel.")
    if "prize_claim" in codes:
        actions.append("Treat unexpected prizes that require payment or personal information as suspicious.")
    if "job_scam_signal" in codes:
        actions.append("Verify the employer and job posting independently, especially before paying any registration or onboarding fee.")
    if "investment_claim" in codes:
        actions.append("Do not invest based on guaranteed or unusually high return claims. Verify the provider through trusted regulatory sources.")

    if not actions:
        actions.append("No strong scam indicators were detected. Still verify unusual requests through an independent trusted channel.")

    return actions
