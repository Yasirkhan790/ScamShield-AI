from app.models.analysis import Indicator


def generate_url_safety_advice(indicators: list[Indicator]) -> list[str]:
    codes = {item.code for item in indicators}
    actions: list[str] = []

    if codes & {"domain_mismatch", "userinfo_obfuscation", "punycode_domain"}:
        actions.append("Do not sign in through this link. Open the organization’s official website or app independently.")
    if "suspicious_keywords" in codes:
        actions.append("Do not enter passwords, OTPs, PINs, payment details, or other sensitive information until the destination is verified.")
    if "url_shortener" in codes:
        actions.append("Treat the shortened destination as unverified because the final domain is hidden from view.")
    if "ip_address_host" in codes:
        actions.append("Verify why the link uses a raw IP address instead of the organization’s normal domain.")
    if "no_https" in codes:
        actions.append("Avoid sending sensitive information over a non-HTTPS connection.")

    if not actions:
        actions.append("No strong URL heuristic was detected. Still confirm unexpected links through an independent trusted channel.")

    actions.append("ScamShield inspected the URL text only and did not visit or verify the destination website.")
    return actions
