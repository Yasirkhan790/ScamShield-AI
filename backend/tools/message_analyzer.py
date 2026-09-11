import re


SCAM_PATTERNS = {
    "urgency": [
        "urgent",
        "immediately",
        "act now",
        "right away",
    ],
    "threat": [
        "you will be arrested",
        "legal action",
        "police will",
        "your account will be closed",
        "you will lose access",
    ],
    "account_suspension": [
        "account suspended",
        "account will be suspended",
        "account blocked",
        "account locked",
        "account disabled",
        "account is suspended",
    ],
    "credential_request": [
        "password",
        "login details",
        "login credentials",
        "username and password",
    ],
    "otp_request": [
        "otp",
        "one time password",
        "verification code",
        "security code",
    ],
    "payment_request": [
        "send money",
        "make payment",
        "pay now",
        "transfer money",
        "bank transfer",
    ],
    "prize_claim": [
        "you have won",
        "you won",
        "claim your prize",
        "claim your reward",
        "lottery winner",
    ],
    "impersonation": [
        "this is your bank",
        "this is the police",
        "this is from the government",
        "i am calling from your bank",
    ],
    "suspicious_link_language": [
        "click this link",
        "click here",
        "open this link",
    ],
    "personal_info_request": [
        "date of birth",
        "social security number",
        "national id",
        "id card number",
        "personal information",
    ],
    "emotional_pressure": [
        "please help me",
        "i need your help",
        "don't tell anyone",
        "keep this secret",
        "i am desperate",
    ],
    "limited_time_pressure": [
        "limited time",
        "expires today",
        "only today",
        "within 24 hours",
        "offer expires",
    ],
    "job_offer_scam": [
        "job offer",
        "work from home",
        "easy money",
        "earn money quickly",
        "guaranteed income",
    ],
    "investment_scam": [
        "guaranteed return",
        "guaranteed profit",
        "double your money",
        "investment opportunity",
        "risk free investment",
    ],
    "romance_pressure": [
        "i love you",
        "send me money",
        "help me financially",
        "i need money urgently",
        "send money for my emergency",
    ],
}


URL_PATTERN = r"https?://[^\s<>'\"]+"


def analyze_message(message: str) -> dict:
    """
    Analyze untrusted message content for scam indicators.

    The submitted message is treated only as untrusted data.
    It is never interpreted as instructions or executed.
    """

    if not message or not message.strip():
        raise ValueError("Message text must not be empty.")

    if len(message) > 8000:
        raise ValueError("Message must not exceed 8000 characters.")

    message_lower = " ".join(message.lower().split())

    indicators = []
    matched_keywords = []

    for indicator_name, keywords in SCAM_PATTERNS.items():
        for keyword in keywords:
            if re.search(r"\b" + re.escape(keyword) + r"\b", message_lower):
                if indicator_name not in indicators:
                    indicators.append(indicator_name)

                matched_keywords.append(keyword)

    urls = list(dict.fromkeys(re.findall(URL_PATTERN, message)))

    if "suspicious_link_language" in indicators and urls:
        if "suspicious_url" not in indicators:
            indicators.append("suspicious_url")

    contextual_notes = []

    if "urgency" in indicators and "credential_request" in indicators:
        contextual_notes.append(
            "Urgency combined with a credential request is a classic phishing signal."
        )

    if "prize_claim" in indicators and "payment_request" in indicators:
        contextual_notes.append(
            "A prize claim combined with a payment request is a strong lottery scam signal."
        )

    if "impersonation" in indicators and "account_suspension" in indicators:
        contextual_notes.append(
            "Impersonation combined with an account suspension threat is a common phishing tactic."
        )

    return {
        "indicators": indicators,
        "matched_keywords": matched_keywords,
        "urls": urls,
        "contextual_notes": contextual_notes,
    }