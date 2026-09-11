SCAM_PATTERNS = {
    "Urgent language": [
        "urgent",
        "immediately",
        "act now",
        "limited time",
        "within 24 hours",
    ],
    "Account threat": [
        "account suspended",
        "account blocked",
        "account will be closed",
        "account locked",
    ],
    "Verification request": [
        "verify your account",
        "verify now",
        "verification code",
        "confirm your identity",
    ],
    "Credential request": [
        "password",
        "otp",
        "one time password",
        "login details",
        "security code",
    ],
    "Payment request": [
        "send money",
        "make payment",
        "pay now",
        "transfer money",
        "bank transfer",
    ],
    "Prize or reward": [
        "you have won",
        "claim your prize",
        "you won",
        "congratulations",
        "free reward",
    ],
    "Suspicious link": [
        "click this link",
        "click here",
        "open this link",
    ],
}


def analyze_message(message: str) -> dict:
    """
    Analyze a message for common scam indicators.
    """

    message_lower = message.lower()

    indicators = []
    matched_keywords = []

    for category, keywords in SCAM_PATTERNS.items():
        for keyword in keywords:
            if keyword in message_lower:
                if category not in indicators:
                    indicators.append(category)

                matched_keywords.append(keyword)

    return {
        "indicators": indicators,
        "matched_keywords": matched_keywords,
    }