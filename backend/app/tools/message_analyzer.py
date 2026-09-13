import re
from app.models.analysis import Indicator

PATTERNS = [
    {
        "code": "urgency",
        "name": "Urgency",
        "description": "The message pressures the recipient to act quickly.",
        "severity": "medium",
        "weight": 15,
        "patterns": [r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bfinal warning\b", r"within \d+ (minutes?|hours?)", r"\btoday\b"],
    },
    {
        "code": "account_threat",
        "name": "Account threat",
        "description": "The message threatens suspension, closure, blocking, or another negative account action.",
        "severity": "high",
        "weight": 15,
        "patterns": [r"account (?:has been |will be )?(?:suspended|closed|blocked|locked)", r"\blegal action\b", r"\baccount restriction\b"],
    },
    {
        "code": "credential_request",
        "name": "Credential request",
        "description": "The message asks for authentication or other sensitive credentials.",
        "severity": "high",
        "weight": 25,
        "patterns": [r"\bpassword\b", r"\botp\b", r"one[- ]time password", r"\bpin\b", r"credit[- ]?card", r"login credentials?", r"verify (?:your )?(?:identity|account)"],
    },
    {
        "code": "payment_request",
        "name": "Payment request",
        "description": "The message asks for money, a fee, a transfer, gift cards, or cryptocurrency.",
        "severity": "high",
        "weight": 25,
        "patterns": [r"processing fee", r"registration fee", r"\bpay\b", r"\bpayment\b", r"bank transfer", r"gift cards?", r"\bcrypto(?:currency)?\b", r"\bdeposit\b"],
    },
    {
        "code": "prize_claim",
        "name": "Unexpected prize claim",
        "description": "The message claims an unexpected prize, lottery, giveaway, or winnings.",
        "severity": "high",
        "weight": 20,
        "patterns": [r"\bwon\b", r"\bwinner\b", r"\blottery\b", r"\bgiveaway\b", r"\bprize\b", r"winnings?"],
    },
    {
        "code": "job_scam_signal",
        "name": "Employment scam signal",
        "description": "The message combines unrealistic work claims or guaranteed employment with suspicious conditions.",
        "severity": "high",
        "weight": 20,
        "patterns": [r"earn \$?\d+[\d,]* per day", r"guaranteed employment", r"work from home", r"no experience required"],
    },
    {
        "code": "investment_claim",
        "name": "Unrealistic investment claim",
        "description": "The message promises unusually high or guaranteed investment returns.",
        "severity": "high",
        "weight": 25,
        "patterns": [r"guaranteed \d+%", r"guaranteed returns?", r"risk[- ]free investment", r"\bno risk\b", r"\d+% return"],
    },
    {
        "code": "external_link",
        "name": "External link",
        "description": "The message contains a link that should be independently verified before opening.",
        "severity": "medium",
        "weight": 10,
        "patterns": [r"https?://[^\s]+", r"www\.[^\s]+"],
    },
    {
        "code": "impersonation_language",
        "name": "Impersonation language",
        "description": "The message presents itself as a bank, company, support team, or authority and asks the recipient to take action.",
        "severity": "medium",
        "weight": 15,
        "patterns": [r"\byour bank\b", r"bank account", r"support team", r"customer service", r"security department", r"tax authority", r"government department"],
    },
]


def analyze_message(message: str) -> list[Indicator]:
    text = message.lower()
    found: list[Indicator] = []

    for rule in PATTERNS:
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in rule["patterns"]):
            found.append(
                Indicator(
                    code=rule["code"],
                    name=rule["name"],
                    description=rule["description"],
                    severity=rule["severity"],
                    weight=rule["weight"],
                )
            )

    return found
