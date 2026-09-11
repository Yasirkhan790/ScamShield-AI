import re
from typing import List, Dict, Any, Tuple

INDICATOR_DESCRIPTIONS = {
    "credential_request": "Request for password or login credentials",
    "otp_request": "Request for one-time verification code or OTP",
    "payment_request": "Urgent request to transfer money or make a payment",
    "suspicious_url": "Contains suspicious or unverified web links",
    "urgency": "Urgent or high-pressure language demanding immediate action",
    "threat": "Threats of account termination, legal action, or penalties",
    "account_suspension": "Warning of account lock, suspension, or compromise",
    "prize_claim": "Claims of lottery wins, prize payouts, or free rewards",
    "job_offer_scam": "Suspicious job offer or high-pay easy task promotion",
    "investment_scam": "Promotions promising guaranteed high investment returns",
    "impersonation": "Claims to represent official institutions (banks, services, executives)",
    "personal_info_request": "Request for sensitive personal details (SSN, national ID, address)",
    "emotional_pressure": "Appeals to panic, fear, or emotional distress",
    "limited_time_pressure": "Artificial time limits (e.g. 'within 24 hours', 'act now')",
    "romance_pressure": "Romantic or social engineering manipulation language"
}

INDICATOR_PATTERNS = {
    "urgency": [r"\burgent\b", r"\bimmediat(ely|e)\b", r"\bact now\b", r"\bright now\b", r"\bhurry\b", r"\bquick(ly)?\b"],
    "threat": [r"\bpolice\b", r"\blegal action\b", r"\barrest\b", r"\bsued?\b", r"\bpenalty\b", r"\bprosecut(e|ion)\b", r"\bdeactivat(e|ed|ion)\b"],
    "account_suspension": [r"\baccount.*(suspend|block|restrict|lock|clos)(ed|ing)?\b", r"\bsuspend(ed)?\b", r"\bsecurity breach\b", r"\bunauthorized access\b"],
    "credential_request": [r"\bverifi(ed|y).*(account|password|identity|credential)\b", r"\bpassword\b", r"\blogin\b", r"\bcredentials?\b", r"\benter.*pass\b"],
    "otp_request": [r"\botp\b", r"\bone[- ]time (password|pin|code)\b", r"\bverification code\b", r"\b2fa code\b", r"\bsecurity code\b"],
    "payment_request": [r"\bsend money\b", r"\bwire transfer\b", r"\bpay.*fee\b", r"\bgift card\b", r"\bcrypto(currency)?\b", r"\bbitcoin\b", r"\bpayment required\b"],
    "prize_claim": [r"\bclaim.*prize\b", r"\byou (have )?won\b", r"\blottery\b", r"\bwinner\b", r"\bjackpot\b", r"\bfree reward\b"],
    "impersonation": [r"\b(bank|paypal|amazon|apple|microsoft|netflix|usps|fedex|ups|government|irs|sec)\b", r"\bofficial support\b", r"\bcustomer service\b"],
    "personal_info_request": [r"\bssn\b", r"\bsocial security\b", r"\bcredit card number\b", r"\bcvv\b", r"\bbank account number\b"],
    "emotional_pressure": [r"\bhelp me\b", r"\bemergency\b", r"\bin trouble\b", r"\bdon't tell anyone\b", r"\bkeep this secret\b"],
    "limited_time_pressure": [r"\bwithin 24 hours?\b", r"\bexpires (today|soon)\b", r"\blimited time\b", r"\btime running out\b"],
    "job_offer_scam": [r"\bearn \$?\d+ (a|per) (day|hour)\b", r"\bwork from home\b", r"\bno experience needed\b", r"\beasy job\b", r"\bdata entry job\b"],
    "investment_scam": [r"\bguaranteed return\b", r"\b100% risk[- ]free\b", r"\bdouble your money\b", r"\bcrypto investment\b", r"\bpassive income\b"],
    "romance_pressure": [r"\bmy love\b", r"\bdearest\b", r"\bneed money for flight\b", r"\bsend money for medical\b"]
}

URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)

def analyze_message(text: str) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    indicators = []
    text_lower = text.lower()
    fired_names = set()

    for name, patterns in INDICATOR_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower):
                fired_names.add(name)
                break

    detected_urls = URL_REGEX.findall(text)
    if detected_urls and "suspicious_url" not in fired_names:
        fired_names.add("suspicious_url")

    notes = []
    if "urgency" in fired_names and "credential_request" in fired_names:
        notes.append("High-risk pattern: Urgency combined with credential request is a classic phishing indicator.")
    if "prize_claim" in fired_names and "payment_request" in fired_names:
        notes.append("High-risk pattern: Prize notification requiring payment is a characteristic lottery scam.")
    if "impersonation" in fired_names and "account_suspension" in fired_names:
        notes.append("High-risk pattern: Brand impersonation with account suspension threats is a common credential harvesting tactic.")

    for name in fired_names:
        indicators.append({
            "name": name,
            "description": INDICATOR_DESCRIPTIONS.get(name, "Suspicious pattern detected"),
            "weight": 0
        })

    return indicators, detected_urls, notes