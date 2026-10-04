from app.tools.message_analyzer import analyze_message
from app.tools.risk_engine import calculate_risk


def test_message_analyzer_detects_phishing_indicators():
    message = (
        "Urgent! Your account will be suspended. "
        "You will lose access immediately. "
        "Click this link and enter your password."
    )

    indicators = analyze_message(message)

    codes = {
        indicator.code
        for indicator in indicators
    }

    assert "urgency" in codes
    assert "account_threat" in codes
    assert "credential_request" in codes

    score, level = calculate_risk(indicators)

    assert score >= 60
    assert level in {
        "HIGH",
        "CRITICAL",
    }