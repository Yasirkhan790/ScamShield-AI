from backend.tools.message_analyzer import analyze_message
from backend.tools.risk_engine import calculate_risk

def test_message_analyzer_detects_phishing_indicators():
    message = (
        "Urgent! Your account will be suspended. "
        "You will lose access immediately. "
        "Click this link and enter your password."
    )

    result = analyze_message(message)

    assert "urgency" in result["indicators"]
    assert "account_suspension" in result["indicators"]
    assert "threat" in result["indicators"]
    assert "credential_request" in result["indicators"]