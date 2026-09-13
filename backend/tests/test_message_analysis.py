from app.services.message_analysis_service import analyze_message_content


def test_fake_bank_message_is_high_risk():
    result = analyze_message_content(
        "URGENT: Your bank account has been suspended. Verify your password and OTP immediately using https://example.com/login"
    )
    assert result.risk_score >= 80
    assert result.risk_level == "CRITICAL"
    assert result.category in {"Phishing", "Impersonation"}
    assert any(item.code == "credential_request" for item in result.indicators)


def test_benign_message_is_low_risk():
    result = analyze_message_content("Hi, the class starts at 10 AM tomorrow. See you there.")
    assert result.risk_level == "LOW"
    assert result.risk_score < 30
