from app.services.message_analysis_service import analyze_message_content


def test_prize_demo_case_is_high_or_critical():
    result = analyze_message_content(
        "Congratulations! You've won $5,000. Pay a $20 processing fee to claim your prize."
    )
    assert result.category == "Prize/Lottery Scam"
    assert result.risk_score >= 60
    assert result.risk_level in {"HIGH", "CRITICAL"}


def test_fake_bank_demo_case_is_high_or_critical():
    result = analyze_message_content(
        "URGENT: Your bank account has been suspended. Verify your password and OTP immediately using https://example.com/login"
    )
    assert result.category == "Phishing"
    assert result.risk_score >= 60
    assert result.risk_level in {"HIGH", "CRITICAL"}


def test_job_demo_case_is_high_or_critical():
    result = analyze_message_content(
        "Earn $500 per day working from home. Pay a $30 registration fee to start."
    )
    assert result.category == "Job Scam"
    assert result.risk_score >= 60


def test_investment_demo_case_is_high_or_critical():
    result = analyze_message_content(
        "Guaranteed 300% return in 7 days. No risk. Deposit $500 today."
    )
    assert result.category == "Investment Scam"
    assert result.risk_score >= 60
    assert result.risk_level in {"HIGH", "CRITICAL"}


def test_legitimate_demo_case_stays_low():
    result = analyze_message_content(
        "Hi, our study group meets in the library at 3 PM tomorrow. Bring your notes if you have them."
    )
    assert result.risk_level == "LOW"
    assert result.risk_score <= 29
