from app.services.url_analysis_service import analyze_url_content


def test_normal_https_url_is_low_risk():
    result = analyze_url_content("https://example.com/about")
    assert result.risk_level == "LOW"
    assert result.risk_score < 30
    assert result.uses_https is True


def test_ip_login_url_is_high_risk():
    result = analyze_url_content("http://192.0.2.10/login/verify-account")
    codes = {item.code for item in result.indicators}
    assert result.risk_score >= 60
    assert result.risk_level in {"HIGH", "CRITICAL"}
    assert "ip_address_host" in codes
    assert "suspicious_keywords" in codes


def test_brand_mismatch_url_is_high_risk():
    result = analyze_url_content("https://paypal.security-check.example.com/login")
    codes = {item.code for item in result.indicators}
    assert result.risk_score >= 60
    assert result.risk_level in {"HIGH", "CRITICAL"}
    assert "domain_mismatch" in codes


def test_shortener_is_detected():
    result = analyze_url_content("https://bit.ly/account-verify")
    codes = {item.code for item in result.indicators}
    assert "url_shortener" in codes
