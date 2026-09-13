import json

from app.ai import service as ai_service
from app.services.message_analysis_service import analyze_message_content
from app.services.url_analysis_service import analyze_url_content


class FakeProvider:
    name = "fake"

    def __init__(self, payload):
        self.payload = payload

    def generate_json(self, user_prompt: str) -> str:
        return self.payload


def test_ai_structured_output_enriches_message_without_changing_score(monkeypatch):
    payload = json.dumps({
        "summary": "The message uses account pressure and credential requests, which are common phishing signals.",
        "category": "Phishing",
        "secondary_categories": ["Impersonation"],
        "observations": [
            {
                "name": "Authority pressure",
                "description": "The sender presents the request as a bank security action.",
                "severity": "high"
            }
        ],
        "recommended_actions": ["Open the bank app directly instead of using the supplied link."]
    })
    monkeypatch.setattr(ai_service, "get_ai_provider", lambda: FakeProvider(payload))

    result = analyze_message_content(
        "URGENT: Your bank account has been suspended. Verify your password and OTP immediately using https://example.com/login"
    )

    assert result.ai_status == "used"
    assert result.ai_provider == "fake"
    assert result.category == "Phishing"
    assert result.risk_score == 90
    assert len(result.ai_observations) == 1
    assert any("bank app" in action.lower() for action in result.recommended_actions)


def test_malformed_ai_json_falls_back_to_deterministic_analysis(monkeypatch):
    monkeypatch.setattr(ai_service, "get_ai_provider", lambda: FakeProvider("not-json"))

    result = analyze_message_content(
        "Earn $500 per day working from home. Pay a $30 registration fee to start."
    )

    assert result.ai_status == "fallback"
    assert result.category == "Job Scam"
    assert result.risk_score == 60
    assert result.ai_observations == []


def test_invalid_ai_category_falls_back(monkeypatch):
    payload = json.dumps({
        "summary": "Suspicious.",
        "category": "Definitely Evil",
        "secondary_categories": [],
        "observations": [],
        "recommended_actions": []
    })
    monkeypatch.setattr(ai_service, "get_ai_provider", lambda: FakeProvider(payload))

    result = analyze_message_content("Congratulations! You won a prize. Pay a processing fee.")

    assert result.ai_status == "fallback"
    assert result.category == "Prize/Lottery Scam"
    assert result.risk_score >= 60


def test_url_ai_does_not_change_deterministic_score(monkeypatch):
    payload = json.dumps({
        "summary": "The hostname structure imitates a payment brand and includes a login path.",
        "category": "Phishing",
        "secondary_categories": ["Impersonation"],
        "observations": [
            {
                "name": "Brand impersonation",
                "description": "A payment brand appears in a misleading subdomain rather than the registrable domain.",
                "severity": "high"
            }
        ],
        "recommended_actions": ["Navigate to the payment provider using a saved bookmark or typed address."]
    })
    monkeypatch.setattr(ai_service, "get_ai_provider", lambda: FakeProvider(payload))

    result = analyze_url_content("https://paypal.security-check.example.com/login")

    assert result.ai_status == "used"
    assert result.category == "Phishing"
    assert result.risk_score == 60
    assert result.host == "paypal.security-check.example.com"
