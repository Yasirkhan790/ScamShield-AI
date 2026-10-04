from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_reports_release_candidate_features():
    response = client.get("/api/health")

    assert response.status_code == 200

    body = response.json()

    # ScamShield V2 API
    assert body["version"] == "2.0.0"

    # Existing V1 capabilities
    assert "url-analysis" in body["features"]
    assert "structured-ai-analysis" in body["features"]
    assert "sqlite-history" in body["features"]
    assert "screenshot-analysis" in body["features"]
    assert "multimodal-text-extraction" in body["features"]
    assert "demo-ready-sample-cases" in body["features"]
    assert "configurable-cors" in body["features"]
    assert "release-smoke-check" in body["features"]

    # New V2 trained ML capability
    assert "trained-local-ml-classifier" in body["features"]

    # AI provider health
    assert body["ai_provider"] in {
        "disabled",
        "gemini",
        "openai",
    }

    assert isinstance(
        body["ai_ready"],
        bool,
    )

    assert isinstance(
        body["screenshot_ready"],
        bool,
    )

    # ML health
    assert body["ml_status"] in {
        "ready",
        "fallback",
        "disabled",
    }

    assert isinstance(
        body["ml_ready"],
        bool,
    )

    if body["ml_ready"]:
        assert (
            body["ml_model_version"]
            == "scamshield-text-v2-release-1"
        )

        assert isinstance(
            body["ml_selected_threshold"],
            float,
        )

        assert (
            0.0
            <= body["ml_selected_threshold"]
            <= 1.0
        )


def test_url_endpoint_returns_structured_report():
    response = client.post(
        "/api/analyze/url",
        json={
            "url":
                "https://paypal.security-check.example.com/login"
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["risk_level"] == "HIGH"

    assert body["category"] == "Phishing"

    assert (
        body["host"]
        == "paypal.security-check.example.com"
    )

    assert isinstance(
        body["indicators"],
        list,
    )


def test_url_endpoint_rejects_unsupported_scheme():
    response = client.post(
        "/api/analyze/url",
        json={
            "url":
                "ftp://example.com/file"
        },
    )

    assert response.status_code == 422