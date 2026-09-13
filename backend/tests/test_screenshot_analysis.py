import base64
import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.ai import service as ai_service
from app.main import app

PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


class FakeScreenshotProvider:
    name = "fake-vision"

    def extract_text_from_image(self, image_bytes: bytes, mime_type: str) -> str:
        assert image_bytes
        assert mime_type == "image/png"
        return "URGENT: Your bank account is suspended. Send your OTP 123456 immediately using https://example.com/login."

    def generate_json(self, user_prompt: str) -> str:
        return json.dumps({
            "summary": "The extracted message uses urgency, an account threat, and requests a credential.",
            "category": "Phishing",
            "secondary_categories": ["Impersonation"],
            "observations": [],
            "recommended_actions": ["Contact the bank using its official app or phone number."],
        })


class EmptyScreenshotProvider(FakeScreenshotProvider):
    def extract_text_from_image(self, image_bytes: bytes, mime_type: str) -> str:
        return ""


def test_screenshot_endpoint_extracts_text_and_analyzes(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'screenshot.db'}")
    monkeypatch.setattr(ai_service, "get_ai_provider", lambda: FakeScreenshotProvider())

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/screenshot",
            files={"file": ("bank.png", PNG_BYTES, "image/png")},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["text_extraction_status"] == "used"
        assert body["text_extraction_provider"] == "fake-vision"
        assert body["file_name"] == "bank.png"
        assert "bank account" in body["extracted_text"].lower()
        assert body["risk_score"] >= 60
        assert body["category"] == "Phishing"
        assert isinstance(body["analysis_id"], int)

        history = client.get("/api/history").json()
        assert history[0]["input_type"] == "screenshot"
        assert "123456" not in history[0]["input_content"]

        detail = client.get(f"/api/history/{body['analysis_id']}").json()
        assert "123456" not in detail["result"]["extracted_text"]


def test_screenshot_rejects_unsupported_file_type(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'invalid.db'}")
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/screenshot",
            files={"file": ("note.txt", b"hello", "text/plain")},
        )
        assert response.status_code == 415


def test_screenshot_rejects_oversized_file(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'large.db'}")
    monkeypatch.setenv("SCREENSHOT_MAX_BYTES", "1024")
    payload = b"\x89PNG\r\n\x1a\n" + (b"x" * 2000)

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/screenshot",
            files={"file": ("large.png", payload, "image/png")},
        )
        assert response.status_code == 413


def test_screenshot_requires_multimodal_provider(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'disabled.db'}")
    monkeypatch.setattr(ai_service, "get_ai_provider", lambda: None)

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/screenshot",
            files={"file": ("bank.png", PNG_BYTES, "image/png")},
        )
        assert response.status_code == 503
        assert "multimodal AI provider" in response.json()["detail"]


def test_screenshot_handles_no_readable_text(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'empty.db'}")
    monkeypatch.setattr(ai_service, "get_ai_provider", lambda: EmptyScreenshotProvider())

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/screenshot",
            files={"file": ("blank.png", PNG_BYTES, "image/png")},
        )
        assert response.status_code == 422
        assert "could not extract readable text" in response.json()["detail"]
