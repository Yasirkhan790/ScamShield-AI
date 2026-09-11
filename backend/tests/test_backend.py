import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.database import init_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    init_db()

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "ai_service" in data
    assert "ocr_available" in data

def test_analyze_message_success():
    payload = {"text": "URGENT! Your bank account will be suspended today unless you verify credentials."}
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["input_type"] == "message"
    assert "risk_score" in data
    assert "risk_level" in data
    assert "disclaimer" in data

def test_analyze_message_empty_error():
    response = client.post("/api/analyze/message", json={"text": "   "})
    assert response.status_code == 422
    assert "Message text must not be empty" in response.json()["detail"]

def test_analyze_message_oversized_error():
    long_text = "a" * 8001
    response = client.post("/api/analyze/message", json={"text": long_text})
    assert response.status_code == 422

def test_analyze_url_success():
    payload = {"url": "http://192.168.1.1/login"}
    response = client.post("/api/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["input_type"] == "url"
    assert "risk_score" in data

def test_analyze_url_empty_error():
    response = client.post("/api/analyze/url", json={"url": "  "})
    assert response.status_code == 422
    assert "URL string must not be empty" in response.json()["detail"]

def test_analyze_screenshot_unsupported_file_type():
    files = {"file": ("test.txt", b"plain text", "text/plain")}
    response = client.post("/api/analyze/screenshot", files=files)
    assert response.status_code == 422
    assert "Unsupported file type" in response.json()["detail"]

def test_analyze_screenshot_oversized_file():
    huge_bytes = b"0" * (8 * 1024 * 1024 + 1)
    files = {"file": ("test.png", huge_bytes, "image/png")}
    response = client.post("/api/analyze/screenshot", files=files)
    assert response.status_code == 422
    assert "File too large" in response.json()["detail"]

def test_history_list_and_detail():
    client.post("/api/analyze/message", json={"text": "Sample test message for history"})
    
    response = client.get("/api/history")
    assert response.status_code == 200
    history_list = response.json()
    assert isinstance(history_list, list)
    assert len(history_list) > 0
    
    first_id = history_list[0]["id"]
    detail_response = client.get(f"/api/history/{first_id}")
    assert detail_response.status_code == 200
    assert detail_response.json()["id"] == first_id

def test_history_not_found():
    response = client.get("/api/history/999999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Analysis not found."
