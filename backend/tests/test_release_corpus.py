import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.message_analysis_service import analyze_message_content


SCAM_CASES = [
    (
        "URGENT: Your bank account has been suspended. Verify your password and OTP immediately using https://example.com/login",
        "Phishing",
    ),
    (
        "Congratulations! You won a prize. Pay a processing fee today to claim your winnings.",
        "Prize/Lottery Scam",
    ),
    (
        "Earn $500 per day working from home. Pay a registration fee today to start.",
        "Job Scam",
    ),
    (
        "Guaranteed 300% return in 7 days. No risk. Deposit $500 today.",
        "Investment Scam",
    ),
    (
        "Security department: your account has been locked. Verify your identity and OTP immediately.",
        "Phishing",
    ),
    (
        "Lottery winner notice. Pay the processing fee immediately to receive your prize.",
        "Prize/Lottery Scam",
    ),
    (
        "Work from home with no experience required. Pay the registration fee today.",
        "Job Scam",
    ),
    (
        "Risk-free investment with guaranteed returns. Deposit funds today.",
        "Investment Scam",
    ),
    (
        "Customer service final warning: verify your account password immediately at https://example.com/verify.",
        "Phishing",
    ),
    (
        "Government department notice: legal action will follow. Pay the required payment immediately today.",
        "Impersonation",
    ),
]


LEGITIMATE_CASES = [
    "Our project meeting starts at 2 PM in Lab 3. Please bring your notes.",
    "The library will close at 8 PM on Friday for maintenance.",
    "Your assignment feedback is available in the university portal.",
    "Dinner is at 7 PM. I will meet you at the restaurant entrance.",
    "The lecture slides from this morning are in the shared class folder.",
]


@pytest.mark.parametrize(("message", "expected_category"), SCAM_CASES)
def test_release_scam_corpus(message, expected_category):
    result = analyze_message_content(message)
    assert result.risk_score >= 60
    assert result.risk_level in {"HIGH", "CRITICAL"}
    assert result.category == expected_category


@pytest.mark.parametrize("message", LEGITIMATE_CASES)
def test_release_legitimate_corpus(message):
    result = analyze_message_content(message)
    assert result.risk_score <= 29
    assert result.risk_level == "LOW"


def test_edge_empty_message_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'edge-empty.db'}")
    with TestClient(app) as client:
        response = client.post("/api/analyze/message", json={"message": ""})
    assert response.status_code == 422


def test_edge_whitespace_message_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'edge-space.db'}")
    with TestClient(app) as client:
        response = client.post("/api/analyze/message", json={"message": "   "})
    assert response.status_code == 422


def test_edge_oversized_message_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'edge-long.db'}")
    with TestClient(app) as client:
        response = client.post("/api/analyze/message", json={"message": "x" * 10001})
    assert response.status_code == 422


def test_edge_url_with_spaces_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'edge-url-space.db'}")
    with TestClient(app) as client:
        response = client.post("/api/analyze/url", json={"url": "https://example.com/a b"})
    assert response.status_code == 422


def test_edge_unsupported_url_scheme_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'edge-url-scheme.db'}")
    with TestClient(app) as client:
        response = client.post("/api/analyze/url", json={"url": "ftp://example.com/file"})
    assert response.status_code == 422
