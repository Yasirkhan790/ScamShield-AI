"""Fast local smoke check for the hackathon release candidate."""

import os
import sys
import tempfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

# Keep the smoke check deterministic and isolated from a developer database.
os.environ["AI_PROVIDER"] = "disabled"
_tmp = tempfile.TemporaryDirectory(prefix="scamshield-release-")
os.environ["DATABASE_URL"] = f"sqlite:///{Path(_tmp.name) / 'release-check.db'}"

from fastapi.testclient import TestClient
from app.main import app


MESSAGE_CASES = [
    ("Fake bank", "URGENT: Your bank account has been suspended. Verify your password and OTP immediately using https://example.com/login", 60),
    ("Prize", "Congratulations! You've won $5,000. Pay a $20 processing fee to claim your prize.", 60),
    ("Job", "Earn $500 per day working from home. Pay a $30 registration fee to start.", 60),
    ("Investment", "Guaranteed 300% return in 7 days. No risk. Deposit $500 today.", 60),
    ("Legitimate", "Our study group meets in the library at 3 PM. Bring your notes.", 0),
]


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    raise SystemExit(1)


def main() -> None:
    with TestClient(app) as client:
        health = client.get("/api/health")
        if health.status_code != 200 or health.json().get("status") != "ok":
            fail("health endpoint")
        print(f"PASS: API health, version {health.json().get('version')}")

        for label, message, minimum in MESSAGE_CASES:
            response = client.post("/api/analyze/message", json={"message": message})
            if response.status_code != 200:
                fail(f"{label} message endpoint returned {response.status_code}")
            body = response.json()
            if body["risk_score"] < minimum:
                fail(f"{label} score {body['risk_score']} was below {minimum}")
            print(f"PASS: {label}: {body['risk_score']}/100 {body['risk_level']} {body['category']}")

        url_response = client.post(
            "/api/analyze/url",
            json={"url": "https://paypal.security-check.example.com/login"},
        )
        if url_response.status_code != 200 or url_response.json()["risk_score"] < 60:
            fail("URL scanner smoke case")
        print(f"PASS: URL: {url_response.json()['risk_score']}/100 {url_response.json()['risk_level']}")

        history = client.get("/api/history?limit=10")
        if history.status_code != 200 or len(history.json()) < 6:
            fail("history persistence")
        print(f"PASS: History persisted {len(history.json())} smoke-check records")

    print("RELEASE CHECK PASSED")


if __name__ == "__main__":
    try:
        main()
    finally:
        _tmp.cleanup()
