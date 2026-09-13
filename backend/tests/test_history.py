from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


def test_analysis_is_saved_and_retrievable(monkeypatch, tmp_path: Path):
    db_path = tmp_path / "history.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/message",
            json={"message": "URGENT: send your OTP 123456 immediately."},
        )
        assert response.status_code == 200
        body = response.json()
        assert isinstance(body["analysis_id"], int)

        history = client.get("/api/history")
        assert history.status_code == 200
        items = history.json()
        assert len(items) == 1
        assert items[0]["id"] == body["analysis_id"]
        assert "123456" not in items[0]["input_content"]

        detail = client.get(f"/api/history/{body['analysis_id']}")
        assert detail.status_code == 200
        saved = detail.json()
        assert saved["result"]["risk_score"] == body["risk_score"]
        assert saved["result"]["analysis_id"] == body["analysis_id"]


def test_url_history_removes_query_and_fragment(monkeypatch, tmp_path: Path):
    db_path = tmp_path / "url-history.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/url",
            json={"url": "https://example.com/login?token=super-secret#account"},
        )
        assert response.status_code == 200

        history = client.get("/api/history?limit=5").json()
        assert len(history) == 1
        assert history[0]["input_content"] == "https://example.com/login"

        detail = client.get(f"/api/history/{history[0]['id']}").json()
        assert detail["result"]["normalized_url"] == "https://example.com/login"


def test_history_missing_record_returns_404(monkeypatch, tmp_path: Path):
    db_path = tmp_path / "missing.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    with TestClient(app) as client:
        response = client.get("/api/history/999")
        assert response.status_code == 404


def test_phase4_database_migrates_to_screenshot_input_type(monkeypatch, tmp_path: Path):
    import sqlite3
    from app.database.history_repository import initialize_database

    db_path = tmp_path / "phase4-migration.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_type TEXT NOT NULL CHECK (input_type IN ('message', 'url')),
                input_content TEXT NOT NULL,
                scam_category TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                red_flags TEXT NOT NULL,
                recommendations TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO analyses (
                input_type, input_content, scam_category, risk_score, risk_level,
                red_flags, recommendations, result_json, created_at
            ) VALUES ('message', 'hello', 'Other / Suspicious', 0, 'LOW', '[]', '[]', '{}', '2026-01-01T00:00:00+00:00')
            """
        )

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    initialize_database()

    with sqlite3.connect(db_path) as connection:
        schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='analyses'"
        ).fetchone()[0]
        count = connection.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]

    assert "'screenshot'" in schema
    assert count == 1
