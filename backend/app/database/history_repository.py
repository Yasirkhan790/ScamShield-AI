import json
import os
import re
import sqlite3
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel

DEFAULT_DATABASE_URL = "sqlite:///./scamshield.db"


def _database_path() -> Path:
    database_url = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL).strip()
    if not database_url.startswith("sqlite:///"):
        raise RuntimeError("ScamShield MVP supports SQLite DATABASE_URL values only")

    raw_path = database_url[len("sqlite:///"):]
    if not raw_path or raw_path == ":memory:":
        raise RuntimeError("DATABASE_URL must point to a file-backed SQLite database")

    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


def _connect() -> sqlite3.Connection:
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def _create_schema(connection: sqlite3.Connection, table_name: str = "analyses") -> None:
    connection.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_type TEXT NOT NULL CHECK (input_type IN ('message', 'url', 'screenshot')),
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


def _migrate_input_type_constraint(connection: sqlite3.Connection) -> None:
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='analyses'"
    ).fetchone()
    if not row or not row["sql"] or "'screenshot'" in row["sql"]:
        return

    connection.execute("DROP TABLE IF EXISTS analyses_phase5")
    _create_schema(connection, "analyses_phase5")
    connection.execute(
        """
        INSERT INTO analyses_phase5 (
            id, input_type, input_content, scam_category, risk_score, risk_level,
            red_flags, recommendations, result_json, created_at
        )
        SELECT id, input_type, input_content, scam_category, risk_score, risk_level,
               red_flags, recommendations, result_json, created_at
        FROM analyses
        """
    )
    connection.execute("DROP TABLE analyses")
    connection.execute("ALTER TABLE analyses_phase5 RENAME TO analyses")


def initialize_database() -> None:
    with _connect() as connection:
        _create_schema(connection)
        _migrate_input_type_constraint(connection)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at DESC)"
        )


def _sanitize_message_preview(value: str) -> str:
    preview = " ".join(value.split())
    preview = re.sub(
        r"(?i)\b(otp|pin|password|passcode)\b\s*[:=\-]?\s*\S+",
        lambda match: f"{match.group(1)} [redacted]",
        preview,
    )
    preview = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[redacted email]", preview)
    preview = re.sub(r"(?<!\d)(?:\d[ -]?){12,19}(?!\d)", "[redacted number]", preview)
    return preview[:220]


def _sanitize_url_preview(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        netloc = f"{hostname}{port}"
        sanitized = urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
        return sanitized[:220]
    except ValueError:
        return value.split("?", 1)[0].split("#", 1)[0][:220]


def sanitize_input(input_type: str, value: str) -> str:
    if input_type == "url":
        return _sanitize_url_preview(value)
    return _sanitize_message_preview(value)


def _sanitize_result_for_storage(input_type: str, result: dict[str, Any]) -> dict[str, Any]:
    stored = deepcopy(result)
    if input_type == "url" and stored.get("normalized_url"):
        stored["normalized_url"] = _sanitize_url_preview(str(stored["normalized_url"]))
    if input_type == "screenshot" and stored.get("extracted_text"):
        stored["extracted_text"] = _sanitize_message_preview(str(stored["extracted_text"]))
    return stored


def save_analysis(input_type: str, raw_input: str, result: BaseModel | dict[str, Any]) -> int:
    if input_type not in {"message", "url", "screenshot"}:
        raise ValueError("Unsupported history input type")

    initialize_database()
    result_data = result.model_dump(mode="json") if isinstance(result, BaseModel) else dict(result)
    stored_result = _sanitize_result_for_storage(input_type, result_data)
    preview = sanitize_input(input_type, raw_input)
    created_at = datetime.now(timezone.utc).isoformat()

    with _connect() as connection:
        cursor = connection.execute(
            """
            INSERT INTO analyses (
                input_type, input_content, scam_category, risk_score, risk_level,
                red_flags, recommendations, result_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                input_type,
                preview,
                stored_result.get("category", "Other / Suspicious"),
                int(stored_result.get("risk_score", 0)),
                stored_result.get("risk_level", "LOW"),
                json.dumps(stored_result.get("indicators", []), ensure_ascii=False),
                json.dumps(stored_result.get("recommended_actions", []), ensure_ascii=False),
                json.dumps(stored_result, ensure_ascii=False),
                created_at,
            ),
        )
        record_id = int(cursor.lastrowid)
        stored_result["analysis_id"] = record_id
        connection.execute(
            "UPDATE analyses SET result_json = ? WHERE id = ?",
            (json.dumps(stored_result, ensure_ascii=False), record_id),
        )
    return record_id


def list_analyses(limit: int = 20) -> list[dict[str, Any]]:
    initialize_database()
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT id, input_type, input_content, scam_category, risk_score, risk_level, created_at
            FROM analyses
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            "id": row["id"],
            "input_type": row["input_type"],
            "input_content": row["input_content"],
            "scam_category": row["scam_category"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def get_analysis(record_id: int) -> dict[str, Any] | None:
    initialize_database()
    with _connect() as connection:
        row = connection.execute(
            """
            SELECT id, input_type, input_content, scam_category, risk_score, risk_level,
                   red_flags, recommendations, result_json, created_at
            FROM analyses
            WHERE id = ?
            """,
            (record_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "id": row["id"],
        "input_type": row["input_type"],
        "input_content": row["input_content"],
        "scam_category": row["scam_category"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "red_flags": json.loads(row["red_flags"]),
        "recommendations": json.loads(row["recommendations"]),
        "result": json.loads(row["result_json"]),
        "created_at": row["created_at"],
    }
