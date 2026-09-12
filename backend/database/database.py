import sqlite3
import json
import logging
from typing import List, Optional

try:
    from backend.config import settings
    from backend.schemas import AnalysisResultResponse, HistorySummaryResponse, IndicatorModel
except ImportError:
    from config import settings
    from schemas import AnalysisResultResponse, HistorySummaryResponse, IndicatorModel

logger = logging.getLogger(__name__)

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initialize the SQLite database schema."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_type TEXT CHECK(input_type IN ('message', 'url', 'screenshot')),
                input_content TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                scam_category TEXT,
                indicators TEXT,
                explanation TEXT,
                recommendations TEXT,
                created_at TEXT
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_analyses_created_at 
            ON analyses(created_at DESC)
        """)
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")

def save_analysis(result: AnalysisResultResponse, raw_content: str) -> Optional[int]:
    """
    Save analysis result to SQLite database.
    DB write errors are logged and swallowed per PRD Section 10/22.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        truncated_content = (raw_content or "")[:1000]
        indicators_json = json.dumps([ind.model_dump() for ind in result.indicators])
        recommendations_json = json.dumps(result.recommendations)
        
        cursor.execute("""
            INSERT INTO analyses (
                input_type, input_content, risk_score, risk_level,
                scam_category, indicators, explanation, recommendations, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.input_type,
            truncated_content,
            result.risk_score,
            result.risk_level,
            result.scam_category,
            indicators_json,
            result.explanation,
            recommendations_json,
            result.created_at
        ))
        
        assigned_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return assigned_id
    except Exception as e:
        logger.error(f"Database save error (non-blocking): {e}")
        return None

def get_history(limit: int = 50) -> List[HistorySummaryResponse]:
    """Retrieve recent analyses summary records sorted newest-first."""
    results = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, input_type, risk_score, risk_level, scam_category, created_at
            FROM analyses
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        for row in rows:
            results.append(HistorySummaryResponse(
                id=row["id"],
                input_type=row["input_type"],
                risk_score=row["risk_score"],
                risk_level=row["risk_level"],
                scam_category=row["scam_category"],
                created_at=row["created_at"]
            ))
    except Exception as e:
        logger.error(f"Error fetching history: {e}")
    return results

def get_analysis_by_id(analysis_id: int) -> Optional[AnalysisResultResponse]:
    """Retrieve full analysis result by ID."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM analyses WHERE id = ?
        """, (analysis_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
            
        indicators_data = json.loads(row["indicators"]) if row["indicators"] else []
        indicators = [IndicatorModel(**ind) for ind in indicators_data]
        recommendations = json.loads(row["recommendations"]) if row["recommendations"] else []
        
        return AnalysisResultResponse(
            id=row["id"],
            input_type=row["input_type"],
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            scam_category=row["scam_category"],
            category_confidence="medium",
            indicators=indicators,
            detected_urls=[],
            extracted_text=row["input_content"] if row["input_type"] == "screenshot" else None,
            explanation=row["explanation"],
            recommendations=recommendations,
            created_at=row["created_at"]
        )
    except Exception as e:
        logger.error(f"Error fetching analysis {analysis_id}: {e}")
        return None
