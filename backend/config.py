import os
from typing import List

class Settings:
    PROJECT_NAME: str = "ScamShield AI"
    VERSION: str = "1.0.0"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "scamshield.db")
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3:8b")
    MAX_TEXT_LENGTH: int = 8000
    MAX_IMAGE_SIZE_BYTES: int = 8 * 1024 * 1024  # 8MB limit per PRD
    ALLOWED_IMAGE_TYPES: List[str] = ["image/png", "image/jpeg", "image/jpg", "image/webp"]
    CORS_ORIGINS: List[str] = ["*"]

settings = Settings()
