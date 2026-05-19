"""
PhishGuard AI — Configuration Module
Centralized settings loaded from environment variables / .env file.
"""

from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    """Application-wide settings backed by environment variables."""

    # ── App ──
    APP_NAME: str = "PhishGuard AI"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = True

    # ── API ──
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 4

    # ── Rate Limiting ──
    RATE_LIMIT: str = "100/minute"

    # ── Model Paths ──
    MODEL_PATH: str = "app/models/phishguard_model.joblib"
    SCALER_PATH: str = "app/models/scaler.joblib"
    MODEL_VERSION: str = "1.0.0"

    # ── Dataset ──
    DATASET_PATH: str = "../datasets/new_data_urls.csv"
    MAX_DATASET_ROWS: int = 500000

    # ── Security ──
    CORS_ORIGINS: str = "*"  # Override via env var: CORS_ORIGINS=https://yoursite.netlify.app
    MAX_BATCH_SIZE: int = 100
    MAX_URL_LENGTH: int = 2048

    # ── Logging ──
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/phishguard.log"

    # ── QR Security ──
    QR_MAX_IMAGE_SIZE_MB: int = 10
    QR_RISK_THRESHOLD: int = 60
    QR_CRITICAL_THRESHOLD: int = 85
    QR_SCAN_TIMEOUT: float = 30.0
    QR_MAX_BATCH_SIZE: int = 10
    QR_FOLLOW_REDIRECTS: bool = True
    QR_MAX_REDIRECTS: int = 10

    @property
    def cors_origins_list(self) -> List[str]:
        origins = [o.strip() for o in self.CORS_ORIGINS.split(",")]
        return origins

    @property
    def cors_allow_all(self) -> bool:
        """Return True if wildcard CORS is configured."""
        return "*" in self.CORS_ORIGINS

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Singleton instance
settings = Settings()
