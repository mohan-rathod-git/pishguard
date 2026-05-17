"""
PhishGuard AI — API Request/Response Schemas
Pydantic models for type-safe request validation and response serialization.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
import re


class URLPredictRequest(BaseModel):
    """Request body for single URL prediction."""
    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="The URL to analyze for threats",
        examples=["https://suspicious-login-verify.xyz/account"],
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        # Basic structure check
        if " " in v and not v.startswith("http"):
            raise ValueError("URL appears to be malformed")
        return v


class BatchPredictRequest(BaseModel):
    """Request body for batch URL prediction."""
    urls: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of URLs to analyze (max 100)",
    )


class ThreatReason(BaseModel):
    """A single reason explaining why a URL is flagged."""
    reason: str


class PredictionResponse(BaseModel):
    """Response for a single URL prediction."""
    url: str
    prediction: str = Field(
        ..., description="Threat category: SAFE, PHISHING, SPAM, MALWARE, or SCAM"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Model confidence (0-1)"
    )
    risk_score: int = Field(
        ..., ge=0, le=100, description="Risk score (0-100)"
    )
    reasons: List[str] = Field(
        ..., description="Human-readable explanations for the verdict"
    )


class BatchPredictionResponse(BaseModel):
    """Response for batch URL prediction."""
    count: int
    results: List[PredictionResponse]


class HealthResponse(BaseModel):
    """Response for health check endpoint."""
    status: str
    app: str
    version: str
    model_loaded: bool
    uptime_seconds: float


class ModelInfoResponse(BaseModel):
    """Response for model info endpoint."""
    model_type: str
    model_version: str
    feature_count: int
    features: List[str]
    loaded: bool
    blacklist_size: int
    whitelist_size: int
    cache_entries: int


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
