"""
PhishGuard AI — QR Security API Schemas
Pydantic models for QR scan request validation and response serialization.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# ────────────────────────────────────────────────
# Request Schemas
# ────────────────────────────────────────────────

class QRScanBase64Request(BaseModel):
    """Request body for QR scan via base64 image."""
    image_base64: str = Field(
        ...,
        min_length=10,
        max_length=15_000_000,  # ~10MB in base64
        description="Base64-encoded QR code image (PNG, JPEG, BMP, WEBP)",
        examples=["iVBORw0KGgoAAAANSUhEUgAA..."],
    )
    follow_redirects: bool = Field(
        default=True,
        description="Whether to follow and analyze URL redirect chains",
    )
    use_ml_model: bool = Field(
        default=True,
        description="Whether to use the existing URL AI model for analysis",
    )


# ────────────────────────────────────────────────
# Response Schemas
# ────────────────────────────────────────────────

class QRScanResponse(BaseModel):
    """Response for a single QR code scan."""
    scan_id: str = Field(
        ..., description="Unique scan tracking ID"
    )
    status: str = Field(
        ..., description="Decision: BLOCKED, ALLOWED, NO_QR_FOUND, or ERROR"
    )
    prediction: str = Field(
        ...,
        description=(
            "Threat classification: SAFE, PHISHING, MALWARE, SCAM, "
            "FAKE_PAYMENT, SUSPICIOUS, CRITICAL, or UNKNOWN"
        ),
    )
    risk_score: int = Field(
        ..., ge=0, le=100, description="Risk score (0-100)"
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Classification confidence (0-1)"
    )
    severity: str = Field(
        ..., description="Severity level: NONE, LOW, MEDIUM, HIGH, or CRITICAL"
    )
    decoded_payload: Optional[str] = Field(
        None, description="Decoded QR code payload text"
    )
    payload_type: Optional[str] = Field(
        None, description="Classified payload type: URL, TEXT, EMAIL, UPI_PAYMENT, etc."
    )
    final_url: Optional[str] = Field(
        None, description="Final destination URL after redirect expansion"
    )
    redirect_chain: List[str] = Field(
        default=[], description="Ordered list of URLs in the redirect chain"
    )
    reasons: List[str] = Field(
        ..., description="Human-readable explanations for the verdict"
    )
    fake_payment_detected: bool = Field(
        default=False, description="Whether a fake payment QR was detected"
    )
    is_shortened_url: bool = Field(
        default=False, description="Whether the QR payload contains a shortened URL"
    )
    qr_count: int = Field(
        default=0, description="Number of QR codes detected in the image"
    )
    processing_time_ms: float = Field(
        default=0.0, description="Total processing time in milliseconds"
    )
    all_results: List[Dict[str, Any]] = Field(
        default=[], description="Results for all QR codes if multiple were found"
    )


class QRBatchScanResponse(BaseModel):
    """Response for batch QR code scan."""
    total_scanned: int = Field(
        ..., description="Total number of images scanned"
    )
    total_blocked: int = Field(
        ..., description="Number of QR codes blocked"
    )
    total_allowed: int = Field(
        ..., description="Number of QR codes allowed"
    )
    processing_time_ms: float = Field(
        ..., description="Total processing time in milliseconds"
    )
    results: List[QRScanResponse] = Field(
        ..., description="Individual scan results"
    )


class QRHealthResponse(BaseModel):
    """Response for QR security health check."""
    status: str = Field(
        ..., description="QR engine status: healthy or degraded"
    )
    qr_engine_active: bool = Field(
        ..., description="Whether the QR security engine is operational"
    )
    ml_model_loaded: bool = Field(
        ..., description="Whether the URL AI model is loaded"
    )
    total_scans: int = Field(
        ..., description="Total QR scans processed"
    )
    total_blocked: int = Field(
        ..., description="Total QR codes blocked"
    )
    block_rate: float = Field(
        ..., description="Percentage of scans that were blocked"
    )
    blocking_threshold: int = Field(
        ..., description="Current risk score blocking threshold"
    )
    sandbox_available: bool = Field(
        ..., description="Whether sandbox scanning is available"
    )
    uptime_seconds: float = Field(
        ..., description="QR engine uptime in seconds"
    )
