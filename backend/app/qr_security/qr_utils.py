"""
PhishGuard AI — QR Security Utilities
Shared utility functions for QR scanning, image validation,
MIME type checking, and scan ID generation.
"""

import hashlib
import io
import re
import time
import uuid
from typing import Optional, Tuple

from app.utils.logger import logger


# ────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────

MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

ALLOWED_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/bmp",
    "image/webp",
}

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}

# Magic bytes for image format detection
MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"BM": "image/bmp",
    b"RIFF": "image/webp",
}


class QRSecurityUtils:
    """
    Utility functions for QR security operations.
    Provides image validation, sanitization, and helper methods.
    """

    @staticmethod
    def generate_scan_id() -> str:
        """
        Generate a unique scan identifier for tracking and audit.

        Returns:
            Unique scan ID string (e.g., "QR-a1b2c3d4").
        """
        return f"QR-{uuid.uuid4().hex[:8]}"

    @staticmethod
    def validate_image(
        data: bytes,
        filename: Optional[str] = None,
        content_type: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate an uploaded image for safety and format compliance.

        Checks:
        - File size limit
        - Magic bytes (actual file format)
        - Content type header (if provided)
        - File extension (if provided)
        - Malicious content patterns

        Args:
            data: Raw image bytes.
            filename: Optional original filename.
            content_type: Optional MIME type from upload headers.

        Returns:
            Tuple of (is_valid, error_message).
        """
        # Size check
        if not data:
            return False, "Image data is empty"

        if len(data) > MAX_IMAGE_SIZE_BYTES:
            return False, (
                f"Image exceeds maximum size of "
                f"{MAX_IMAGE_SIZE_BYTES // (1024 * 1024)} MB "
                f"(received {len(data) // (1024 * 1024)} MB)"
            )

        # Magic bytes verification (actual format detection)
        detected_type = QRSecurityUtils._detect_mime_from_magic(data)
        if detected_type is None:
            return False, (
                "Unsupported or unrecognized image format. "
                "Accepted formats: PNG, JPEG, BMP, WEBP"
            )

        # Content-Type header validation (if provided)
        if content_type:
            # Normalize content type
            ct = content_type.lower().split(";")[0].strip()
            if ct not in ALLOWED_MIME_TYPES:
                return False, (
                    f"Invalid content type: {ct}. "
                    f"Accepted: {', '.join(sorted(ALLOWED_MIME_TYPES))}"
                )

        # Extension validation (if provided)
        if filename:
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext and ext not in ALLOWED_EXTENSIONS:
                return False, (
                    f"Invalid file extension: {ext}. "
                    f"Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
                )

        # Malicious content detection
        is_clean, mal_reason = QRSecurityUtils._check_malicious_content(data)
        if not is_clean:
            return False, mal_reason

        return True, None

    @staticmethod
    def _detect_mime_from_magic(data: bytes) -> Optional[str]:
        """Detect MIME type from file magic bytes."""
        for magic, mime in MAGIC_SIGNATURES.items():
            if data[:len(magic)] == magic:
                return mime
        return None

    @staticmethod
    def _check_malicious_content(data: bytes) -> Tuple[bool, Optional[str]]:
        """
        Check image bytes for embedded malicious content.
        Detects polyglot files, embedded scripts, and injection attempts.
        """
        # Check first 8KB for embedded scripts/HTML
        header = data[:8192]

        # PHP/script injection in image
        dangerous_patterns = [
            b"<?php",
            b"<script",
            b"<%@ ",
            b"#!/",
            b"MZ",  # Windows PE executable header (after magic bytes area)
        ]

        for pattern in dangerous_patterns:
            if pattern in header[16:]:  # Skip magic bytes area
                logger.warning(
                    f"Malicious content detected in image: {pattern}"
                )
                return False, (
                    "Image contains embedded malicious content "
                    "(possible polyglot file)"
                )

        # Check for excessive non-image data (steganography indicator)
        if len(data) > 100_000:
            # Rough heuristic: too much ASCII text in a large image
            ascii_count = sum(
                1 for b in data[1000:5000] if 32 <= b <= 126
            )
            ascii_ratio = ascii_count / 4000
            if ascii_ratio > 0.8:
                logger.warning(
                    f"Suspicious image: high ASCII ratio ({ascii_ratio:.1%})"
                )
                # Don't block, just warn — could be a valid format

        return True, None

    @staticmethod
    def compute_payload_hash(payload: str) -> str:
        """
        Compute SHA-256 hash of a QR payload for caching/deduplication.

        Args:
            payload: Decoded QR payload text.

        Returns:
            Hex digest of the SHA-256 hash.
        """
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def truncate_url(url: str, max_length: int = 80) -> str:
        """Safely truncate a URL for logging purposes."""
        if len(url) <= max_length:
            return url
        return url[:max_length - 3] + "..."

    @staticmethod
    def sanitize_payload_for_response(payload: str, max_length: int = 2048) -> str:
        """
        Sanitize a QR payload before including it in API responses.
        Removes control characters and truncates if needed.
        """
        # Remove control characters (except newline, tab)
        sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", payload)
        # Truncate
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "... [truncated]"
        return sanitized

    @staticmethod
    def format_risk_level(risk_score: int) -> str:
        """Convert numeric risk score to human-readable risk level."""
        if risk_score <= 20:
            return "LOW"
        if risk_score <= 45:
            return "MODERATE"
        if risk_score <= 65:
            return "HIGH"
        if risk_score <= 85:
            return "VERY HIGH"
        return "CRITICAL"
