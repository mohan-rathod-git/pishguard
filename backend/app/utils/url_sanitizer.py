"""
PhishGuard AI — URL Sanitizer & Validator
Input validation and security sanitization for incoming URLs.
"""

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

import bleach


# Max acceptable URL length
MAX_URL_LENGTH = 2048

# Disallowed patterns (injection / XSS attempts)
INJECTION_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"data:text/html", re.IGNORECASE),
    re.compile(r"vbscript:", re.IGNORECASE),
    re.compile(r"on\w+=", re.IGNORECASE),        # onload=, onclick=, etc.
    re.compile(r"\{\{.*\}\}"),                     # template injection
    re.compile(r"\$\{.*\}"),                       # expression injection
    re.compile(r";\s*(rm|del|drop|exec|system)", re.IGNORECASE),  # command injection
]


def sanitize_url(url: str) -> str:
    """Strip dangerous characters and sanitize input URL."""
    # Strip whitespace
    url = url.strip()
    # Remove any HTML tags
    url = bleach.clean(url, tags=[], strip=True)
    # Remove null bytes
    url = url.replace("\x00", "")
    # Remove control characters
    url = re.sub(r"[\x01-\x1f\x7f]", "", url)
    return url


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate a URL for safety and well-formedness.

    Returns:
        (is_valid, error_message) — error_message is None when valid.
    """
    if not url:
        return False, "URL is empty"

    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_URL_LENGTH} characters"

    # Check for injection patterns
    for pattern in INJECTION_PATTERNS:
        if pattern.search(url):
            return False, "URL contains potentially malicious content"

    # Basic URL structure validation
    normalised = url
    if not re.match(r"^https?://", url, re.IGNORECASE):
        normalised = "http://" + url

    try:
        parsed = urlparse(normalised)
        if not parsed.hostname:
            return False, "URL has no valid hostname"
        if len(parsed.hostname) > 253:
            return False, "Hostname exceeds maximum length"
    except Exception:
        return False, "URL is malformed and cannot be parsed"

    return True, None
