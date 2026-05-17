"""
PhishGuard AI — QR Payload Extractor
Extracts and classifies payloads from decoded QR codes.
Identifies URLs, UPI payment strings, vCards, WiFi configs, plain text,
and other structured data types embedded in QR codes.
"""

import re
from enum import Enum
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, unquote

from app.utils.logger import logger


# ────────────────────────────────────────────────
# Payload Type Classification
# ────────────────────────────────────────────────

class PayloadType(str, Enum):
    """Classification of QR code payload types."""
    URL = "URL"
    UPI = "UPI_PAYMENT"
    VCARD = "VCARD"
    WIFI = "WIFI"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SMS = "SMS"
    GEO = "GEO_LOCATION"
    CRYPTO = "CRYPTO"
    TEXT = "PLAIN_TEXT"
    UNKNOWN = "UNKNOWN"


# ────────────────────────────────────────────────
# Regex Patterns
# ────────────────────────────────────────────────

URL_PATTERN = re.compile(
    r"^https?://[^\s]+$", re.IGNORECASE
)

# Matches bare domains like example.com/path
BARE_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}(?:/[^\s]*)?$"
)

UPI_PATTERN = re.compile(
    r"^upi://pay\?", re.IGNORECASE
)

VCARD_PATTERN = re.compile(
    r"^BEGIN:VCARD", re.IGNORECASE
)

WIFI_PATTERN = re.compile(
    r"^WIFI:", re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r"^mailto:", re.IGNORECASE
)

PHONE_PATTERN = re.compile(
    r"^tel:", re.IGNORECASE
)

SMS_PATTERN = re.compile(
    r"^sms(to)?:", re.IGNORECASE
)

GEO_PATTERN = re.compile(
    r"^geo:", re.IGNORECASE
)

CRYPTO_PATTERNS = [
    re.compile(r"^bitcoin:", re.IGNORECASE),
    re.compile(r"^ethereum:", re.IGNORECASE),
    re.compile(r"^litecoin:", re.IGNORECASE),
]


class QRPayloadExtractor:
    """
    Extracts structured data from decoded QR payloads.
    Classifies payload type and extracts embedded URLs,
    payment parameters, and hidden data.
    """

    @staticmethod
    def classify_payload(text: str) -> PayloadType:
        """
        Determine the type of QR payload.

        Args:
            text: Decoded QR payload string.

        Returns:
            PayloadType enum indicating the payload class.
        """
        if not text:
            return PayloadType.UNKNOWN

        text_stripped = text.strip()

        if URL_PATTERN.match(text_stripped):
            return PayloadType.URL
        if BARE_DOMAIN_PATTERN.match(text_stripped):
            return PayloadType.URL
        if UPI_PATTERN.match(text_stripped):
            return PayloadType.UPI
        if VCARD_PATTERN.match(text_stripped):
            return PayloadType.VCARD
        if WIFI_PATTERN.match(text_stripped):
            return PayloadType.WIFI
        if EMAIL_PATTERN.match(text_stripped):
            return PayloadType.EMAIL
        if PHONE_PATTERN.match(text_stripped):
            return PayloadType.PHONE
        if SMS_PATTERN.match(text_stripped):
            return PayloadType.SMS
        if GEO_PATTERN.match(text_stripped):
            return PayloadType.GEO
        for pattern in CRYPTO_PATTERNS:
            if pattern.match(text_stripped):
                return PayloadType.CRYPTO

        return PayloadType.TEXT

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """
        Extract all URLs from a QR payload, including embedded
        and hidden URLs within other payload types.

        Args:
            text: Decoded QR payload string.

        Returns:
            List of extracted URL strings.
        """
        urls: List[str] = []

        if not text:
            return urls

        # Direct HTTP/HTTPS URLs
        http_urls = re.findall(
            r"https?://[^\s<>\"']+", text, re.IGNORECASE
        )
        urls.extend(http_urls)

        # Bare domains (e.g., evil-site.xyz/steal)
        if not http_urls:
            if BARE_DOMAIN_PATTERN.match(text.strip()):
                urls.append(f"http://{text.strip()}")

        # URLs inside UPI parameters (url= field)
        if UPI_PATTERN.match(text):
            parsed = urlparse(text)
            params = parse_qs(parsed.query)
            for key in ("url", "refUrl", "cu", "mc"):
                if key in params:
                    for val in params[key]:
                        if re.match(r"https?://", val, re.IGNORECASE):
                            urls.append(val)

        # Decode percent-encoded URLs
        decoded_text = unquote(text)
        if decoded_text != text:
            hidden = re.findall(
                r"https?://[^\s<>\"']+", decoded_text, re.IGNORECASE
            )
            for u in hidden:
                if u not in urls:
                    urls.append(u)

        # Deduplicate while preserving order
        seen = set()
        unique: List[str] = []
        for u in urls:
            u_clean = u.rstrip("/.,;:)")
            if u_clean not in seen:
                seen.add(u_clean)
                unique.append(u_clean)

        return unique

    @staticmethod
    def extract_upi_params(text: str) -> Optional[Dict[str, Any]]:
        """
        Parse UPI payment QR payload and extract all parameters.

        Args:
            text: UPI payment string (e.g., upi://pay?pa=...&pn=...&am=...)

        Returns:
            Dictionary of UPI parameters, or None if not a UPI payload.
        """
        if not UPI_PATTERN.match(text):
            return None

        try:
            parsed = urlparse(text)
            params = parse_qs(parsed.query, keep_blank_values=True)
            # Flatten single-value lists
            flat_params = {
                k: v[0] if len(v) == 1 else v
                for k, v in params.items()
            }

            return {
                "payee_address": flat_params.get("pa", ""),
                "payee_name": flat_params.get("pn", ""),
                "amount": flat_params.get("am", ""),
                "currency": flat_params.get("cu", "INR"),
                "transaction_note": flat_params.get("tn", ""),
                "transaction_ref": flat_params.get("tr", ""),
                "merchant_code": flat_params.get("mc", ""),
                "url": flat_params.get("url", ""),
                "mode": flat_params.get("mode", ""),
                "raw_params": flat_params,
            }
        except Exception as e:
            logger.error(f"UPI parameter extraction failed: {e}")
            return None

    @staticmethod
    def extract_wifi_params(text: str) -> Optional[Dict[str, str]]:
        """
        Parse WiFi QR payload.

        Args:
            text: WiFi config string (e.g., WIFI:S:NetworkName;T:WPA;P:password;;)

        Returns:
            Dictionary of WiFi parameters, or None if not a WiFi payload.
        """
        if not WIFI_PATTERN.match(text):
            return None

        params: Dict[str, str] = {}
        content = text[5:]  # Strip "WIFI:"
        fields = content.rstrip(";").split(";")

        for field in fields:
            if ":" in field:
                key, value = field.split(":", 1)
                key_map = {
                    "S": "ssid",
                    "T": "security_type",
                    "P": "password",
                    "H": "hidden",
                }
                param_name = key_map.get(key.upper(), key.lower())
                params[param_name] = value

        return params

    @staticmethod
    def detect_hidden_characters(text: str) -> Dict[str, Any]:
        """
        Detect hidden/invisible Unicode characters that may be used
        for payload obfuscation or IDN homograph attacks.

        Args:
            text: Decoded QR payload string.

        Returns:
            Dictionary with hidden character analysis.
        """
        hidden_chars: List[Dict[str, Any]] = []

        # Zero-width characters
        zero_width = {
            "\u200b": "ZERO WIDTH SPACE",
            "\u200c": "ZERO WIDTH NON-JOINER",
            "\u200d": "ZERO WIDTH JOINER",
            "\u200e": "LEFT-TO-RIGHT MARK",
            "\u200f": "RIGHT-TO-LEFT MARK",
            "\ufeff": "BYTE ORDER MARK",
            "\u2060": "WORD JOINER",
            "\u2061": "FUNCTION APPLICATION",
            "\u2062": "INVISIBLE TIMES",
            "\u2063": "INVISIBLE SEPARATOR",
        }

        for char, name in zero_width.items():
            count = text.count(char)
            if count > 0:
                hidden_chars.append({
                    "character": name,
                    "unicode": f"U+{ord(char):04X}",
                    "count": count,
                })

        # Check for homoglyph characters (Cyrillic/Greek lookalikes)
        homoglyph_ranges = [
            (0x0400, 0x04FF, "Cyrillic"),   # а, е, о, с, etc.
            (0x0370, 0x03FF, "Greek"),       # α, ε, ο, etc.
        ]
        for start, end, script in homoglyph_ranges:
            count = sum(1 for c in text if start <= ord(c) <= end)
            if count > 0:
                hidden_chars.append({
                    "character": f"{script} lookalike characters",
                    "unicode": f"U+{start:04X}-U+{end:04X}",
                    "count": count,
                })

        return {
            "has_hidden_chars": len(hidden_chars) > 0,
            "hidden_char_count": sum(h["count"] for h in hidden_chars),
            "details": hidden_chars,
        }

    def extract_full_payload(self, decoded_text: str) -> Dict[str, Any]:
        """
        Perform complete payload extraction and analysis.

        Args:
            decoded_text: Raw decoded QR code text.

        Returns:
            Comprehensive payload analysis dictionary.
        """
        payload_type = self.classify_payload(decoded_text)
        urls = self.extract_urls(decoded_text)
        hidden = self.detect_hidden_characters(decoded_text)

        result: Dict[str, Any] = {
            "raw_payload": decoded_text,
            "payload_type": payload_type.value,
            "payload_length": len(decoded_text),
            "extracted_urls": urls,
            "url_count": len(urls),
            "hidden_characters": hidden,
        }

        # Type-specific extraction
        if payload_type == PayloadType.UPI:
            result["upi_params"] = self.extract_upi_params(decoded_text)
        elif payload_type == PayloadType.WIFI:
            result["wifi_params"] = self.extract_wifi_params(decoded_text)

        logger.debug(
            f"Payload extracted: type={payload_type.value}, "
            f"urls={len(urls)}, hidden={hidden['has_hidden_chars']}"
        )

        return result


# Module-level singleton
payload_extractor = QRPayloadExtractor()
