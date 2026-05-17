"""
PhishGuard AI — QR Feature Engineering Engine
Extracts advanced cybersecurity features from QR payloads for ML classification.
Covers URL features, payment scam indicators, behavioral signals,
and QR-specific obfuscation patterns.
"""

import math
import re
import hashlib
from collections import Counter
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs, unquote

import tldextract

from app.utils.logger import logger
from app.qr_security.extractor import PayloadType


# ────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "adf.ly", "tiny.cc", "lnkd.in", "db.tt", "qr.ae",
    "bitly.com", "cutt.ly", "rb.gy", "shorturl.at", "t.ly",
    "v.gd", "x.co", "soo.gd", "s.id", "clck.ru", "rebrand.ly",
    "shorturl.asia", "tny.im", "bl.ink", "lc.chat", "ur.cx",
]

SUSPICIOUS_TLDS = [
    "xyz", "top", "club", "work", "buzz", "tk", "ml", "ga", "cf",
    "gq", "pw", "cc", "icu", "cam", "bid", "loan", "win", "click",
    "link", "info", "online", "site", "website", "space", "fun",
    "life", "live", "stream", "download", "racing", "review",
    "party", "trade", "date", "accountant", "faith", "cricket",
]

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "account",
    "update", "secure", "security", "banking", "confirm", "password",
    "suspend", "alert", "urgent", "expire", "expired", "locked",
    "unlock", "restore", "recover", "validate", "authenticate",
    "reactivate", "unusual-activity", "limited-access",
]

SCAM_KEYWORDS = [
    "free", "prize", "winner", "congratulations", "claim", "reward",
    "gift", "offer", "bonus", "promo", "limited-time", "act-now",
    "exclusive", "jackpot", "lottery", "giveaway", "cash",
]

MALWARE_KEYWORDS = [
    "download", "install", "update", "patch", "setup",
    ".apk", ".exe", ".msi", ".dmg", ".deb", ".rpm",
    ".bat", ".cmd", ".ps1", ".sh", ".vbs",
]

PAYMENT_APP_NAMES = [
    "phonepe", "paytm", "googlepay", "gpay", "bhim", "amazonpay",
    "mobikwik", "freecharge", "airtel", "jio",
]

KNOWN_BANK_NAMES = [
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "bob",
    "canara", "union", "idbi", "rbl", "yes", "indusind",
    "federal", "bandhan", "idfc",
]

SUSPICIOUS_UPI_PATTERNS = [
    r"\.merchant@",          # Generic merchant VPAs
    r"\d{10}@",              # Phone-number-based VPAs (common in scams)
    r"(fake|scam|fraud)",    # Obvious scam indicators
]

AUTO_DOWNLOAD_EXTENSIONS = [
    ".apk", ".exe", ".msi", ".dmg", ".deb", ".rpm", ".bat",
    ".cmd", ".ps1", ".sh", ".vbs", ".jar", ".py", ".scr",
    ".com", ".pif", ".application", ".gadget", ".wsf",
]


class QRFeatureEngine:
    """
    Production-grade feature engineering for QR code threat detection.
    Extracts 40+ features across multiple threat dimensions.
    """

    # ────────────────────────────────────
    # Core Text Features
    # ────────────────────────────────────

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy — measures randomness/obfuscation."""
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        return round(
            -sum((c / length) * math.log2(c / length) for c in counter.values()),
            4,
        )

    @staticmethod
    def extract_basic_features(payload: str) -> Dict[str, float]:
        """
        Extract basic payload-level features.

        Returns:
            Dictionary of numeric feature values.
        """
        features: Dict[str, float] = {}

        features["payload_length"] = float(len(payload))
        features["payload_entropy"] = QRFeatureEngine._shannon_entropy(payload)

        # Character composition
        features["num_digits"] = float(sum(c.isdigit() for c in payload))
        features["num_special_chars"] = float(
            sum(not c.isalnum() and c not in ":/.-_@" for c in payload)
        )

        length = max(len(payload), 1)
        features["digit_ratio"] = round(features["num_digits"] / length, 4)
        features["special_char_ratio"] = round(
            features["num_special_chars"] / length, 4
        )

        # Hidden character detection
        zero_width_chars = [
            "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
            "\ufeff", "\u2060", "\u2061", "\u2062", "\u2063",
        ]
        zw_count = sum(payload.count(c) for c in zero_width_chars)
        features["hidden_char_count"] = float(zw_count)
        features["has_hidden_chars"] = 1.0 if zw_count > 0 else 0.0

        # Unicode trick detection (homoglyphs)
        cyrillic_count = sum(1 for c in payload if 0x0400 <= ord(c) <= 0x04FF)
        greek_count = sum(1 for c in payload if 0x0370 <= ord(c) <= 0x03FF)
        features["homoglyph_count"] = float(cyrillic_count + greek_count)
        features["has_homoglyphs"] = 1.0 if (cyrillic_count + greek_count) > 0 else 0.0

        return features

    # ────────────────────────────────────
    # URL-Specific Features
    # ────────────────────────────────────

    @staticmethod
    def extract_url_features(url: str) -> Dict[str, float]:
        """
        Extract URL-specific cybersecurity features.

        Args:
            url: The URL string to analyze.

        Returns:
            Dictionary of URL-level features.
        """
        features: Dict[str, float] = {}

        if not url:
            return {f"url_{k}": 0.0 for k in [
                "length", "num_dots", "num_hyphens", "num_slashes",
                "has_at_sign", "has_double_slash_redirect", "is_ip_based",
                "is_shortened", "is_suspicious_tld", "has_https",
                "has_non_standard_port", "has_punycode",
                "url_entropy", "domain_entropy", "path_entropy",
                "path_depth", "num_query_params", "has_query",
                "num_subdomains", "subdomain_length",
                "suspicious_keyword_count", "has_suspicious_keywords",
                "phishing_keyword_count", "scam_keyword_count",
                "malware_keyword_count",
                "has_apk_download", "has_auto_download",
            ]}

        # Normalize
        normalized = url.strip()
        if not re.match(r"^https?://", normalized, re.IGNORECASE):
            normalized = "http://" + normalized

        parsed = urlparse(normalized)
        extracted = tldextract.extract(normalized)

        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        domain = extracted.registered_domain or ""
        subdomain = extracted.subdomain or ""
        tld = extracted.suffix or ""
        url_lower = url.lower()

        # Length features
        features["url_length"] = float(len(url))
        features["url_num_dots"] = float(url.count("."))
        features["url_num_hyphens"] = float(url.count("-"))
        features["url_num_slashes"] = float(url.count("/"))

        # Boolean indicators
        features["url_has_at_sign"] = 1.0 if "@" in url else 0.0
        features["url_has_double_slash_redirect"] = 1.0 if "//" in path else 0.0

        # IP-based URL
        ipv4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        features["url_is_ip_based"] = 1.0 if ipv4.match(hostname) else 0.0

        # Shortened URL
        features["url_is_shortened"] = 1.0 if any(
            s in url_lower for s in URL_SHORTENERS
        ) else 0.0

        # Suspicious TLD
        features["url_is_suspicious_tld"] = 1.0 if tld.lower() in SUSPICIOUS_TLDS else 0.0

        # HTTPS
        features["url_has_https"] = 1.0 if parsed.scheme == "https" else 0.0

        # Non-standard port
        features["url_has_non_standard_port"] = (
            1.0 if parsed.port and parsed.port not in (80, 443) else 0.0
        )

        # Punycode / IDN
        features["url_has_punycode"] = 1.0 if "xn--" in hostname else 0.0

        # Entropy
        features["url_entropy"] = QRFeatureEngine._shannon_entropy(url)
        features["url_domain_entropy"] = QRFeatureEngine._shannon_entropy(domain)
        features["url_path_entropy"] = QRFeatureEngine._shannon_entropy(path)

        # Structure
        features["url_path_depth"] = float(path.count("/") - 1) if path else 0.0
        features["url_num_query_params"] = float(len(parse_qs(query)))
        features["url_has_query"] = 1.0 if query else 0.0
        features["url_num_subdomains"] = float(
            len(subdomain.split(".")) if subdomain else 0
        )
        features["url_subdomain_length"] = float(len(subdomain))

        # Keyword analysis
        phishing_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
        scam_hits = sum(1 for kw in SCAM_KEYWORDS if kw in url_lower)
        malware_hits = sum(1 for kw in MALWARE_KEYWORDS if kw in url_lower)

        features["url_phishing_keyword_count"] = float(phishing_hits)
        features["url_scam_keyword_count"] = float(scam_hits)
        features["url_malware_keyword_count"] = float(malware_hits)
        features["url_suspicious_keyword_count"] = float(
            phishing_hits + scam_hits + malware_hits
        )
        features["url_has_suspicious_keywords"] = (
            1.0 if (phishing_hits + scam_hits + malware_hits) > 0 else 0.0
        )

        # Download detection
        features["url_has_apk_download"] = 1.0 if ".apk" in url_lower else 0.0
        features["url_has_auto_download"] = 1.0 if any(
            ext in url_lower for ext in AUTO_DOWNLOAD_EXTENSIONS
        ) else 0.0

        # Fake login pattern: domain mimics known brands
        brand_mimic_patterns = [
            r"(?:paypal|apple|microsoft|google|amazon|netflix|facebook)"
            r"[^a-z]",
        ]
        features["url_has_brand_mimic"] = 1.0 if any(
            re.search(pat, url_lower) for pat in brand_mimic_patterns
        ) and domain.lower() not in [
            "paypal.com", "apple.com", "microsoft.com", "google.com",
            "amazon.com", "netflix.com", "facebook.com",
        ] else 0.0

        return features

    # ────────────────────────────────────
    # Payment / UPI Scam Features
    # ────────────────────────────────────

    @staticmethod
    def extract_payment_features(
        payload: str,
        upi_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, float]:
        """
        Extract features specific to payment QR scam detection.

        Args:
            payload: Raw QR payload.
            upi_params: Parsed UPI parameters (if applicable).

        Returns:
            Dictionary of payment-related threat features.
        """
        features: Dict[str, float] = {}
        payload_lower = payload.lower()

        features["is_upi_payment"] = 1.0 if upi_params else 0.0

        if not upi_params:
            # Check for payment-related content even if not UPI
            features["mentions_payment_app"] = 1.0 if any(
                app in payload_lower for app in PAYMENT_APP_NAMES
            ) else 0.0
            features["mentions_bank"] = 1.0 if any(
                bank in payload_lower for bank in KNOWN_BANK_NAMES
            ) else 0.0
            features["has_amount"] = 1.0 if re.search(
                r"(?:rs\.?|₹|inr)\s*\d+", payload_lower
            ) else 0.0
            features["payment_risk_score"] = 0.0
            features["suspicious_vpa"] = 0.0
            features["high_amount"] = 0.0
            features["vpa_entropy"] = 0.0
            features["has_collect_request"] = 0.0
            return features

        # UPI-specific features
        vpa = upi_params.get("payee_address", "")
        payee_name = upi_params.get("payee_name", "")
        amount_str = upi_params.get("amount", "")
        note = upi_params.get("transaction_note", "")

        # Suspicious VPA patterns
        suspicious_vpa = 0.0
        for pattern in SUSPICIOUS_UPI_PATTERNS:
            if re.search(pattern, vpa, re.IGNORECASE):
                suspicious_vpa = 1.0
                break

        features["suspicious_vpa"] = suspicious_vpa
        features["vpa_entropy"] = QRFeatureEngine._shannon_entropy(vpa)

        # High amount detection (amounts over ₹10,000 are higher risk)
        try:
            amount = float(amount_str) if amount_str else 0.0
            features["has_amount"] = 1.0 if amount > 0 else 0.0
            features["high_amount"] = 1.0 if amount > 10000 else 0.0
        except (ValueError, TypeError):
            features["has_amount"] = 0.0
            features["high_amount"] = 0.0

        # Payment app impersonation
        features["mentions_payment_app"] = 1.0 if any(
            app in payee_name.lower() or app in note.lower()
            for app in PAYMENT_APP_NAMES
        ) else 0.0

        # Bank impersonation
        features["mentions_bank"] = 1.0 if any(
            bank in payee_name.lower() or bank in vpa.lower()
            for bank in KNOWN_BANK_NAMES
        ) else 0.0

        # Collect request (dangerous — money goes FROM victim)
        features["has_collect_request"] = (
            1.0 if upi_params.get("mode", "").lower() == "02" else 0.0
        )

        # Combined payment risk
        payment_risk = (
            suspicious_vpa * 30 +
            features["high_amount"] * 20 +
            features["has_collect_request"] * 25 +
            features["mentions_bank"] * 15 +
            features["mentions_payment_app"] * 10
        )
        features["payment_risk_score"] = min(payment_risk, 100.0)

        return features

    # ────────────────────────────────────
    # Behavioral Features
    # ────────────────────────────────────

    @staticmethod
    def extract_behavior_features(
        payload: str,
        urls: List[str],
    ) -> Dict[str, float]:
        """
        Extract behavioral features — indicators of malicious intent
        such as auto-downloads, JavaScript execution, popup behavior.

        Args:
            payload: Raw QR payload.
            urls: List of extracted URLs.

        Returns:
            Dictionary of behavioral features.
        """
        features: Dict[str, float] = {}
        payload_lower = payload.lower()

        # APK / executable download
        features["has_apk_download"] = 1.0 if ".apk" in payload_lower else 0.0
        features["has_exe_download"] = 1.0 if any(
            ext in payload_lower for ext in [".exe", ".msi", ".bat", ".cmd"]
        ) else 0.0
        features["has_auto_download"] = 1.0 if any(
            ext in payload_lower for ext in AUTO_DOWNLOAD_EXTENSIONS
        ) else 0.0

        # JavaScript indicators
        js_patterns = [
            "javascript:", "<script", "eval(", "document.cookie",
            "window.location", "onclick=", "onerror=", "onload=",
        ]
        features["has_js_indicators"] = 1.0 if any(
            p in payload_lower for p in js_patterns
        ) else 0.0

        # Data URI (can embed malicious content)
        features["has_data_uri"] = 1.0 if "data:" in payload_lower else 0.0

        # Multiple URL redirects embedded in payload
        features["embedded_url_count"] = float(len(urls))
        features["has_multiple_urls"] = 1.0 if len(urls) > 1 else 0.0

        # Encoded/obfuscated content
        features["has_base64_content"] = 1.0 if re.search(
            r"[A-Za-z0-9+/]{40,}={0,2}", payload
        ) else 0.0

        features["has_hex_encoding"] = 1.0 if re.search(
            r"%[0-9a-fA-F]{2}", payload
        ) else 0.0

        return features

    # ────────────────────────────────────
    # Redirect-Aware Features
    # ────────────────────────────────────

    @staticmethod
    def extract_redirect_features(
        redirect_chain: Optional[List[str]] = None,
        final_url: Optional[str] = None,
    ) -> Dict[str, float]:
        """
        Extract features from redirect chain analysis.

        Args:
            redirect_chain: Ordered list of URLs in the redirect chain.
            final_url: The final destination URL after all redirects.

        Returns:
            Dictionary of redirect-related features.
        """
        features: Dict[str, float] = {}

        if not redirect_chain:
            features["redirect_count"] = 0.0
            features["has_redirects"] = 0.0
            features["redirect_domain_change"] = 0.0
            features["redirect_tld_change"] = 0.0
            features["redirect_scheme_downgrade"] = 0.0
            features["final_url_suspicious_tld"] = 0.0
            features["final_url_is_ip"] = 0.0
            return features

        features["redirect_count"] = float(len(redirect_chain) - 1)
        features["has_redirects"] = 1.0 if len(redirect_chain) > 1 else 0.0

        # Domain changes in redirect chain
        domains = []
        for url in redirect_chain:
            ext = tldextract.extract(url)
            domains.append(ext.registered_domain)
        unique_domains = set(d for d in domains if d)
        features["redirect_domain_change"] = float(len(unique_domains) - 1)

        # TLD changes
        tlds = [tldextract.extract(url).suffix for url in redirect_chain]
        unique_tlds = set(t for t in tlds if t)
        features["redirect_tld_change"] = float(len(unique_tlds) - 1)

        # HTTPS to HTTP downgrade
        schemes = [urlparse(url).scheme for url in redirect_chain]
        features["redirect_scheme_downgrade"] = 1.0 if (
            "https" in schemes[:-1] and schemes[-1] == "http"
        ) else 0.0

        # Final URL analysis
        if final_url:
            final_ext = tldextract.extract(final_url)
            features["final_url_suspicious_tld"] = (
                1.0 if final_ext.suffix in SUSPICIOUS_TLDS else 0.0
            )
            final_hostname = urlparse(final_url).hostname or ""
            features["final_url_is_ip"] = 1.0 if re.match(
                r"^(\d{1,3}\.){3}\d{1,3}$", final_hostname
            ) else 0.0
        else:
            features["final_url_suspicious_tld"] = 0.0
            features["final_url_is_ip"] = 0.0

        return features

    # ────────────────────────────────────
    # Full Feature Vector
    # ────────────────────────────────────

    def extract_all_features(
        self,
        payload: str,
        payload_type: str,
        urls: List[str],
        upi_params: Optional[Dict[str, Any]] = None,
        redirect_chain: Optional[List[str]] = None,
        final_url: Optional[str] = None,
    ) -> Dict[str, float]:
        """
        Extract the complete QR feature vector across all dimensions.

        Args:
            payload: Raw QR payload text.
            payload_type: Classified payload type string.
            urls: List of extracted URLs.
            upi_params: Parsed UPI parameters (if applicable).
            redirect_chain: URL redirect chain (if available).
            final_url: Final destination URL (if available).

        Returns:
            Comprehensive feature dictionary with 40+ features.
        """
        features: Dict[str, float] = {}

        # Basic payload features
        features.update(self.extract_basic_features(payload))

        # URL features (use primary URL if available)
        primary_url = urls[0] if urls else ""
        features.update(self.extract_url_features(primary_url))

        # Payment features
        features.update(self.extract_payment_features(payload, upi_params))

        # Behavioral features
        features.update(self.extract_behavior_features(payload, urls))

        # Redirect features
        features.update(self.extract_redirect_features(redirect_chain, final_url))

        # Payload type encoding
        type_encoding = {
            "URL": 1.0, "UPI_PAYMENT": 2.0, "VCARD": 3.0,
            "WIFI": 4.0, "EMAIL": 5.0, "PHONE": 6.0,
            "SMS": 7.0, "GEO_LOCATION": 8.0, "CRYPTO": 9.0,
            "PLAIN_TEXT": 0.0, "UNKNOWN": -1.0,
        }
        features["payload_type_code"] = type_encoding.get(payload_type, -1.0)

        logger.debug(f"Extracted {len(features)} QR features")
        return features


# Module-level singleton
qr_feature_engine = QRFeatureEngine()
