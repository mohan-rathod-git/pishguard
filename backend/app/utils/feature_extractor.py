"""
PhishGuard AI — URL Feature Extractor
Production-grade feature extraction for phishing/malware URL detection.
Extracts 25+ cybersecurity features from raw URLs.
"""

import math
import re
from collections import Counter
from typing import Dict, List, Tuple
from urllib.parse import urlparse, parse_qs

import tldextract


# ────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS: List[str] = [
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "confirm", "password", "suspend", "alert", "urgent",
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "ebay", "facebook", "instagram", "whatsapp", "telegram",
    "wallet", "crypto", "bitcoin", "free", "prize", "winner",
    "claim", "reward", "gift", "offer", "bonus", "promo",
    "click", "redirect", "track", "restore", "recover", "unlock",
    "invoice", "payment", "billing", "subscribe", "expire",
]

URL_SHORTENERS: List[str] = [
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "buff.ly",
    "ow.ly", "adf.ly", "tiny.cc", "lnkd.in", "db.tt", "qr.ae",
    "bitly.com", "cutt.ly", "rb.gy", "shorturl.at", "t.ly",
    "v.gd", "x.co", "soo.gd", "s.id", "clck.ru", "rebrand.ly",
]

SUSPICIOUS_TLDS: List[str] = [
    "xyz", "top", "club", "work", "buzz", "tk", "ml", "ga", "cf",
    "gq", "pw", "cc", "icu", "cam", "bid", "loan", "win", "click",
    "link", "info", "online", "site", "website", "space", "fun",
    "life", "live", "stream", "download", "racing", "review",
]

TRUSTED_DOMAINS: List[str] = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "reddit.com", "netflix.com", "whatsapp.com", "zoom.us",
]


# ────────────────────────────────────────────────
# Helper Functions
# ────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (measures randomness)."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)


def _is_ip_based(hostname: str) -> bool:
    """Check if the hostname is an IP address (IPv4 or IPv6)."""
    ipv4_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    ipv6_pattern = re.compile(
        r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
    )
    # Also check hex-encoded IPs like 0x...
    hex_pattern = re.compile(r"^0x[0-9a-fA-F]+$")

    return bool(
        ipv4_pattern.match(hostname)
        or ipv6_pattern.match(hostname)
        or hex_pattern.match(hostname)
    )


def _normalize_url(url: str) -> str:
    """Ensure URL has a scheme so urlparse works correctly."""
    url = url.strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return url


# ────────────────────────────────────────────────
# Main Feature Extraction
# ────────────────────────────────────────────────

def extract_features(url: str) -> Dict[str, float]:
    """
    Extract a comprehensive feature vector from a single URL.

    Returns a dictionary of 25+ numeric features suitable for ML input.
    """
    normalised = _normalize_url(url)
    parsed = urlparse(normalised)
    extracted = tldextract.extract(normalised)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    domain = extracted.registered_domain or ""
    subdomain = extracted.subdomain or ""
    tld = extracted.suffix or ""
    url_lower = url.lower()

    features: Dict[str, float] = {}

    # ── 1. Length-based features ──
    features["url_length"] = float(len(url))
    features["hostname_length"] = float(len(hostname))
    features["path_length"] = float(len(path))
    features["query_length"] = float(len(query))

    # ── 2. Character count features ──
    features["num_dots"] = float(url.count("."))
    features["num_hyphens"] = float(url.count("-"))
    features["num_underscores"] = float(url.count("_"))
    features["num_slashes"] = float(url.count("/"))
    features["num_at_signs"] = float(url.count("@"))
    features["num_ampersands"] = float(url.count("&"))
    features["num_equals"] = float(url.count("="))
    features["num_digits"] = float(sum(c.isdigit() for c in url))
    features["num_special_chars"] = float(
        sum(not c.isalnum() and c not in ":/.-_" for c in url)
    )

    # ── 3. Ratio features ──
    url_len = max(len(url), 1)
    features["digit_ratio"] = round(features["num_digits"] / url_len, 4)
    features["special_char_ratio"] = round(features["num_special_chars"] / url_len, 4)
    letter_count = sum(c.isalpha() for c in url)
    features["letter_ratio"] = round(letter_count / url_len, 4)

    # ── 4. Domain / subdomain features ──
    features["num_subdomains"] = float(len(subdomain.split(".")) if subdomain else 0)
    features["subdomain_length"] = float(len(subdomain))

    # ── 5. Entropy features ──
    features["url_entropy"] = _shannon_entropy(url)
    features["domain_entropy"] = _shannon_entropy(domain)
    features["path_entropy"] = _shannon_entropy(path)

    # ── 6. Boolean / categorical features ──
    features["has_https"] = 1.0 if parsed.scheme == "https" else 0.0
    features["has_at_sign"] = 1.0 if "@" in url else 0.0
    features["has_double_slash_redirect"] = 1.0 if "//" in path else 0.0
    features["is_ip_based"] = 1.0 if _is_ip_based(hostname) else 0.0

    # ── 7. Shortener detection ──
    features["is_shortened"] = 1.0 if any(
        s in url_lower for s in URL_SHORTENERS
    ) else 0.0

    # ── 8. Suspicious keyword count ──
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    features["suspicious_keyword_count"] = float(keyword_hits)
    features["has_suspicious_keywords"] = 1.0 if keyword_hits > 0 else 0.0

    # ── 9. TLD analysis ──
    features["is_suspicious_tld"] = 1.0 if tld.lower() in SUSPICIOUS_TLDS else 0.0
    features["tld_length"] = float(len(tld))

    # ── 10. Path / query features ──
    features["path_depth"] = float(path.count("/") - 1) if path else 0.0
    features["num_query_params"] = float(len(parse_qs(query)))
    features["has_query"] = 1.0 if query else 0.0

    # ── 11. Domain trust ──
    features["is_trusted_domain"] = 1.0 if domain.lower() in TRUSTED_DOMAINS else 0.0

    # ── 12. Punycode / internationalized domain ──
    features["has_punycode"] = 1.0 if "xn--" in hostname else 0.0

    # ── 13. Port presence ──
    features["has_non_standard_port"] = 1.0 if parsed.port and parsed.port not in (80, 443) else 0.0

    return features


def get_feature_names() -> List[str]:
    """Return the ordered list of feature names (useful for model training)."""
    # Use a dummy URL to get the dict keys in insertion order
    dummy = extract_features("https://example.com")
    return list(dummy.keys())


def extract_features_batch(urls: List[str]) -> List[Dict[str, float]]:
    """Extract features for a batch of URLs."""
    return [extract_features(url) for url in urls]


# ────────────────────────────────────────────────
# Explainability Engine
# ────────────────────────────────────────────────

def explain_features(features: Dict[str, float]) -> List[str]:
    """
    Generate human-readable explanations for why a URL may be suspicious.
    Returns a list of reason strings ordered by severity.
    """
    reasons: List[str] = []

    if features.get("is_ip_based", 0):
        reasons.append("URL uses IP address instead of domain name")

    if features.get("is_shortened", 0):
        reasons.append("URL uses a known URL shortening service")

    if features.get("has_at_sign", 0):
        reasons.append("URL contains @ symbol — possible credential harvesting")

    if features.get("has_suspicious_keywords", 0):
        count = int(features.get("suspicious_keyword_count", 0))
        reasons.append(f"Contains {count} suspicious keyword(s) (login, verify, account, etc.)")

    if features.get("is_suspicious_tld", 0):
        reasons.append("Uses a suspicious top-level domain (TLD)")

    if features.get("url_entropy", 0) > 4.5:
        reasons.append(f"High URL entropy ({features['url_entropy']:.2f}) — may be randomly generated")

    if features.get("domain_entropy", 0) > 4.0:
        reasons.append(f"High domain entropy ({features['domain_entropy']:.2f}) — domain looks random")

    if features.get("url_length", 0) > 100:
        reasons.append(f"Unusually long URL ({int(features['url_length'])} chars)")

    if features.get("num_subdomains", 0) > 3:
        reasons.append(f"Excessive subdomains ({int(features['num_subdomains'])})")

    if features.get("has_double_slash_redirect", 0):
        reasons.append("Contains double-slash redirect in path")

    if features.get("has_non_standard_port", 0):
        reasons.append("Uses non-standard port number")

    if features.get("has_punycode", 0):
        reasons.append("Uses Punycode (internationalized domain) — possible homograph attack")

    if features.get("digit_ratio", 0) > 0.3:
        reasons.append(f"High digit ratio ({features['digit_ratio']:.1%}) — URL contains many numbers")

    if features.get("num_special_chars", 0) > 10:
        reasons.append(f"High special character count ({int(features['num_special_chars'])})")

    if features.get("has_https", 0) == 0:
        reasons.append("Does not use HTTPS encryption")

    if features.get("path_depth", 0) > 5:
        reasons.append(f"Deep path structure (depth={int(features['path_depth'])})")

    if features.get("is_trusted_domain", 0):
        reasons.append("Domain is in trusted whitelist — lower risk")

    if not reasons:
        reasons.append("No specific risk indicators detected")

    return reasons
