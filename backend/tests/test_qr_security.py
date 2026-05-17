"""
PhishGuard AI — QR Security Module Tests
Comprehensive tests for QR decoding, extraction, features, classification, and API.
"""

import pytest
import base64
import io
import numpy as np

# Try importing test dependencies
try:
    import cv2
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_QR_DEPS = True
except ImportError:
    HAS_QR_DEPS = False

from app.qr_security.extractor import payload_extractor, PayloadType
from app.qr_security.qr_features import qr_feature_engine
from app.qr_security.qr_classifier import qr_classifier, QRThreatLevel
from app.qr_security.qr_blocker import qr_blocker, BlockingConfig
from app.qr_security.qr_utils import QRSecurityUtils


# ────────────────────────────────────────────────
# Payload Extractor Tests
# ────────────────────────────────────────────────

class TestPayloadExtractor:
    """Tests for QR payload extraction and classification."""

    def test_classify_http_url(self):
        assert payload_extractor.classify_payload("https://example.com") == PayloadType.URL

    def test_classify_bare_domain(self):
        assert payload_extractor.classify_payload("example.com/path") == PayloadType.URL

    def test_classify_upi(self):
        assert payload_extractor.classify_payload(
            "upi://pay?pa=test@upi&pn=Test&am=100"
        ) == PayloadType.UPI

    def test_classify_wifi(self):
        assert payload_extractor.classify_payload(
            "WIFI:S:MyNetwork;T:WPA;P:password;;"
        ) == PayloadType.WIFI

    def test_classify_email(self):
        assert payload_extractor.classify_payload("mailto:test@example.com") == PayloadType.EMAIL

    def test_classify_phone(self):
        assert payload_extractor.classify_payload("tel:+1234567890") == PayloadType.PHONE

    def test_classify_plain_text(self):
        assert payload_extractor.classify_payload("Hello World") == PayloadType.TEXT

    def test_extract_urls_http(self):
        urls = payload_extractor.extract_urls("https://evil.com/phish")
        assert len(urls) == 1
        assert "https://evil.com/phish" in urls[0]

    def test_extract_urls_multiple(self):
        text = "Visit https://a.com and https://b.com"
        urls = payload_extractor.extract_urls(text)
        assert len(urls) == 2

    def test_extract_urls_bare_domain(self):
        urls = payload_extractor.extract_urls("evil-site.xyz/steal")
        assert len(urls) >= 1

    def test_extract_upi_params(self):
        upi = "upi://pay?pa=merchant@bank&pn=Shop&am=500&cu=INR"
        params = payload_extractor.extract_upi_params(upi)
        assert params is not None
        assert params["payee_address"] == "merchant@bank"
        assert params["amount"] == "500"

    def test_extract_upi_params_non_upi(self):
        assert payload_extractor.extract_upi_params("https://example.com") is None

    def test_extract_wifi_params(self):
        wifi = "WIFI:S:TestNet;T:WPA2;P:secret123;;"
        params = payload_extractor.extract_wifi_params(wifi)
        assert params is not None
        assert params["ssid"] == "TestNet"
        assert params["password"] == "secret123"

    def test_detect_hidden_characters(self):
        text = "normal\u200btext\u200dwith\ufeffhidden"
        result = payload_extractor.detect_hidden_characters(text)
        assert result["has_hidden_chars"] is True
        assert result["hidden_char_count"] >= 3

    def test_detect_no_hidden_characters(self):
        result = payload_extractor.detect_hidden_characters("clean text")
        assert result["has_hidden_chars"] is False

    def test_full_payload_extraction(self):
        result = payload_extractor.extract_full_payload("https://evil.xyz/login")
        assert result["payload_type"] == "URL"
        assert result["url_count"] >= 1
        assert "extracted_urls" in result


# ────────────────────────────────────────────────
# Feature Engine Tests
# ────────────────────────────────────────────────

class TestQRFeatureEngine:
    """Tests for QR feature extraction."""

    def test_basic_features(self):
        features = qr_feature_engine.extract_basic_features("test payload")
        assert "payload_length" in features
        assert "payload_entropy" in features
        assert features["payload_length"] == 12.0

    def test_url_features_phishing(self):
        features = qr_feature_engine.extract_url_features(
            "http://192.168.1.1/login/verify/account"
        )
        assert features["url_is_ip_based"] == 1.0
        assert features["url_phishing_keyword_count"] >= 2
        assert features["url_has_https"] == 0.0

    def test_url_features_shortened(self):
        features = qr_feature_engine.extract_url_features("https://bit.ly/abc123")
        assert features["url_is_shortened"] == 1.0

    def test_url_features_suspicious_tld(self):
        features = qr_feature_engine.extract_url_features("https://evil-site.xyz/steal")
        assert features["url_is_suspicious_tld"] == 1.0

    def test_payment_features_upi(self):
        upi_params = {
            "payee_address": "9999999999@upi",
            "payee_name": "SBI Bank",
            "amount": "50000",
            "mode": "02",
        }
        features = qr_feature_engine.extract_payment_features(
            "upi://pay?pa=9999999999@upi", upi_params
        )
        assert features["is_upi_payment"] == 1.0
        assert features["high_amount"] == 1.0
        assert features["has_collect_request"] == 1.0

    def test_behavior_features_apk(self):
        features = qr_feature_engine.extract_behavior_features(
            "https://evil.com/app.apk", ["https://evil.com/app.apk"]
        )
        assert features["has_apk_download"] == 1.0
        assert features["has_auto_download"] == 1.0

    def test_behavior_features_js(self):
        features = qr_feature_engine.extract_behavior_features(
            "javascript:document.cookie", []
        )
        assert features["has_js_indicators"] == 1.0

    def test_redirect_features(self):
        chain = [
            "https://bit.ly/abc",
            "http://redirect.com/go",
            "http://evil.xyz/steal",
        ]
        features = qr_feature_engine.extract_redirect_features(chain, chain[-1])
        assert features["redirect_count"] == 2.0
        assert features["has_redirects"] == 1.0
        assert features["redirect_scheme_downgrade"] == 1.0

    def test_all_features(self):
        features = qr_feature_engine.extract_all_features(
            payload="https://evil.xyz/login",
            payload_type="URL",
            urls=["https://evil.xyz/login"],
        )
        assert len(features) >= 30


# ────────────────────────────────────────────────
# Classifier Tests
# ────────────────────────────────────────────────

class TestQRClassifier:
    """Tests for QR threat classification."""

    def test_safe_classification(self):
        features = qr_feature_engine.extract_all_features(
            payload="https://google.com",
            payload_type="URL",
            urls=["https://google.com"],
        )
        threat, conf, reasons = qr_classifier.classify_from_features(features)
        assert threat in (QRThreatLevel.SAFE, QRThreatLevel.SUSPICIOUS)

    def test_phishing_classification(self):
        features = qr_feature_engine.extract_all_features(
            payload="http://192.168.1.1/login/verify/account/password",
            payload_type="URL",
            urls=["http://192.168.1.1/login/verify/account/password"],
        )
        threat, conf, reasons = qr_classifier.classify_from_features(features)
        assert threat != QRThreatLevel.SAFE
        assert len(reasons) > 0

    def test_malware_classification(self):
        features = qr_feature_engine.extract_all_features(
            payload="http://evil.xyz/malware.apk",
            payload_type="URL",
            urls=["http://evil.xyz/malware.apk"],
        )
        threat, conf, reasons = qr_classifier.classify_from_features(features)
        assert threat in (QRThreatLevel.MALWARE, QRThreatLevel.CRITICAL)

    def test_fake_payment_classification(self):
        upi_params = {
            "payee_address": "9999999999@upi",
            "payee_name": "Fake Bank",
            "amount": "50000",
            "mode": "02",
        }
        features = qr_feature_engine.extract_all_features(
            payload="upi://pay?pa=9999999999@upi&am=50000&mode=02",
            payload_type="UPI_PAYMENT",
            urls=[],
            upi_params=upi_params,
        )
        threat, conf, reasons = qr_classifier.classify_from_features(features)
        assert threat != QRThreatLevel.SAFE

    def test_reasons_populated(self):
        features = qr_feature_engine.extract_all_features(
            payload="http://evil.xyz/login",
            payload_type="URL",
            urls=["http://evil.xyz/login"],
        )
        _, _, reasons = qr_classifier.classify_from_features(features)
        assert isinstance(reasons, list)
        assert len(reasons) > 0


# ────────────────────────────────────────────────
# Blocker Tests
# ────────────────────────────────────────────────

class TestQRBlocker:
    """Tests for QR blocking engine."""

    def test_block_high_risk(self):
        assert qr_blocker.should_block(90, QRThreatLevel.CRITICAL) is True

    def test_allow_safe(self):
        assert qr_blocker.should_block(10, QRThreatLevel.SAFE) is False

    def test_auto_block_malware(self):
        assert qr_blocker.should_block(30, QRThreatLevel.MALWARE) is True

    def test_auto_block_phishing(self):
        assert qr_blocker.should_block(40, QRThreatLevel.PHISHING) is True

    def test_threshold_boundary(self):
        assert qr_blocker.should_block(59, QRThreatLevel.SUSPICIOUS) is False
        assert qr_blocker.should_block(61, QRThreatLevel.SUSPICIOUS) is True

    def test_critical_override(self):
        assert qr_blocker.should_block(90, QRThreatLevel.SAFE) is True


# ────────────────────────────────────────────────
# Utility Tests
# ────────────────────────────────────────────────

class TestQRUtils:
    """Tests for QR security utilities."""

    def test_generate_scan_id(self):
        sid = QRSecurityUtils.generate_scan_id()
        assert sid.startswith("QR-")
        assert len(sid) == 11

    def test_validate_empty_image(self):
        valid, err = QRSecurityUtils.validate_image(b"")
        assert valid is False

    def test_validate_oversized_image(self):
        data = b"\x89PNG" + b"\x00" * (11 * 1024 * 1024)
        valid, err = QRSecurityUtils.validate_image(data)
        assert valid is False
        assert "size" in err.lower()

    def test_validate_invalid_format(self):
        valid, err = QRSecurityUtils.validate_image(b"not an image")
        assert valid is False

    def test_sanitize_payload(self):
        dirty = "test\x00\x01\x02payload"
        clean = QRSecurityUtils.sanitize_payload_for_response(dirty)
        assert "\x00" not in clean

    def test_compute_hash(self):
        h = QRSecurityUtils.compute_payload_hash("test")
        assert len(h) == 64

    def test_format_risk_level(self):
        assert QRSecurityUtils.format_risk_level(10) == "LOW"
        assert QRSecurityUtils.format_risk_level(50) == "HIGH"
        assert QRSecurityUtils.format_risk_level(90) == "CRITICAL"


# ────────────────────────────────────────────────
# API Integration Tests
# ────────────────────────────────────────────────

@pytest.mark.asyncio
class TestQRAPI:
    """Tests for QR security API endpoints."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from app.main import app
        return TestClient(app)

    def test_qr_health(self, client):
        resp = client.get("/api/v1/qr/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("healthy", "degraded")
        assert "qr_engine_active" in data

    def test_scan_no_file(self, client):
        resp = client.post("/api/v1/qr/scan")
        assert resp.status_code in (400, 422)

    def test_scan_empty_file(self, client):
        from io import BytesIO
        resp = client.post(
            "/api/v1/qr/scan",
            files={"file": ("empty.png", BytesIO(b""), "image/png")},
        )
        assert resp.status_code == 400

    def test_scan_invalid_format(self, client):
        resp = client.post(
            "/api/v1/qr/scan",
            files={"file": ("test.txt", b"not an image", "text/plain")},
        )
        assert resp.status_code == 400

    @pytest.mark.skipif(not HAS_QR_DEPS, reason="QR deps not installed")
    def test_scan_valid_qr_image(self, client):
        """Test with a programmatically generated QR code image."""
        try:
            import qrcode
            qr = qrcode.make("https://google.com")
            buf = io.BytesIO()
            qr.save(buf, format="PNG")
            buf.seek(0)

            resp = client.post(
                "/api/v1/qr/scan",
                files={"file": ("qr.png", buf, "image/png")},
                data={"follow_redirects": "false", "use_ml_model": "false"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] in ("ALLOWED", "BLOCKED", "NO_QR_FOUND")
            assert "risk_score" in data
        except ImportError:
            pytest.skip("qrcode library not available")


# ────────────────────────────────────────────────
# Malicious QR Simulation Tests
# ────────────────────────────────────────────────

class TestMaliciousQRSimulations:
    """Simulate malicious QR scenarios and verify detection."""

    def _run_classification(self, payload, payload_type="URL", urls=None, upi_params=None):
        if urls is None:
            urls = payload_extractor.extract_urls(payload)
        features = qr_feature_engine.extract_all_features(
            payload=payload, payload_type=payload_type,
            urls=urls, upi_params=upi_params,
        )
        return qr_classifier.classify_from_features(features)

    def test_shortened_phishing_url(self):
        threat, _, reasons = self._run_classification(
            "https://bit.ly/fakebank-login-verify"
        )
        assert threat != QRThreatLevel.SAFE

    def test_ip_based_credential_stealer(self):
        threat, _, _ = self._run_classification(
            "http://45.33.32.156:8080/login/signin/password"
        )
        assert threat != QRThreatLevel.SAFE

    def test_apk_malware_download(self):
        threat, _, _ = self._run_classification(
            "https://evil-download.xyz/app-update.apk"
        )
        assert threat in (QRThreatLevel.MALWARE, QRThreatLevel.CRITICAL)

    def test_fake_upi_payment(self):
        payload = "upi://pay?pa=9876543210@ybl&pn=SBI+Bank&am=25000&mode=02"
        upi_params = payload_extractor.extract_upi_params(payload)
        threat, _, _ = self._run_classification(
            payload, payload_type="UPI_PAYMENT",
            urls=[], upi_params=upi_params,
        )
        assert threat != QRThreatLevel.SAFE

    def test_hidden_unicode_obfuscation(self):
        payload = "https://g\u200booglе.com/login"  # Zero-width space + Cyrillic е
        threat, _, reasons = self._run_classification(payload)
        assert threat != QRThreatLevel.SAFE
        assert any("hidden" in r.lower() or "homoglyph" in r.lower() for r in reasons)

    def test_javascript_injection(self):
        features = qr_feature_engine.extract_all_features(
            payload="javascript:document.cookie",
            payload_type="TEXT", urls=[],
        )
        assert features["has_js_indicators"] == 1.0

    def test_safe_google_url(self):
        threat, _, _ = self._run_classification("https://www.google.com")
        assert threat == QRThreatLevel.SAFE
