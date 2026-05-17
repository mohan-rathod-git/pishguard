"""
PhishGuard AI — QR Threat Classifier
Heuristic + ML-integrated threat classification for QR payloads.
Combines QR-specific feature analysis with the existing URL AI model
to produce a final threat classification.
"""

from enum import Enum
from typing import Dict, List, Optional, Any, Tuple

from app.utils.logger import logger


# ────────────────────────────────────────────────
# Threat Classifications
# ────────────────────────────────────────────────

class QRThreatLevel(str, Enum):
    """QR code threat classification labels."""
    SAFE = "SAFE"
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    SCAM = "SCAM"
    FAKE_PAYMENT = "FAKE_PAYMENT"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class QRSeverity(str, Enum):
    """Severity levels for QR threats."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ────────────────────────────────────────────────
# QR Threat Classifier
# ────────────────────────────────────────────────

class QRThreatClassifier:
    """
    Classifies QR code threats by combining:
    1. QR-specific heuristic rules
    2. Feature-based scoring
    3. Existing URL ML model predictions
    4. Payment scam detection rules
    """

    # Classification thresholds
    THRESHOLDS = {
        "safe_max": 20,
        "suspicious_max": 45,
        "warning_max": 65,
        "dangerous_max": 85,
        # Above 85 = CRITICAL
    }

    @staticmethod
    def classify_from_features(
        qr_features: Dict[str, float],
        url_prediction: Optional[Dict[str, Any]] = None,
    ) -> Tuple[QRThreatLevel, float, List[str]]:
        """
        Classify QR code threat level from extracted features
        and optional URL model prediction.

        Args:
            qr_features: Feature vector from QRFeatureEngine.
            url_prediction: Prediction result from existing PhishGuard URL model.

        Returns:
            Tuple of (threat_level, confidence, reasons).
        """
        reasons: List[str] = []
        risk_points: float = 0.0

        # ── 1. Hidden character / obfuscation signals ──
        if qr_features.get("has_hidden_chars", 0):
            count = int(qr_features.get("hidden_char_count", 0))
            risk_points += 25
            reasons.append(
                f"Hidden Unicode characters detected ({count}) — payload obfuscation"
            )

        if qr_features.get("has_homoglyphs", 0):
            risk_points += 20
            reasons.append("Homoglyph characters detected — possible IDN homograph attack")

        # ── 2. URL-level threats ──
        if qr_features.get("url_is_ip_based", 0):
            risk_points += 20
            reasons.append("URL uses IP address instead of domain name")

        if qr_features.get("url_is_shortened", 0):
            risk_points += 15
            reasons.append("Shortened URL detected — destination is hidden")

        if qr_features.get("url_is_suspicious_tld", 0):
            risk_points += 12
            reasons.append("Uses a high-risk top-level domain (TLD)")

        if qr_features.get("url_has_at_sign", 0):
            risk_points += 15
            reasons.append("URL contains @ symbol — possible credential harvesting")

        if qr_features.get("url_has_double_slash_redirect", 0):
            risk_points += 10
            reasons.append("URL contains double-slash redirect pattern")

        if qr_features.get("url_has_punycode", 0):
            risk_points += 15
            reasons.append("Punycode domain detected — possible homograph attack")

        if qr_features.get("url_has_non_standard_port", 0):
            risk_points += 10
            reasons.append("Non-standard port number in URL")

        if not qr_features.get("url_has_https", 0) and qr_features.get("url_length", 0) > 0:
            risk_points += 8
            reasons.append("URL does not use HTTPS encryption")

        # ── 3. Keyword-based signals ──
        phishing_kw = int(qr_features.get("url_phishing_keyword_count", 0))
        if phishing_kw > 0:
            risk_points += min(phishing_kw * 8, 25)
            reasons.append(f"Contains {phishing_kw} phishing keyword(s)")

        scam_kw = int(qr_features.get("url_scam_keyword_count", 0))
        if scam_kw > 0:
            risk_points += min(scam_kw * 6, 20)
            reasons.append(f"Contains {scam_kw} scam keyword(s)")

        malware_kw = int(qr_features.get("url_malware_keyword_count", 0))
        if malware_kw > 0:
            risk_points += min(malware_kw * 10, 30)
            reasons.append(f"Contains {malware_kw} malware-related keyword(s)")

        # ── 4. Brand impersonation ──
        if qr_features.get("url_has_brand_mimic", 0):
            risk_points += 25
            reasons.append("URL appears to impersonate a well-known brand")

        # ── 5. Download / execution threats ──
        if qr_features.get("has_apk_download", 0):
            risk_points += 30
            reasons.append("APK download detected — potential malware installation")

        if qr_features.get("has_exe_download", 0):
            risk_points += 30
            reasons.append("Executable download detected — potential malware")

        if qr_features.get("has_auto_download", 0) and not qr_features.get("has_apk_download", 0):
            risk_points += 20
            reasons.append("Auto-download file extension detected")

        if qr_features.get("has_js_indicators", 0):
            risk_points += 20
            reasons.append("JavaScript injection indicators detected")

        if qr_features.get("has_data_uri", 0):
            risk_points += 15
            reasons.append("Data URI detected — may embed malicious content")

        # ── 6. Payment / UPI scam signals ──
        if qr_features.get("is_upi_payment", 0):
            if qr_features.get("suspicious_vpa", 0):
                risk_points += 25
                reasons.append("Suspicious UPI VPA pattern detected")

            if qr_features.get("has_collect_request", 0):
                risk_points += 30
                reasons.append(
                    "UPI collect request detected — money will be DEBITED from your account"
                )

            if qr_features.get("high_amount", 0):
                risk_points += 15
                reasons.append("High transaction amount detected (>₹10,000)")

            if qr_features.get("mentions_bank", 0):
                risk_points += 10
                reasons.append("Bank name mentioned in payment details — possible impersonation")

            if qr_features.get("mentions_payment_app", 0):
                risk_points += 10
                reasons.append("Payment app name in details — possible impersonation")

        # ── 7. Entropy / obfuscation ──
        if qr_features.get("url_entropy", 0) > 4.5:
            risk_points += 8
            reasons.append(
                f"High URL entropy ({qr_features['url_entropy']:.2f}) — may be randomly generated"
            )

        if qr_features.get("payload_entropy", 0) > 5.0:
            risk_points += 5
            reasons.append("High payload entropy — possible encoded/obfuscated content")

        # ── 8. Redirect chain analysis ──
        redirect_count = int(qr_features.get("redirect_count", 0))
        if redirect_count > 0:
            risk_points += min(redirect_count * 5, 20)
            reasons.append(f"Redirect chain detected ({redirect_count} redirects)")

        if qr_features.get("redirect_domain_change", 0) > 0:
            risk_points += 15
            reasons.append("Domain changes during redirect chain")

        if qr_features.get("redirect_scheme_downgrade", 0):
            risk_points += 15
            reasons.append("HTTPS to HTTP downgrade in redirect chain")

        if qr_features.get("final_url_suspicious_tld", 0):
            risk_points += 12
            reasons.append("Final destination has suspicious TLD")

        if qr_features.get("final_url_is_ip", 0):
            risk_points += 15
            reasons.append("Final destination resolves to IP address")

        # ── 9. Integrate existing URL model prediction ──
        if url_prediction:
            url_risk = url_prediction.get("risk_score", 0)
            url_label = url_prediction.get("prediction", "SAFE")
            url_confidence = url_prediction.get("confidence", 0.0)

            if url_label != "SAFE":
                # Blend the URL model's risk score
                blend_weight = 0.6  # Trust the ML model significantly
                risk_points = (
                    risk_points * (1 - blend_weight) +
                    url_risk * blend_weight
                )
                reasons.append(
                    f"URL AI model classified as {url_label} "
                    f"(confidence: {url_confidence:.1%}, risk: {url_risk})"
                )
            else:
                # Safe URL prediction reduces risk
                discount = min(url_confidence * 15, 15)
                risk_points = max(0, risk_points - discount)
                if url_confidence > 0.8:
                    reasons.append(
                        f"URL AI model classified as SAFE (confidence: {url_confidence:.1%})"
                    )

        # ── 10. URL-level structural anomalies ──
        if qr_features.get("url_length", 0) > 150:
            risk_points += 5
            reasons.append(
                f"Unusually long URL ({int(qr_features['url_length'])} chars)"
            )

        if qr_features.get("url_num_subdomains", 0) > 3:
            risk_points += 6
            reasons.append(
                f"Excessive subdomains ({int(qr_features['url_num_subdomains'])})"
            )

        # ── Clamp risk ──
        risk_score = max(0, min(100, int(risk_points)))

        # ── Determine classification ──
        threat_level = QRThreatClassifier._risk_to_threat_level(
            risk_score, qr_features
        )

        # ── Calculate confidence ──
        confidence = QRThreatClassifier._calculate_confidence(
            risk_score, len(reasons), url_prediction
        )

        if not reasons:
            reasons.append("No specific risk indicators detected")

        logger.info(
            f"QR classification: {threat_level.value} "
            f"(risk={risk_score}, confidence={confidence:.2f})"
        )

        return threat_level, confidence, reasons

    @staticmethod
    def _risk_to_threat_level(
        risk_score: int,
        features: Dict[str, float],
    ) -> QRThreatLevel:
        """Map risk score + features to a threat classification."""
        thresholds = QRThreatClassifier.THRESHOLDS

        if risk_score <= thresholds["safe_max"]:
            return QRThreatLevel.SAFE

        if risk_score <= thresholds["suspicious_max"]:
            return QRThreatLevel.SUSPICIOUS

        # Check for specific threat types
        if features.get("is_upi_payment", 0) and (
            features.get("suspicious_vpa", 0)
            or features.get("has_collect_request", 0)
        ):
            return QRThreatLevel.FAKE_PAYMENT

        if features.get("has_apk_download", 0) or features.get("has_exe_download", 0):
            return QRThreatLevel.MALWARE

        if features.get("url_has_brand_mimic", 0) or (
            features.get("url_phishing_keyword_count", 0) >= 2
        ):
            return QRThreatLevel.PHISHING

        if risk_score > thresholds["dangerous_max"]:
            return QRThreatLevel.CRITICAL

        if risk_score > thresholds["warning_max"]:
            if features.get("url_scam_keyword_count", 0) > 0:
                return QRThreatLevel.SCAM
            return QRThreatLevel.PHISHING

        return QRThreatLevel.SUSPICIOUS

    @staticmethod
    def _calculate_confidence(
        risk_score: int,
        reason_count: int,
        url_prediction: Optional[Dict[str, Any]],
    ) -> float:
        """
        Calculate classification confidence based on
        risk score consistency and evidence strength.
        """
        # Base confidence from risk score distance from midpoint
        distance_from_mid = abs(risk_score - 50) / 50.0
        base_confidence = 0.5 + (distance_from_mid * 0.35)

        # Evidence boost: more reasons = higher confidence
        evidence_boost = min(reason_count * 0.03, 0.15)

        # URL model agreement boost
        model_boost = 0.0
        if url_prediction:
            url_conf = url_prediction.get("confidence", 0.5)
            model_boost = url_conf * 0.1

        confidence = min(base_confidence + evidence_boost + model_boost, 0.99)
        return round(confidence, 4)

    @staticmethod
    def get_severity(threat_level: QRThreatLevel) -> QRSeverity:
        """Map threat level to severity for response formatting."""
        severity_map = {
            QRThreatLevel.SAFE: QRSeverity.NONE,
            QRThreatLevel.SUSPICIOUS: QRSeverity.LOW,
            QRThreatLevel.SCAM: QRSeverity.MEDIUM,
            QRThreatLevel.PHISHING: QRSeverity.HIGH,
            QRThreatLevel.FAKE_PAYMENT: QRSeverity.HIGH,
            QRThreatLevel.MALWARE: QRSeverity.CRITICAL,
            QRThreatLevel.CRITICAL: QRSeverity.CRITICAL,
        }
        return severity_map.get(threat_level, QRSeverity.MEDIUM)


# Module-level singleton
qr_classifier = QRThreatClassifier()
