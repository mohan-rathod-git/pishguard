"""
PhishGuard AI — Threat Scoring Engine
Combines ML prediction with heuristic signals for a final risk assessment.
"""

from typing import Dict, List, Tuple

from app.utils.feature_extractor import explain_features


# ── Label Mapping ──
LABEL_MAP = {
    0: "PHISHING",
    1: "SAFE",
}

# Reverse for lookup
LABEL_TO_INT = {v: k for k, v in LABEL_MAP.items()}


class ThreatScorer:
    """
    Combines ML model confidence with rule-based heuristics
    to produce a final threat verdict and risk score.
    """

    @staticmethod
    def compute_risk_score(
        prediction_label: str,
        confidence: float,
        features: Dict[str, float],
    ) -> int:
        """
        Compute a 0-100 risk score.
        0 = completely safe, 100 = extremely dangerous.
        """
        # Start with ML confidence
        if prediction_label == "SAFE":
            base_score = int((1.0 - confidence) * 60)
        else:
            base_score = int(confidence * 70)

        # ── Heuristic adjustments ──
        adjustments = 0

        if features.get("is_ip_based", 0):
            adjustments += 15
        if features.get("is_shortened", 0):
            adjustments += 10
        if features.get("has_at_sign", 0):
            adjustments += 12
        if features.get("is_suspicious_tld", 0):
            adjustments += 8
        if features.get("has_suspicious_keywords", 0):
            kw_count = features.get("suspicious_keyword_count", 0)
            adjustments += min(int(kw_count) * 3, 15)
        if features.get("url_entropy", 0) > 4.5:
            adjustments += 8
        if features.get("has_punycode", 0):
            adjustments += 10
        if features.get("has_double_slash_redirect", 0):
            adjustments += 7
        if features.get("url_length", 0) > 150:
            adjustments += 5
        if features.get("num_subdomains", 0) > 3:
            adjustments += 6

        # Whitelist discount
        if features.get("is_trusted_domain", 0):
            adjustments -= 30

        # HTTPS bonus
        if features.get("has_https", 0):
            adjustments -= 3

        final = max(0, min(100, base_score + adjustments))
        return final

    @staticmethod
    def classify_threat(
        risk_score: int,
        prediction_label: str,
        features: Dict[str, float],
    ) -> str:
        """
        Refine the ML label based on risk score and heuristics.
        Returns one of: SAFE, PHISHING, SPAM, MALWARE, SCAM.
        """
        if risk_score <= 20:
            return "SAFE"

        if risk_score <= 40:
            # Low-medium risk — might be spam
            if features.get("has_suspicious_keywords", 0) and features.get("is_suspicious_tld", 0):
                return "SPAM"
            return "SAFE"

        if risk_score <= 65:
            # Medium risk
            if features.get("is_ip_based", 0) or features.get("has_punycode", 0):
                return "MALWARE"
            if features.get("has_suspicious_keywords", 0):
                return "PHISHING"
            return "SCAM"

        # High risk (65+)
        if features.get("is_ip_based", 0) and features.get("has_non_standard_port", 0):
            return "MALWARE"
        if features.get("suspicious_keyword_count", 0) >= 3:
            return "PHISHING"
        if features.get("is_shortened", 0) and risk_score > 80:
            return "SCAM"

        return prediction_label if prediction_label != "SAFE" else "PHISHING"

    @staticmethod
    def build_verdict(
        url: str,
        prediction_label: str,
        confidence: float,
        features: Dict[str, float],
    ) -> Dict:
        """
        Build the final verdict dictionary for a URL.
        """
        risk_score = ThreatScorer.compute_risk_score(
            prediction_label, confidence, features
        )
        final_label = ThreatScorer.classify_threat(
            risk_score, prediction_label, features
        )
        reasons = explain_features(features)

        return {
            "url": url,
            "prediction": final_label,
            "confidence": round(confidence, 4),
            "risk_score": risk_score,
            "reasons": reasons,
        }


# Module-level instance
threat_scorer = ThreatScorer()
