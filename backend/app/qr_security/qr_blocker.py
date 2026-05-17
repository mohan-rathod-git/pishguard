"""
PhishGuard AI — QR Blocking Engine
Decision engine for blocking or allowing QR code payloads.
Uses configurable thresholds and threat-level-based rules.
"""

from typing import Dict, List, Optional, Any

from app.utils.logger import logger
from app.qr_security.qr_classifier import QRThreatLevel


# ────────────────────────────────────────────────
# Blocking Configuration
# ────────────────────────────────────────────────

class BlockingConfig:
    """Configurable blocking thresholds."""

    # Risk score threshold — block if score exceeds this
    RISK_THRESHOLD: int = 60

    # Always block these threat levels regardless of score
    AUTO_BLOCK_LEVELS = {
        QRThreatLevel.MALWARE,
        QRThreatLevel.CRITICAL,
        QRThreatLevel.PHISHING,
        QRThreatLevel.FAKE_PAYMENT,
    }

    # Always allow these threat levels (unless risk score is extreme)
    AUTO_ALLOW_LEVELS = {
        QRThreatLevel.SAFE,
    }

    # Emergency override — block everything above this score
    CRITICAL_THRESHOLD: int = 85


class QRBlocker:
    """
    Production QR blocking engine.
    Determines whether a QR code payload should be blocked or allowed
    based on risk score, threat classification, and configurable rules.
    """

    def __init__(self, config: Optional[BlockingConfig] = None) -> None:
        self.config = config or BlockingConfig()
        self._block_log: List[Dict[str, Any]] = []

    def should_block(
        self,
        risk_score: int,
        threat_level: QRThreatLevel,
        override_threshold: Optional[int] = None,
    ) -> bool:
        """
        Determine whether to block a QR code payload.

        Args:
            risk_score: Computed risk score (0-100).
            threat_level: Classified threat level.
            override_threshold: Optional per-request threshold override.

        Returns:
            True if the payload should be BLOCKED.
        """
        threshold = override_threshold or self.config.RISK_THRESHOLD

        # Rule 1: Auto-block dangerous threat levels
        if threat_level in self.config.AUTO_BLOCK_LEVELS:
            self._log_block(
                risk_score, threat_level,
                reason=f"Auto-blocked: threat level {threat_level.value}",
            )
            return True

        # Rule 2: Auto-allow safe QR codes (unless score is extreme)
        if threat_level in self.config.AUTO_ALLOW_LEVELS:
            if risk_score >= self.config.CRITICAL_THRESHOLD:
                self._log_block(
                    risk_score, threat_level,
                    reason="Safe-classified but critically high risk score",
                )
                return True
            return False

        # Rule 3: Risk score threshold
        if risk_score >= threshold:
            self._log_block(
                risk_score, threat_level,
                reason=f"Risk score {risk_score} exceeds threshold {threshold}",
            )
            return True

        # Rule 4: Critical threshold override
        if risk_score >= self.config.CRITICAL_THRESHOLD:
            self._log_block(
                risk_score, threat_level,
                reason=f"Risk score {risk_score} exceeds critical threshold",
            )
            return True

        return False

    def _log_block(
        self,
        risk_score: int,
        threat_level: QRThreatLevel,
        reason: str,
    ) -> None:
        """Log a blocking decision for audit trail."""
        import time

        entry = {
            "timestamp": time.time(),
            "risk_score": risk_score,
            "threat_level": threat_level.value,
            "reason": reason,
        }
        self._block_log.append(entry)

        # Keep only the last 1000 entries to prevent memory leaks
        if len(self._block_log) > 1000:
            self._block_log = self._block_log[-500:]

        logger.warning(
            f"QR BLOCKED: {threat_level.value} (risk={risk_score}) — {reason}"
        )

    def get_block_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent blocking decisions for audit."""
        return self._block_log[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Return blocking engine statistics."""
        return {
            "total_blocks": len(self._block_log),
            "risk_threshold": self.config.RISK_THRESHOLD,
            "critical_threshold": self.config.CRITICAL_THRESHOLD,
            "auto_block_levels": [
                level.value for level in self.config.AUTO_BLOCK_LEVELS
            ],
        }

    def update_threshold(self, new_threshold: int) -> None:
        """
        Dynamically update the risk score blocking threshold.

        Args:
            new_threshold: New threshold value (0-100).
        """
        if not 0 <= new_threshold <= 100:
            raise ValueError("Threshold must be between 0 and 100")

        old = self.config.RISK_THRESHOLD
        self.config.RISK_THRESHOLD = new_threshold
        logger.info(
            f"QR blocking threshold updated: {old} → {new_threshold}"
        )


# Module-level singleton
qr_blocker = QRBlocker()
