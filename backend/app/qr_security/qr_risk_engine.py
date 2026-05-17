"""
PhishGuard AI — QR Risk Engine
Central orchestrator for the QR security pipeline.
Coordinates decoding, extraction, feature engineering, redirect analysis,
ML model integration, classification, and blocking decisions.
"""

import time
import asyncio
from typing import Dict, List, Optional, Any

from app.utils.logger import logger
from app.qr_security.decoder import qr_decoder, QRDecodeResult
from app.qr_security.extractor import payload_extractor, PayloadType
from app.qr_security.qr_features import qr_feature_engine
from app.qr_security.qr_classifier import (
    qr_classifier,
    QRThreatLevel,
    QRThreatClassifier,
)
from app.qr_security.qr_blocker import qr_blocker
from app.qr_security.qr_redirect_analyzer import redirect_analyzer
from app.qr_security.qr_utils import QRSecurityUtils


class QRRiskEngine:
    """
    Production QR risk assessment engine.
    Orchestrates the complete QR security pipeline from image to verdict.

    Pipeline:
        QR Image → Decode → Extract Payload → Identify URLs →
        Expand Shortened URLs → Analyze Redirects → Run URL AI Model →
        Extract QR Features → Classify Threat → Block/Allow Decision
    """

    def __init__(self) -> None:
        self._scan_count: int = 0
        self._block_count: int = 0
        self._start_time: float = time.time()

    async def scan_image(
        self,
        image_data: bytes,
        use_ml_model: bool = True,
        follow_redirects: bool = True,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """
        Run the full QR security pipeline on an uploaded image.

        Args:
            image_data: Raw image bytes (PNG, JPEG, BMP, WEBP).
            use_ml_model: Whether to integrate the existing URL AI model.
            follow_redirects: Whether to follow and analyze redirect chains.
            timeout: Maximum processing time in seconds.

        Returns:
            Complete scan result dictionary.
        """
        start = time.time()
        self._scan_count += 1
        scan_id = QRSecurityUtils.generate_scan_id()

        logger.info(f"[{scan_id}] Starting QR scan pipeline...")

        try:
            result = await asyncio.wait_for(
                self._run_pipeline(
                    image_data=image_data,
                    scan_id=scan_id,
                    use_ml_model=use_ml_model,
                    follow_redirects=follow_redirects,
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.error(f"[{scan_id}] Pipeline timed out after {timeout}s")
            result = self._build_error_result(
                scan_id=scan_id,
                error=f"Scan timed out after {timeout} seconds",
            )
        except Exception as e:
            logger.error(f"[{scan_id}] Pipeline error: {e}")
            result = self._build_error_result(
                scan_id=scan_id,
                error=str(e),
            )

        result["processing_time_ms"] = round((time.time() - start) * 1000, 2)
        return result

    async def _run_pipeline(
        self,
        image_data: bytes,
        scan_id: str,
        use_ml_model: bool,
        follow_redirects: bool,
    ) -> Dict[str, Any]:
        """Execute the complete QR analysis pipeline."""

        # ── Step 1: Decode QR ──
        logger.info(f"[{scan_id}] Step 1: Decoding QR image...")
        decoded_results: List[QRDecodeResult] = qr_decoder.decode_image(image_data)

        if not decoded_results:
            logger.warning(f"[{scan_id}] No QR codes found in image")
            return {
                "scan_id": scan_id,
                "status": "NO_QR_FOUND",
                "prediction": "UNKNOWN",
                "risk_score": 0,
                "confidence": 0.0,
                "severity": "NONE",
                "decoded_payload": None,
                "payload_type": None,
                "final_url": None,
                "redirect_chain": [],
                "reasons": ["No QR code detected in the uploaded image"],
                "fake_payment_detected": False,
                "is_shortened_url": False,
                "qr_count": 0,
                "all_results": [],
            }

        # Process each QR code found
        all_results: List[Dict[str, Any]] = []
        worst_result: Optional[Dict[str, Any]] = None
        worst_risk: int = -1

        for idx, qr in enumerate(decoded_results):
            logger.info(
                f"[{scan_id}] Processing QR {idx+1}/{len(decoded_results)}: "
                f"{qr.decoded_text[:80]}..."
            )

            qr_result = await self._analyze_single_qr(
                decoded_text=qr.decoded_text,
                scan_id=scan_id,
                qr_index=idx,
                use_ml_model=use_ml_model,
                follow_redirects=follow_redirects,
            )
            all_results.append(qr_result)

            if qr_result["risk_score"] > worst_risk:
                worst_risk = qr_result["risk_score"]
                worst_result = qr_result

        # Use the worst (highest risk) result as the primary response
        primary = worst_result or all_results[0]

        # Derive convenience flags
        fake_payment_detected = primary.get("prediction") == "FAKE_PAYMENT"
        redirect_chain = primary.get("redirect_chain") or []
        payload = primary.get("decoded_payload", "") or ""
        is_shortened_url = any(
            s in payload.lower()
            for s in ["bit.ly", "tinyurl", "t.co", "goo.gl", "rb.gy", "t.ly", "cutt.ly"]
        )

        return {
            "scan_id": scan_id,
            "status": primary["status"],
            "prediction": primary["prediction"],
            "risk_score": primary["risk_score"],
            "confidence": primary["confidence"],
            "severity": primary["severity"],
            "decoded_payload": primary["decoded_payload"],
            "payload_type": primary.get("payload_type"),
            "final_url": primary.get("final_url"),
            "redirect_chain": redirect_chain,
            "reasons": primary["reasons"],
            "fake_payment_detected": fake_payment_detected,
            "is_shortened_url": is_shortened_url,
            "qr_count": len(decoded_results),
            "all_results": all_results if len(decoded_results) > 1 else [],
        }

    async def _analyze_single_qr(
        self,
        decoded_text: str,
        scan_id: str,
        qr_index: int,
        use_ml_model: bool,
        follow_redirects: bool,
    ) -> Dict[str, Any]:
        """Analyze a single decoded QR payload through the full pipeline."""

        # ── Step 2: Extract payload ──
        logger.info(f"[{scan_id}] Step 2: Extracting payload...")
        payload_info = payload_extractor.extract_full_payload(decoded_text)
        urls = payload_info["extracted_urls"]
        payload_type = payload_info["payload_type"]
        upi_params = payload_info.get("upi_params")

        # ── Step 3: Expand shortened URLs ──
        final_url: Optional[str] = None
        redirect_chain: Optional[List[str]] = None

        if urls and follow_redirects:
            logger.info(f"[{scan_id}] Step 3: Analyzing redirects for {len(urls)} URL(s)...")
            primary_url = urls[0]

            redirect_result = await redirect_analyzer.analyze_url(primary_url)
            if redirect_result:
                redirect_chain = redirect_result.get("chain", [])
                final_url = redirect_result.get("final_url", primary_url)

                # Replace primary URL with expanded final URL
                if final_url and final_url != primary_url:
                    logger.info(
                        f"[{scan_id}] URL expanded: {primary_url[:60]} → {final_url[:60]}"
                    )
            else:
                final_url = primary_url
        elif urls:
            final_url = urls[0]

        # ── Step 4: Run existing URL AI model ──
        url_prediction: Optional[Dict[str, Any]] = None

        if urls and use_ml_model:
            logger.info(f"[{scan_id}] Step 4: Running URL AI model...")
            url_prediction = await self._get_url_prediction(
                final_url or urls[0]
            )

        # ── Step 5: Extract QR features ──
        logger.info(f"[{scan_id}] Step 5: Extracting QR features...")
        qr_features = qr_feature_engine.extract_all_features(
            payload=decoded_text,
            payload_type=payload_type,
            urls=urls,
            upi_params=upi_params,
            redirect_chain=redirect_chain,
            final_url=final_url,
        )

        # ── Step 6: Classify threat ──
        logger.info(f"[{scan_id}] Step 6: Classifying threat...")
        threat_level, confidence, reasons = qr_classifier.classify_from_features(
            qr_features=qr_features,
            url_prediction=url_prediction,
        )

        risk_score = self._compute_final_risk(
            qr_features, threat_level, url_prediction
        )

        # ── Step 7: Block/Allow decision ──
        severity = QRThreatClassifier.get_severity(threat_level)
        block_decision = qr_blocker.should_block(
            risk_score=risk_score,
            threat_level=threat_level,
        )

        status = "BLOCKED" if block_decision else "ALLOWED"
        if block_decision:
            self._block_count += 1

        logger.info(
            f"[{scan_id}] Result: {status} | {threat_level.value} | "
            f"risk={risk_score} | confidence={confidence:.2f}"
        )

        return {
            "decoded_payload": decoded_text,
            "payload_type": payload_type,
            "status": status,
            "prediction": threat_level.value,
            "risk_score": risk_score,
            "confidence": round(confidence, 4),
            "severity": severity.value,
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "reasons": reasons,
            "url_model_prediction": url_prediction,
            "qr_index": qr_index,
        }

    async def _get_url_prediction(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Run the existing PhishGuard URL AI model on a URL.
        Integrates with the existing predictor singleton.
        """
        try:
            from app.ml.predictor import predictor

            if not predictor.model_loaded:
                logger.warning("URL AI model not loaded — skipping ML prediction")
                return None

            # Run prediction in executor to avoid blocking the event loop
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, predictor.predict_url, url
            )

            logger.info(
                f"URL AI model result: {result.get('prediction')} "
                f"(risk={result.get('risk_score')}, conf={result.get('confidence'):.2f})"
            )
            return result

        except Exception as e:
            logger.error(f"URL AI model prediction failed: {e}")
            return None

    @staticmethod
    def _compute_final_risk(
        qr_features: Dict[str, float],
        threat_level: QRThreatLevel,
        url_prediction: Optional[Dict[str, Any]],
    ) -> int:
        """
        Compute the final risk score by blending QR heuristics
        and URL model prediction.
        """
        # Start with heuristic base score
        base_score = 0

        # URL model contribution (40% weight if available)
        if url_prediction:
            url_risk = url_prediction.get("risk_score", 0)
            base_score = int(url_risk * 0.4)

        # Threat level contribution
        level_scores = {
            QRThreatLevel.SAFE: 5,
            QRThreatLevel.SUSPICIOUS: 35,
            QRThreatLevel.SCAM: 55,
            QRThreatLevel.PHISHING: 70,
            QRThreatLevel.FAKE_PAYMENT: 75,
            QRThreatLevel.MALWARE: 85,
            QRThreatLevel.CRITICAL: 95,
        }
        level_score = level_scores.get(threat_level, 50)

        # Blend: 60% threat level, 40% URL model (if present)
        if url_prediction:
            final = int(level_score * 0.6 + base_score)
        else:
            final = level_score

        # Feature adjustments
        if qr_features.get("has_hidden_chars", 0):
            final += 5
        if qr_features.get("has_apk_download", 0):
            final += 10
        if qr_features.get("has_collect_request", 0):
            final += 10
        if qr_features.get("redirect_count", 0) > 3:
            final += 5

        return max(0, min(100, final))

    def _build_error_result(
        self,
        scan_id: str,
        error: str,
    ) -> Dict[str, Any]:
        """Build an error response for failed scans."""
        return {
            "scan_id": scan_id,
            "status": "ERROR",
            "prediction": "UNKNOWN",
            "risk_score": 0,
            "confidence": 0.0,
            "severity": "NONE",
            "decoded_payload": None,
            "payload_type": None,
            "final_url": None,
            "redirect_chain": [],
            "reasons": [f"Scan error: {error}"],
            "fake_payment_detected": False,
            "is_shortened_url": False,
            "qr_count": 0,
            "all_results": [],
        }

    async def batch_scan(
        self,
        images: List[bytes],
        use_ml_model: bool = True,
        follow_redirects: bool = True,
    ) -> Dict[str, Any]:
        """
        Scan multiple QR code images concurrently.

        Args:
            images: List of raw image bytes.
            use_ml_model: Whether to use the URL AI model.
            follow_redirects: Whether to follow redirects.

        Returns:
            Batch scan result dictionary.
        """
        start = time.time()
        tasks = [
            self.scan_image(
                img,
                use_ml_model=use_ml_model,
                follow_redirects=follow_redirects,
            )
            for img in images
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed: List[Dict[str, Any]] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append(self._build_error_result(
                    scan_id=QRSecurityUtils.generate_scan_id(),
                    error=str(result),
                ))
            else:
                processed.append(result)

        total_blocked = sum(1 for r in processed if r.get("status") == "BLOCKED")
        total_time = round((time.time() - start) * 1000, 2)

        return {
            "total_scanned": len(images),
            "total_blocked": total_blocked,
            "total_allowed": len(images) - total_blocked,
            "processing_time_ms": total_time,
            "results": processed,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Return engine statistics."""
        uptime = time.time() - self._start_time
        return {
            "total_scans": self._scan_count,
            "total_blocked": self._block_count,
            "block_rate": (
                round(self._block_count / self._scan_count * 100, 2)
                if self._scan_count > 0 else 0.0
            ),
            "uptime_seconds": round(uptime, 2),
        }


# Module-level singleton
qr_risk_engine = QRRiskEngine()
