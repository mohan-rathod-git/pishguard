"""
PhishGuard AI — ML Prediction Engine
Loads the trained model and provides inference methods.
"""

import os
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np

from app.config import settings
from app.utils.logger import logger
from app.utils.feature_extractor import (
    extract_features,
    extract_features_batch,
    get_feature_names,
)
from app.services.threat_scorer import ThreatScorer, LABEL_MAP
from app.services.reputation_service import reputation_service


class PhishGuardPredictor:
    """
    Production inference engine.
    Loads the trained XGBoost/RandomForest model and scaler,
    then provides single and batch prediction methods.
    """

    def __init__(self) -> None:
        self.model = None
        self.scaler = None
        self.feature_names: List[str] = get_feature_names()
        self.model_loaded: bool = False
        self.model_info: Dict = {}

    def load_model(self) -> bool:
        """Load the trained model and scaler from disk."""
        model_path = settings.MODEL_PATH
        scaler_path = settings.SCALER_PATH

        if not os.path.exists(model_path):
            logger.error(f"Model file not found: {model_path}")
            return False

        try:
            self.model = joblib.load(model_path)
            logger.info(f"Model loaded from {model_path}")

            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info(f"Scaler loaded from {scaler_path}")
            else:
                logger.warning("No scaler found — using raw features")

            self.model_loaded = True
            self.model_info = {
                "model_type": type(self.model).__name__,
                "model_version": settings.MODEL_VERSION,
                "feature_count": len(self.feature_names),
                "features": self.feature_names,
            }
            return True

        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False

    def _features_to_array(self, features: Dict[str, float]) -> np.ndarray:
        """Convert a feature dict to a numpy array in the correct feature order."""
        arr = np.array(
            [features.get(f, 0.0) for f in self.feature_names]
        ).reshape(1, -1)

        if self.scaler is not None:
            arr = self.scaler.transform(arr)
        return arr

    def predict_url(self, url: str) -> Dict:
        """
        Run full prediction pipeline on a single URL.
        Returns a verdict dictionary.
        """
        if not self.model_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        # Extract features
        features = extract_features(url)

        # ── Quick-path: check blacklist / whitelist ──
        import tldextract
        ext = tldextract.extract(url)
        domain = ext.registered_domain or ""

        if reputation_service.is_blacklisted(domain):
            return ThreatScorer.build_verdict(url, "PHISHING", 0.99, features)

        if reputation_service.is_whitelisted(domain):
            return ThreatScorer.build_verdict(url, "SAFE", 0.99, features)

        # ── Check cache ──
        cached = reputation_service.get_cached_score(domain)
        if cached is not None:
            label = "SAFE" if cached < 0.5 else "PHISHING"
            return ThreatScorer.build_verdict(url, label, abs(cached), features)

        # ── ML Prediction ──
        X = self._features_to_array(features)
        probabilities = self.model.predict_proba(X)[0]
        predicted_class = int(np.argmax(probabilities))
        confidence = float(probabilities[predicted_class])
        label = LABEL_MAP.get(predicted_class, "PHISHING")

        # Cache the result
        reputation_service.cache_score(domain, probabilities[0])  # prob of phishing

        return ThreatScorer.build_verdict(url, label, confidence, features)

    def predict_batch(self, urls: List[str]) -> List[Dict]:
        """Run prediction on a batch of URLs."""
        return [self.predict_url(url) for url in urls]

    def get_model_info(self) -> Dict:
        """Return model metadata."""
        return {
            **self.model_info,
            "loaded": self.model_loaded,
            **reputation_service.get_stats(),
        }


# Module-level singleton
predictor = PhishGuardPredictor()
