"""
PhishGuard AI — API Routes
Core endpoints for URL threat detection.
"""

import time
from typing import List

from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.api.schemas import (
    URLPredictRequest,
    BatchPredictRequest,
    PredictionResponse,
    BatchPredictionResponse,
    HealthResponse,
    ModelInfoResponse,
    ErrorResponse,
)
from app.ml.predictor import predictor
from app.utils.url_sanitizer import sanitize_url, validate_url
from app.utils.logger import logger
from app.config import settings

# ── Router ──
router = APIRouter()

# ── Rate limiter ──
limiter = Limiter(key_func=get_remote_address)

# ── App start time (set in main.py) ──
_start_time = time.time()


# ─────────────────────────────────────────────
# POST /predict — Single URL prediction
# ─────────────────────────────────────────────

@router.post(
    "/predict",
    response_model=PredictionResponse,
    responses={400: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    summary="Predict threat level for a single URL",
    description="Accepts a URL and returns a threat prediction with confidence, risk score, and explainable reasons.",
    tags=["Prediction"],
)
@limiter.limit(settings.RATE_LIMIT)
async def predict_url(request: Request, body: URLPredictRequest):
    """Analyze a single URL for phishing/malware/spam threats."""

    if not predictor.model_loaded:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please train the model first.",
        )

    # Sanitize
    clean_url = sanitize_url(body.url)

    # Validate
    is_valid, error = validate_url(clean_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)

    try:
        result = predictor.predict_url(clean_url)
        logger.info(
            f"Predicted {result['prediction']} (risk={result['risk_score']}) for: {clean_url[:80]}"
        )
        return PredictionResponse(**result)

    except Exception as e:
        logger.error(f"Prediction error for {clean_url[:80]}: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")


# ─────────────────────────────────────────────
# POST /batch_predict — Batch URL prediction
# ─────────────────────────────────────────────

@router.post(
    "/batch_predict",
    response_model=BatchPredictionResponse,
    responses={400: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
    summary="Predict threats for multiple URLs",
    description=f"Accepts up to {settings.MAX_BATCH_SIZE} URLs and returns predictions for each.",
    tags=["Prediction"],
)
@limiter.limit(settings.RATE_LIMIT)
async def batch_predict(request: Request, body: BatchPredictRequest):
    """Analyze a batch of URLs for threats."""

    if not predictor.model_loaded:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Please train the model first.",
        )

    if len(body.urls) > settings.MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum batch size is {settings.MAX_BATCH_SIZE} URLs",
        )

    results = []
    for url in body.urls:
        clean = sanitize_url(url)
        is_valid, error = validate_url(clean)
        if not is_valid:
            results.append({
                "url": url,
                "prediction": "ERROR",
                "confidence": 0.0,
                "risk_score": 0,
                "reasons": [f"Invalid URL: {error}"],
            })
            continue

        try:
            result = predictor.predict_url(clean)
            results.append(result)
        except Exception as e:
            results.append({
                "url": url,
                "prediction": "ERROR",
                "confidence": 0.0,
                "risk_score": 0,
                "reasons": [f"Prediction failed: {str(e)}"],
            })

    logger.info(f"Batch prediction completed: {len(results)} URLs processed")

    return BatchPredictionResponse(count=len(results), results=results)


# ─────────────────────────────────────────────
# GET /health — Health check
# ─────────────────────────────────────────────

@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns the current status of the PhishGuard API.",
    tags=["System"],
)
async def health_check():
    """Check API health and model status."""
    return HealthResponse(
        status="healthy",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        model_loaded=predictor.model_loaded,
        uptime_seconds=round(time.time() - _start_time, 2),
    )


# ─────────────────────────────────────────────
# GET /model-info — Model information
# ─────────────────────────────────────────────

@router.get(
    "/model-info",
    response_model=ModelInfoResponse,
    summary="Model metadata",
    description="Returns information about the loaded ML model.",
    tags=["System"],
)
async def model_info():
    """Get details about the currently loaded model."""
    if not predictor.model_loaded:
        raise HTTPException(
            status_code=503,
            detail="No model is currently loaded.",
        )
    info = predictor.get_model_info()
    return ModelInfoResponse(**info)
