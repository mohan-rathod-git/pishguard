"""
PhishGuard AI — QR Security API Routes
Endpoints for QR code scanning, batch processing, and health checks.

Endpoints:
    POST /qr/scan          — Scan a single QR code image
    POST /qr/batch_scan    — Scan multiple QR code images
    GET  /qr/health        — QR engine health check
"""

import base64
from typing import List

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import settings
from app.utils.logger import logger
from app.qr_security.qr_risk_engine import qr_risk_engine
from app.qr_security.qr_utils import QRSecurityUtils
from app.qr_security.qr_blocker import qr_blocker
from app.qr_security.qr_sandbox import qr_sandbox
from app.qr_security.qr_schemas import (
    QRScanBase64Request,
    QRScanResponse,
    QRBatchScanResponse,
    QRHealthResponse,
)
from app.api.schemas import ErrorResponse


# ── Router ──
qr_router = APIRouter(prefix="/qr", tags=["QR Security"])

# ── Rate limiter ──
qr_limiter = Limiter(key_func=get_remote_address)

# ── Constants ──
MAX_BATCH_SIZE = 10
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB


# ─────────────────────────────────────────────
# POST /qr/scan — Single QR scan (file upload)
# ─────────────────────────────────────────────

@qr_router.post(
    "/scan",
    response_model=QRScanResponse,
    responses={
        400: {"model": ErrorResponse},
        413: {"model": ErrorResponse},
        422: {"model": ErrorResponse},
    },
    summary="Scan a QR code image for threats",
    description=(
        "Upload a QR code image (PNG, JPEG, BMP, WEBP) or provide a base64-encoded image. "
        "The engine will decode the QR, extract URLs, analyze redirect chains, "
        "run the URL AI model, and return a threat assessment with block/allow decision."
    ),
)
@qr_limiter.limit(settings.RATE_LIMIT)
async def scan_qr_image(
    request: Request,
    file: UploadFile = File(None),
    image_base64: str = Form(None),
    follow_redirects: bool = Form(True),
    use_ml_model: bool = Form(True),
):
    """
    Scan a single QR code image for malicious content.

    Accepts either:
    - File upload (multipart/form-data)
    - Base64-encoded image string

    Returns a complete threat analysis with BLOCKED/ALLOWED status.
    """
    image_data: bytes

    # ── Determine input source ──
    if file is not None:
        # File upload
        content_type = file.content_type or ""
        filename = file.filename or ""

        # Read image bytes
        image_data = await file.read()

        if not image_data:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        # Validate image
        is_valid, error = QRSecurityUtils.validate_image(
            data=image_data,
            filename=filename,
            content_type=content_type,
        )
        if not is_valid:
            raise HTTPException(status_code=400, detail=error)

        logger.info(
            f"QR scan request: file={filename}, "
            f"size={len(image_data)} bytes, type={content_type}"
        )

    elif image_base64 is not None:
        # Base64 input
        try:
            from app.qr_security.decoder import QRDecoder
            image_data = QRDecoder.base64_to_bytes(image_base64)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        # Validate decoded image
        is_valid, error = QRSecurityUtils.validate_image(data=image_data)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error)

        logger.info(
            f"QR scan request: base64 input, size={len(image_data)} bytes"
        )

    else:
        raise HTTPException(
            status_code=400,
            detail="No image provided. Upload a file or send base64-encoded image.",
        )

    # ── Run QR security pipeline ──
    try:
        result = await qr_risk_engine.scan_image(
            image_data=image_data,
            use_ml_model=use_ml_model,
            follow_redirects=follow_redirects,
        )

        # Sanitize payload in response
        if result.get("decoded_payload"):
            result["decoded_payload"] = QRSecurityUtils.sanitize_payload_for_response(
                result["decoded_payload"]
            )

        logger.info(
            f"QR scan complete: {result.get('status')} | "
            f"{result.get('prediction')} | risk={result.get('risk_score')} | "
            f"time={result.get('processing_time_ms')}ms"
        )

        return QRScanResponse(**result)

    except Exception as e:
        logger.error(f"QR scan pipeline error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"QR scan failed: {str(e)}",
        )


# ─────────────────────────────────────────────
# POST /qr/scan/base64 — Scan via JSON body
# ─────────────────────────────────────────────

@qr_router.post(
    "/scan/base64",
    response_model=QRScanResponse,
    responses={400: {"model": ErrorResponse}},
    summary="Scan a base64-encoded QR code image",
    description="Alternative endpoint accepting base64 image via JSON body.",
)
@qr_limiter.limit(settings.RATE_LIMIT)
async def scan_qr_base64(
    request: Request,
    body: QRScanBase64Request,
):
    """Scan a QR code from a base64-encoded image (JSON body)."""
    try:
        from app.qr_security.decoder import QRDecoder
        image_data = QRDecoder.base64_to_bytes(body.image_base64)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    is_valid, error = QRSecurityUtils.validate_image(data=image_data)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)

    try:
        result = await qr_risk_engine.scan_image(
            image_data=image_data,
            use_ml_model=body.use_ml_model,
            follow_redirects=body.follow_redirects,
        )

        if result.get("decoded_payload"):
            result["decoded_payload"] = QRSecurityUtils.sanitize_payload_for_response(
                result["decoded_payload"]
            )

        return QRScanResponse(**result)

    except Exception as e:
        logger.error(f"QR base64 scan error: {e}")
        raise HTTPException(status_code=500, detail=f"QR scan failed: {str(e)}")


# ─────────────────────────────────────────────
# POST /qr/batch_scan — Batch QR scanning
# ─────────────────────────────────────────────

@qr_router.post(
    "/batch_scan",
    response_model=QRBatchScanResponse,
    responses={400: {"model": ErrorResponse}},
    summary="Scan multiple QR code images",
    description=f"Upload up to {MAX_BATCH_SIZE} QR code images for batch analysis.",
)
@qr_limiter.limit(settings.RATE_LIMIT)
async def batch_scan_qr(
    request: Request,
    files: List[UploadFile] = File(...),
    follow_redirects: bool = Form(True),
    use_ml_model: bool = Form(True),
):
    """
    Scan multiple QR code images in a single request.
    Maximum of 10 images per batch.
    """
    if len(files) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum batch size is {MAX_BATCH_SIZE} images",
        )

    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    # Read and validate all images
    images: List[bytes] = []
    for idx, file in enumerate(files):
        data = await file.read()

        is_valid, error = QRSecurityUtils.validate_image(
            data=data,
            filename=file.filename,
            content_type=file.content_type,
        )
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Image {idx+1} ({file.filename}): {error}",
            )
        images.append(data)

    logger.info(f"QR batch scan: {len(images)} images")

    try:
        batch_result = await qr_risk_engine.batch_scan(
            images=images,
            use_ml_model=use_ml_model,
            follow_redirects=follow_redirects,
        )

        # Sanitize payloads in all results
        for result in batch_result.get("results", []):
            if result.get("decoded_payload"):
                result["decoded_payload"] = (
                    QRSecurityUtils.sanitize_payload_for_response(
                        result["decoded_payload"]
                    )
                )

        return QRBatchScanResponse(**batch_result)

    except Exception as e:
        logger.error(f"QR batch scan error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Batch scan failed: {str(e)}"
        )


# ─────────────────────────────────────────────
# GET /qr/health — QR engine health check
# ─────────────────────────────────────────────

@qr_router.get(
    "/health",
    response_model=QRHealthResponse,
    summary="QR security engine health check",
    description="Returns the status of the QR scanning engine and its components.",
)
async def qr_health_check():
    """Check QR security engine health and component status."""
    try:
        from app.ml.predictor import predictor

        engine_stats = qr_risk_engine.get_stats()
        blocker_stats = qr_blocker.get_stats()
        sandbox_stats = qr_sandbox.get_stats()

        return QRHealthResponse(
            status="healthy",
            qr_engine_active=True,
            ml_model_loaded=predictor.model_loaded,
            total_scans=engine_stats["total_scans"],
            total_blocked=engine_stats["total_blocked"],
            block_rate=engine_stats["block_rate"],
            blocking_threshold=blocker_stats["risk_threshold"],
            sandbox_available=sandbox_stats["playwright_available"],
            uptime_seconds=engine_stats["uptime_seconds"],
        )
    except Exception as e:
        logger.error(f"QR health check error: {e}")
        return QRHealthResponse(
            status="degraded",
            qr_engine_active=False,
            ml_model_loaded=False,
            total_scans=0,
            total_blocked=0,
            block_rate=0.0,
            blocking_threshold=60,
            sandbox_available=False,
            uptime_seconds=0.0,
        )
