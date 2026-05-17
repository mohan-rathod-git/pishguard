"""
PhishGuard AI — Main Application Entry Point
Production FastAPI application with CORS, rate limiting, and model loading.
"""

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.utils.logger import logger, setup_logging
from app.api.routes import router, limiter
from app.ml.predictor import predictor
from app.qr_security.qr_routes import qr_router, qr_limiter


# ─────────────────────────────────────────────
# Lifespan (startup / shutdown)
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler — runs on startup and shutdown."""
    # ── Startup ──
    setup_logging(settings.LOG_LEVEL, settings.LOG_FILE)
    logger.info("=" * 60)
    logger.info(f"  🛡️  {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"  Environment: {settings.APP_ENV}")
    logger.info("=" * 60)

    # Load the ML model
    loaded = predictor.load_model()
    if loaded:
        info = predictor.get_model_info()
        logger.info(f"  Model: {info.get('model_type', 'Unknown')}")
        logger.info(f"  Features: {info.get('feature_count', 0)}")
        logger.info("  ✅ Model ready for inference")
    else:
        logger.warning("  ⚠️  No trained model found — run training first:")
        logger.warning("     python -m app.training.train_model")

    # Initialize QR Security Engine
    logger.info("  🔍 QR Security Engine: ACTIVE")
    logger.info("  📡 QR endpoints: /api/v1/qr/scan, /api/v1/qr/batch_scan, /api/v1/qr/health")

    logger.info(f"  API running on http://{settings.API_HOST}:{settings.API_PORT}")
    logger.info("=" * 60)

    yield  # Application runs here

    # ── Shutdown ──
    logger.info("Shutting down PhishGuard AI...")


# ─────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "🛡️ PhishGuard AI — Production-grade AI-powered cybersecurity API. "
        "Detects phishing, spam, malware, and scam URLs using XGBoost "
        "machine learning with 25+ URL features and explainable AI."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Rate Limiter ──
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Routes ──
app.include_router(router, prefix="/api/v1")

# ── QR Security Routes ──
app.include_router(qr_router, prefix="/api/v1")


# ── Root endpoint ──
@app.get("/", tags=["Root"])
async def root():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/api/v1/health",
        "qr_scan": "/api/v1/qr/scan",
        "qr_health": "/api/v1/qr/health",
    }


# ─────────────────────────────────────────────
# Run directly
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        workers=1 if settings.DEBUG else settings.API_WORKERS,
    )
