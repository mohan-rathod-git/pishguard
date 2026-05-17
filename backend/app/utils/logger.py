"""
PhishGuard AI — Logging Utility
Structured logging using loguru with file rotation and console output.
"""

import sys
import os
from loguru import logger


def setup_logging(log_level: str = "INFO", log_file: str = "logs/phishguard.log") -> None:
    """Configure application-wide logging with loguru."""

    # Remove default handler
    logger.remove()

    # ── Console handler (colourised) ──
    logger.add(
        sys.stderr,
        level=log_level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> — "
            "<level>{message}</level>"
        ),
        colorize=True,
    )

    # ── File handler (rotation + compression) ──
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logger.add(
        log_file,
        level=log_level,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} — {message}",
        rotation="10 MB",
        retention="30 days",
        compression="zip",
        enqueue=True,  # thread-safe
    )

    logger.info(f"Logging initialised — level={log_level}, file={log_file}")


# Export the pre-configured logger for direct import
__all__ = ["logger", "setup_logging"]
