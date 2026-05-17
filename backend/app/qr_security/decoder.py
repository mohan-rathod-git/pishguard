"""
PhishGuard AI — QR Code Decoder
Safely decodes QR codes from uploaded images using OpenCV + pyzbar.
Supports PNG, JPG, JPEG, BMP, and WEBP formats.
"""

import io
import base64
import re
from typing import List, Optional, Dict, Any

import cv2
import numpy as np
from PIL import Image

from app.utils.logger import logger

# Try importing pyzbar, with fallback to OpenCV native detector if DLLs are missing
try:
    from pyzbar.pyzbar import decode as pyzbar_decode, ZBarSymbol
    PYZBAR_AVAILABLE = True
except Exception as e:
    logger.warning(f"Could not load pyzbar (missing libiconv or DLLs). Falling back to OpenCV native QR decoder only. Error: {e}")
    pyzbar_decode = None
    ZBarSymbol = None
    PYZBAR_AVAILABLE = False



# ── Constants ──
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
ALLOWED_MIME_TYPES = {
    "image/png", "image/jpeg", "image/jpg", "image/bmp", "image/webp",
}
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp"}


class QRDecodeResult:
    """Represents a single decoded QR code payload."""

    def __init__(
        self,
        raw_data: bytes,
        decoded_text: str,
        qr_type: str,
        rect: Dict[str, int],
        polygon: List[Dict[str, int]],
    ) -> None:
        self.raw_data = raw_data
        self.decoded_text = decoded_text
        self.qr_type = qr_type  # e.g. "QRCODE", "EAN13"
        self.rect = rect
        self.polygon = polygon

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decoded_text": self.decoded_text,
            "qr_type": self.qr_type,
            "payload_length": len(self.decoded_text),
            "rect": self.rect,
        }


class QRDecoder:
    """
    Production QR decoder with multiple fallback strategies.
    Uses pyzbar as primary decoder, OpenCV as fallback.
    """

    @staticmethod
    def validate_image_bytes(data: bytes) -> None:
        """Validate image data before processing."""
        if not data:
            raise ValueError("Image data is empty")

        if len(data) > MAX_IMAGE_SIZE_BYTES:
            raise ValueError(
                f"Image exceeds maximum size of {MAX_IMAGE_SIZE_BYTES // (1024*1024)} MB"
            )

        # Check magic bytes for image formats
        magic_signatures = {
            b"\x89PNG": "PNG",
            b"\xff\xd8\xff": "JPEG",
            b"BM": "BMP",
            b"RIFF": "WEBP",
        }
        matched = False
        for sig, fmt in magic_signatures.items():
            if data[:len(sig)] == sig:
                matched = True
                break

        if not matched:
            raise ValueError(
                "Unsupported image format. Accepted: PNG, JPEG, BMP, WEBP"
            )

    @staticmethod
    def bytes_to_cv2(data: bytes) -> np.ndarray:
        """Convert raw bytes to OpenCV image array."""
        nparr = np.frombuffer(data, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError("Failed to decode image — file may be corrupted")
        return img

    @staticmethod
    def base64_to_bytes(b64_string: str) -> bytes:
        """Decode a base64 image string (with or without data URI prefix)."""
        # Strip data URI prefix if present
        if "," in b64_string:
            b64_string = b64_string.split(",", 1)[1]
        # Strip whitespace
        b64_string = b64_string.strip()
        try:
            return base64.b64decode(b64_string)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {e}")

    @staticmethod
    def preprocess_image(img: np.ndarray) -> List[np.ndarray]:
        """
        Generate multiple preprocessed versions of the image
        to maximize QR detection across different lighting/quality.
        """
        versions = [img]

        # Grayscale
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        versions.append(cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR))

        # Adaptive threshold
        thresh = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY, 11, 2
        )
        versions.append(cv2.cvtColor(thresh, cv2.COLOR_GRAY2BGR))

        # CLAHE (Contrast Limited Adaptive Histogram Equalization)
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        versions.append(cv2.cvtColor(enhanced, cv2.COLOR_GRAY2BGR))

        # Sharpened
        kernel = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]])
        sharpened = cv2.filter2D(gray, -1, kernel)
        versions.append(cv2.cvtColor(sharpened, cv2.COLOR_GRAY2BGR))

        return versions

    def decode_image(self, image_data: bytes) -> List[QRDecodeResult]:
        """
        Decode all QR codes found in an image.

        Args:
            image_data: Raw image bytes

        Returns:
            List of QRDecodeResult objects
        """
        self.validate_image_bytes(image_data)
        img = self.bytes_to_cv2(image_data)

        results: List[QRDecodeResult] = []
        seen_payloads: set = set()

        # Try multiple preprocessing strategies
        image_versions = self.preprocess_image(img)

        for version in image_versions:
            if not PYZBAR_AVAILABLE:
                break
            try:
                decoded_list = pyzbar_decode(version, symbols=[ZBarSymbol.QRCODE])
                for obj in decoded_list:
                    text = obj.data.decode("utf-8", errors="replace")
                    if text in seen_payloads:
                        continue
                    seen_payloads.add(text)

                    rect = obj.rect
                    polygon = [
                        {"x": int(p.x), "y": int(p.y)}
                        for p in obj.polygon
                    ] if obj.polygon else []

                    results.append(QRDecodeResult(
                        raw_data=obj.data,
                        decoded_text=text,
                        qr_type=obj.type,
                        rect={
                            "x": int(rect.left),
                            "y": int(rect.top),
                            "width": int(rect.width),
                            "height": int(rect.height),
                        },
                        polygon=polygon,
                    ))
            except Exception as e:
                logger.debug(f"pyzbar decode attempt failed: {e}")
                continue

        # Fallback: OpenCV QR decoder
        if not results:
            try:
                detector = cv2.QRCodeDetector()
                data, vertices, _ = detector.detectAndDecode(img)
                if data:
                    results.append(QRDecodeResult(
                        raw_data=data.encode("utf-8"),
                        decoded_text=data,
                        qr_type="QRCODE",
                        rect={"x": 0, "y": 0, "width": 0, "height": 0},
                        polygon=[],
                    ))
            except Exception as e:
                logger.debug(f"OpenCV QR detector fallback failed: {e}")

        if results:
            logger.info(f"Decoded {len(results)} QR code(s) from image")
        else:
            logger.warning("No QR codes detected in image")

        return results

    def decode_base64(self, b64_string: str) -> List[QRDecodeResult]:
        """Decode QR codes from a base64-encoded image."""
        image_bytes = self.base64_to_bytes(b64_string)
        return self.decode_image(image_bytes)


# Module-level singleton
qr_decoder = QRDecoder()
