"""
PhishGuard AI — QR Sandbox Scanner
Isolated headless browser sandbox for inspecting suspicious URLs
extracted from QR codes. Detects drive-by downloads, malicious scripts,
popup behavior, and hidden redirects.

OPTIONAL: Requires Playwright or Selenium to be installed.
Falls back gracefully when neither is available.
"""

import asyncio
import time
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from app.utils.logger import logger


# ────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────

SANDBOX_TIMEOUT = 15  # seconds per URL
MAX_CONCURRENT_SANDBOXES = 3

# Dangerous download MIME types
DANGEROUS_MIMES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-executable",
    "application/vnd.android.package-archive",
    "application/java-archive",
    "application/x-shockwave-flash",
    "application/x-msdos-program",
}

# Dangerous file extensions in download URLs
DANGEROUS_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs",
    ".apk", ".jar", ".scr", ".pif", ".com",
    ".dmg", ".deb", ".rpm", ".sh",
}

# Suspicious JavaScript patterns
SUSPICIOUS_JS_PATTERNS = [
    r"document\.cookie",
    r"window\.location\s*=",
    r"document\.location\s*=",
    r"eval\s*\(",
    r"atob\s*\(",
    r"String\.fromCharCode",
    r"XMLHttpRequest",
    r"fetch\s*\(",
    r"navigator\.sendBeacon",
    r"\.submit\(\)",
    r"createElement\(['\"]script['\"]\)",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write",
]


class SandboxResult:
    """Result from a sandbox inspection."""

    def __init__(self) -> None:
        self.url: str = ""
        self.final_url: str = ""
        self.status_code: int = 0
        self.page_title: str = ""
        self.redirects: List[str] = []
        self.downloads_triggered: List[Dict[str, str]] = []
        self.suspicious_scripts: List[str] = []
        self.forms_detected: int = 0
        self.password_fields: int = 0
        self.popups_detected: int = 0
        self.errors: List[str] = []
        self.scan_time_ms: float = 0
        self.risk_signals: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "page_title": self.page_title,
            "redirects": self.redirects,
            "downloads_triggered": self.downloads_triggered,
            "suspicious_scripts": self.suspicious_scripts,
            "forms_detected": self.forms_detected,
            "password_fields": self.password_fields,
            "popups_detected": self.popups_detected,
            "risk_signals": self.risk_signals,
            "errors": self.errors,
            "scan_time_ms": self.scan_time_ms,
        }


class QRSandbox:
    """
    Isolated sandbox for inspecting suspicious URLs in a headless browser.
    Uses Playwright when available, otherwise falls back to basic HTTP inspection.

    Security measures:
    - Isolated browser context (no persistent state)
    - Blocked downloads
    - Network interception for monitoring
    - JavaScript analysis
    - Timeout enforcement
    """

    def __init__(self) -> None:
        self._playwright_available: Optional[bool] = None
        self._scan_count: int = 0

    async def _check_playwright(self) -> bool:
        """Check if Playwright is available."""
        if self._playwright_available is not None:
            return self._playwright_available

        try:
            from playwright.async_api import async_playwright
            self._playwright_available = True
            logger.info("Playwright sandbox available")
        except ImportError:
            self._playwright_available = False
            logger.info(
                "Playwright not installed — sandbox will use basic HTTP inspection"
            )
        return self._playwright_available

    async def inspect_url(self, url: str) -> SandboxResult:
        """
        Inspect a URL in an isolated sandbox environment.

        Args:
            url: The URL to inspect.

        Returns:
            SandboxResult with inspection findings.
        """
        self._scan_count += 1
        result = SandboxResult()
        result.url = url

        if not url or not re.match(r"^https?://", url, re.IGNORECASE):
            result.errors.append("Invalid URL for sandbox inspection")
            return result

        start = time.time()

        if await self._check_playwright():
            try:
                result = await asyncio.wait_for(
                    self._inspect_with_playwright(url),
                    timeout=SANDBOX_TIMEOUT + 5,
                )
            except asyncio.TimeoutError:
                result.errors.append("Sandbox inspection timed out")
            except Exception as e:
                result.errors.append(f"Playwright error: {str(e)[:200]}")
                logger.error(f"Sandbox Playwright error: {e}")
        else:
            result = await self._inspect_with_httpx(url)

        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        return result

    async def _inspect_with_playwright(self, url: str) -> SandboxResult:
        """Full sandbox inspection using Playwright headless browser."""
        from playwright.async_api import async_playwright

        result = SandboxResult()
        result.url = url

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--single-process",
                ],
            )

            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                java_script_enabled=True,
                accept_downloads=False,
            )

            page = await context.new_page()

            # Track redirects
            redirects: List[str] = []
            downloads: List[Dict[str, str]] = []
            popups: int = 0

            # Event handlers
            page.on("request", lambda req: redirects.append(req.url))

            async def handle_download(download):
                downloads.append({
                    "filename": download.suggested_filename,
                    "url": download.url,
                })

            page.on("download", handle_download)

            async def handle_popup(popup_page):
                nonlocal popups
                popups += 1

            page.on("popup", handle_popup)

            try:
                response = await page.goto(
                    url,
                    timeout=SANDBOX_TIMEOUT * 1000,
                    wait_until="domcontentloaded",
                )

                if response:
                    result.status_code = response.status
                    result.final_url = page.url
                else:
                    result.final_url = url

                # Wait for dynamic content
                await page.wait_for_timeout(2000)

                # Get page title
                result.page_title = await page.title() or ""

                # Count forms and password fields
                result.forms_detected = await page.locator("form").count()
                result.password_fields = await page.locator(
                    "input[type='password']"
                ).count()

                # Extract and analyze inline scripts
                scripts = await page.evaluate("""
                    () => {
                        const scripts = document.querySelectorAll('script');
                        return Array.from(scripts).map(s => s.textContent || '').filter(s => s.length > 0);
                    }
                """)

                for script in scripts[:20]:  # Limit analysis
                    for pattern in SUSPICIOUS_JS_PATTERNS:
                        if re.search(pattern, script, re.IGNORECASE):
                            result.suspicious_scripts.append(pattern)
                            break

                result.redirects = list(dict.fromkeys(redirects))[:20]
                result.downloads_triggered = downloads
                result.popups_detected = popups

                # Generate risk signals
                result.risk_signals = self._analyze_sandbox_result(result)

            except Exception as e:
                result.errors.append(f"Page load error: {str(e)[:200]}")

            finally:
                await context.close()
                await browser.close()

        return result

    async def _inspect_with_httpx(self, url: str) -> SandboxResult:
        """Basic HTTP inspection fallback when Playwright is not available."""
        result = SandboxResult()
        result.url = url

        try:
            import httpx

            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=httpx.Timeout(10.0),
                verify=False,
                headers={"User-Agent": "PhishGuard/1.0"},
            ) as client:
                response = await client.get(url)
                result.status_code = response.status_code
                result.final_url = str(response.url)

                # Basic content analysis
                content = response.text[:50000]  # Limit analysis
                content_lower = content.lower()

                # Count forms and password fields
                result.forms_detected = content_lower.count("<form")
                result.password_fields = content_lower.count("type=\"password\"")
                result.password_fields += content_lower.count("type='password'")

                # Title extraction
                title_match = re.search(
                    r"<title[^>]*>([^<]+)</title>", content, re.IGNORECASE
                )
                if title_match:
                    result.page_title = title_match.group(1).strip()

                # Script analysis
                for pattern in SUSPICIOUS_JS_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        result.suspicious_scripts.append(pattern)

                # Track redirects from response history
                result.redirects = [
                    str(r.url) for r in response.history
                ]

                result.risk_signals = self._analyze_sandbox_result(result)

        except ImportError:
            result.errors.append("httpx not available for basic inspection")
        except Exception as e:
            result.errors.append(f"HTTP inspection error: {str(e)[:200]}")

        return result

    @staticmethod
    def _analyze_sandbox_result(result: SandboxResult) -> List[str]:
        """Analyze sandbox findings and generate risk signals."""
        signals: List[str] = []

        if result.downloads_triggered:
            for dl in result.downloads_triggered:
                filename = dl.get("filename", "")
                ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                if ext in DANGEROUS_EXTENSIONS:
                    signals.append(
                        f"Dangerous file download triggered: {filename}"
                    )
                else:
                    signals.append(f"Download triggered: {filename}")

        if result.suspicious_scripts:
            signals.append(
                f"Suspicious JavaScript detected: "
                f"{len(result.suspicious_scripts)} pattern(s)"
            )

        if result.password_fields > 0:
            signals.append(
                f"Login form detected ({result.password_fields} password field(s))"
            )

        if result.popups_detected > 0:
            signals.append(f"Popup windows detected: {result.popups_detected}")

        if len(result.redirects) > 3:
            signals.append(
                f"Multiple redirects observed: {len(result.redirects)}"
            )

        if result.final_url and result.url:
            original_domain = urlparse(result.url).hostname or ""
            final_domain = urlparse(result.final_url).hostname or ""
            if original_domain != final_domain:
                signals.append(
                    f"Domain changed: {original_domain} → {final_domain}"
                )

        return signals

    def get_stats(self) -> Dict[str, Any]:
        """Return sandbox statistics."""
        return {
            "total_inspections": self._scan_count,
            "playwright_available": self._playwright_available or False,
        }


# Module-level singleton
qr_sandbox = QRSandbox()
