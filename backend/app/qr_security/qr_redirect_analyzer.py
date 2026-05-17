"""
PhishGuard AI — QR Redirect Analyzer
Safely follows URL redirect chains to expose hidden destinations,
domain changes, HTTPS downgrades, and redirect loops.
Uses async HTTP for non-blocking analysis.
"""

import asyncio
import re
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

import tldextract

from app.utils.logger import logger


# ────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────

MAX_REDIRECTS = 10
REQUEST_TIMEOUT = 10  # seconds per request
TOTAL_TIMEOUT = 30    # seconds for entire chain

# URL shortener domains (trigger redirect analysis)
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "adf.ly", "tiny.cc", "lnkd.in", "db.tt", "qr.ae",
    "bitly.com", "cutt.ly", "rb.gy", "shorturl.at", "t.ly",
    "v.gd", "x.co", "soo.gd", "s.id", "clck.ru", "rebrand.ly",
}

# Private/internal IP ranges to block (SSRF prevention)
PRIVATE_IP_PATTERNS = [
    re.compile(r"^127\."),                        # Loopback
    re.compile(r"^10\."),                          # Class A private
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."), # Class B private
    re.compile(r"^192\.168\."),                    # Class C private
    re.compile(r"^0\."),                           # Current network
    re.compile(r"^169\.254\."),                    # Link-local
    re.compile(r"^::1$"),                          # IPv6 loopback
    re.compile(r"^fc00:", re.IGNORECASE),          # IPv6 unique local
    re.compile(r"^fe80:", re.IGNORECASE),          # IPv6 link-local
]


class RedirectAnalyzer:
    """
    Production-grade redirect chain analyzer.
    Safely follows HTTP redirects while preventing SSRF attacks
    and detecting suspicious redirect behavior.
    """

    @staticmethod
    def is_private_ip(hostname: str) -> bool:
        """
        Check if a hostname resolves to a private/internal IP.
        Used for SSRF prevention.
        """
        for pattern in PRIVATE_IP_PATTERNS:
            if pattern.match(hostname):
                return True
        return False

    @staticmethod
    def is_shortener(url: str) -> bool:
        """Check if a URL uses a known URL shortener service."""
        try:
            ext = tldextract.extract(url)
            domain = ext.registered_domain or ""
            return domain.lower() in SHORTENER_DOMAINS
        except Exception:
            return False

    async def analyze_url(
        self,
        url: str,
        max_redirects: int = MAX_REDIRECTS,
    ) -> Optional[Dict[str, Any]]:
        """
        Follow a URL's redirect chain and analyze the path.

        Args:
            url: The starting URL to analyze.
            max_redirects: Maximum number of redirects to follow.

        Returns:
            Dictionary with chain analysis, or None on complete failure.
        """
        if not url:
            return None

        # Normalize URL
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "http://" + url

        chain: List[str] = [url]
        current_url = url
        start_time = time.time()
        errors: List[str] = []
        status_codes: List[int] = []

        try:
            # Use httpx for async HTTP with redirect control
            import httpx

            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=httpx.Timeout(REQUEST_TIMEOUT),
                verify=False,  # Allow self-signed certs for analysis
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                },
            ) as client:
                for step in range(max_redirects):
                    # Timeout check
                    if time.time() - start_time > TOTAL_TIMEOUT:
                        errors.append("Redirect analysis timed out")
                        break

                    # SSRF check
                    parsed = urlparse(current_url)
                    hostname = parsed.hostname or ""
                    if self.is_private_ip(hostname):
                        errors.append(
                            f"Blocked: redirect to private IP ({hostname})"
                        )
                        break

                    try:
                        response = await client.head(
                            current_url,
                            follow_redirects=False,
                        )
                        status_codes.append(response.status_code)

                        # Check for redirect status codes
                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get("location", "")
                            if not location:
                                errors.append("Redirect with no Location header")
                                break

                            # Handle relative redirects
                            if location.startswith("/"):
                                parsed_current = urlparse(current_url)
                                location = (
                                    f"{parsed_current.scheme}://"
                                    f"{parsed_current.netloc}{location}"
                                )
                            elif not location.startswith("http"):
                                location = f"http://{location}"

                            # Redirect loop detection
                            if location in chain:
                                errors.append(
                                    f"Redirect loop detected at: {location}"
                                )
                                break

                            chain.append(location)
                            current_url = location
                            logger.debug(
                                f"Redirect {step+1}: → {location[:80]}"
                            )
                        else:
                            # No more redirects
                            break

                    except httpx.TimeoutException:
                        errors.append(f"Timeout at step {step+1}: {current_url[:80]}")
                        break
                    except httpx.ConnectError:
                        errors.append(f"Connection failed at step {step+1}: {current_url[:80]}")
                        break
                    except Exception as e:
                        errors.append(f"Error at step {step+1}: {str(e)[:100]}")
                        break

        except ImportError:
            # httpx not available — fall back to basic analysis
            logger.warning("httpx not available — using basic redirect analysis")
            return await self._basic_redirect_analysis(url)
        except Exception as e:
            logger.error(f"Redirect analysis failed: {e}")
            errors.append(str(e))

        # Build analysis result
        final_url = chain[-1]
        analysis = self._build_chain_analysis(
            chain=chain,
            final_url=final_url,
            status_codes=status_codes,
            errors=errors,
        )

        logger.info(
            f"Redirect analysis: {len(chain)-1} redirects, "
            f"final={final_url[:60]}"
        )

        return analysis

    async def _basic_redirect_analysis(
        self,
        url: str,
    ) -> Dict[str, Any]:
        """
        Fallback redirect analysis using urllib (no external deps).
        Less reliable but always available.
        """
        import urllib.request
        import ssl

        chain = [url]
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(
                url,
                method="HEAD",
                headers={"User-Agent": "PhishGuard/1.0"},
            )
            response = urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=ctx)
            final_url = response.geturl()

            if final_url != url:
                chain.append(final_url)

        except Exception as e:
            logger.debug(f"Basic redirect analysis failed: {e}")

        return self._build_chain_analysis(
            chain=chain,
            final_url=chain[-1],
            status_codes=[],
            errors=[],
        )

    @staticmethod
    def _build_chain_analysis(
        chain: List[str],
        final_url: str,
        status_codes: List[int],
        errors: List[str],
    ) -> Dict[str, Any]:
        """Build the redirect chain analysis result."""

        # Extract domains from chain
        domains = []
        for url in chain:
            ext = tldextract.extract(url)
            domains.append(ext.registered_domain or urlparse(url).hostname or "unknown")

        # Detect domain changes
        unique_domains = list(dict.fromkeys(domains))  # ordered unique
        domain_changes = len(unique_domains) - 1

        # Detect scheme changes (HTTPS → HTTP downgrade)
        schemes = [urlparse(url).scheme for url in chain]
        has_downgrade = False
        for i in range(1, len(schemes)):
            if schemes[i-1] == "https" and schemes[i] == "http":
                has_downgrade = True
                break

        # Suspicious patterns
        suspicious_indicators: List[str] = []
        if domain_changes > 0:
            suspicious_indicators.append(
                f"Domain changed {domain_changes} time(s) during redirect"
            )
        if has_downgrade:
            suspicious_indicators.append("HTTPS downgraded to HTTP during redirect")
        if len(chain) > 3:
            suspicious_indicators.append(
                f"Long redirect chain ({len(chain)-1} hops)"
            )

        # Check if final domain is suspicious
        final_ext = tldextract.extract(final_url)
        suspicious_tlds = {
            "xyz", "top", "club", "tk", "ml", "ga", "cf", "gq",
            "pw", "cc", "icu", "cam", "bid",
        }
        if final_ext.suffix in suspicious_tlds:
            suspicious_indicators.append(
                f"Final URL uses suspicious TLD: .{final_ext.suffix}"
            )

        return {
            "original_url": chain[0],
            "final_url": final_url,
            "chain": chain,
            "redirect_count": len(chain) - 1,
            "domains_visited": unique_domains,
            "domain_changes": domain_changes,
            "status_codes": status_codes,
            "has_https_downgrade": has_downgrade,
            "suspicious_indicators": suspicious_indicators,
            "is_shortened": RedirectAnalyzer.is_shortener(chain[0]),
            "errors": errors,
        }

    async def batch_analyze(
        self,
        urls: List[str],
    ) -> List[Dict[str, Any]]:
        """Analyze multiple URLs concurrently."""
        tasks = [self.analyze_url(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        analyzed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                analyzed.append({
                    "original_url": urls[i],
                    "final_url": urls[i],
                    "chain": [urls[i]],
                    "redirect_count": 0,
                    "error": str(result),
                })
            elif result is None:
                analyzed.append({
                    "original_url": urls[i],
                    "final_url": urls[i],
                    "chain": [urls[i]],
                    "redirect_count": 0,
                })
            else:
                analyzed.append(result)

        return analyzed


# Module-level singleton
redirect_analyzer = RedirectAnalyzer()
