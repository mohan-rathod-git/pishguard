"""
PhishGuard AI — Blacklist & Whitelist Service
Domain reputation checking with in-memory caching.
"""

import os
import json
import time
from typing import Dict, Optional, Set
from pathlib import Path

from app.utils.logger import logger


class ReputationService:
    """
    Manages domain blacklists, whitelists, and a reputation cache.
    Provides fast lookups for known-good and known-bad domains.
    """

    def __init__(self, data_dir: str = "app/datasets") -> None:
        self._blacklist: Set[str] = set()
        self._whitelist: Set[str] = set()
        self._cache: Dict[str, Dict] = {}  # domain -> {score, ts}
        self._cache_ttl: int = 3600  # 1-hour TTL
        self._data_dir = Path(data_dir)

        self._load_lists()

    # ── List Loading ──

    def _load_lists(self) -> None:
        """Load blacklist/whitelist from JSON files if they exist."""
        bl_path = self._data_dir / "blacklist.json"
        wl_path = self._data_dir / "whitelist.json"

        if bl_path.exists():
            with open(bl_path, "r") as f:
                self._blacklist = set(json.load(f))
            logger.info(f"Loaded {len(self._blacklist)} domains into blacklist")
        else:
            # Seed with known phishing domains
            self._blacklist = {
                "phishing-example.com", "malware-site.xyz",
                "fake-login.tk", "scam-prize.club",
            }
            self._save_list(bl_path, self._blacklist)

        if wl_path.exists():
            with open(wl_path, "r") as f:
                self._whitelist = set(json.load(f))
            logger.info(f"Loaded {len(self._whitelist)} domains into whitelist")
        else:
            # Seed with trusted domains
            self._whitelist = {
                "google.com", "youtube.com", "facebook.com", "amazon.com",
                "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
                "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
                "reddit.com", "netflix.com", "whatsapp.com", "zoom.us",
                "cloudflare.com", "aws.amazon.com", "azure.microsoft.com",
            }
            self._save_list(wl_path, self._whitelist)

    def _save_list(self, path: Path, data: Set[str]) -> None:
        """Persist a list to disk."""
        os.makedirs(path.parent, exist_ok=True)
        with open(path, "w") as f:
            json.dump(sorted(data), f, indent=2)

    # ── Public API ──

    def is_blacklisted(self, domain: str) -> bool:
        """Check if a domain is in the blacklist."""
        return domain.lower() in self._blacklist

    def is_whitelisted(self, domain: str) -> bool:
        """Check if a domain is in the whitelist."""
        return domain.lower() in self._whitelist

    def add_to_blacklist(self, domain: str) -> None:
        """Add a domain to the blacklist and persist."""
        self._blacklist.add(domain.lower())
        self._save_list(self._data_dir / "blacklist.json", self._blacklist)
        logger.warning(f"Added {domain} to blacklist")

    def add_to_whitelist(self, domain: str) -> None:
        """Add a domain to the whitelist and persist."""
        self._whitelist.add(domain.lower())
        self._save_list(self._data_dir / "whitelist.json", self._whitelist)
        logger.info(f"Added {domain} to whitelist")

    # ── Reputation Cache ──

    def get_cached_score(self, domain: str) -> Optional[float]:
        """Get cached reputation score for a domain (None if expired / missing)."""
        entry = self._cache.get(domain.lower())
        if entry is None:
            return None
        if time.time() - entry["ts"] > self._cache_ttl:
            del self._cache[domain.lower()]
            return None
        return entry["score"]

    def cache_score(self, domain: str, score: float) -> None:
        """Cache a reputation score for a domain."""
        self._cache[domain.lower()] = {"score": score, "ts": time.time()}

    def get_stats(self) -> Dict:
        """Return current list sizes."""
        return {
            "blacklist_size": len(self._blacklist),
            "whitelist_size": len(self._whitelist),
            "cache_entries": len(self._cache),
        }


# Module-level singleton
reputation_service = ReputationService()
