import requests
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

class PatternLoader:
    """Fetch vulnerability patterns from NIST CWE"""

    def __init__(self):
        self.cache_file = "src/patterns/.patterns_cache.json"

    def get_patterns(self, force_refresh: bool = False) -> Dict[int, dict]:
        """Get patterns (from cache or fetch fresh)"""

        # Default CWEs (OWASP Top 10 + common)
        cwe_ids = [89, 79, 352, 798, 20, 200, 22, 434, 611, 306]

        # Check cache
        if not force_refresh and self._cache_valid():
            logger.info("Loading from cache...")
            return self._load_cache()

        # Fetch fresh
        patterns = {}
        for cwe_id in cwe_ids:
            try:
                url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
                response = requests.get(url, timeout=5)

                import re
                title_match = re.search(r'<h1[^>]*>([^<]+)</h1>', response.text)
                title = title_match.group(1).strip() if title_match else f"CWE-{cwe_id}"

                patterns[cwe_id] = {
                    "cwe_id": cwe_id,
                    "name": title,
                    "url": url,
                    "fetched_at": datetime.now().isoformat()
                }
                logger.info(f"✓ CWE-{cwe_id}")
            except Exception as e:
                logger.warning(f"Failed CWE-{cwe_id}: {e}")

        # Save cache
        os.makedirs("src/patterns", exist_ok=True)
        with open(self.cache_file, "w") as f:
            json.dump(patterns, f, indent=2, default=str)

        return patterns

    def _cache_valid(self) -> bool:
        """Check if cache is fresh (<24h)"""
        if not os.path.exists(self.cache_file):
            return False
        age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(self.cache_file))
        return age < timedelta(hours=24)

    def _load_cache(self) -> Dict[int, dict]:
        """Load from cache"""
        with open(self.cache_file, "r") as f:
            return {int(k): v for k, v in json.load(f).items()}