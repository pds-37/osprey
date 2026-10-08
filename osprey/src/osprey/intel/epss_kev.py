"""EPSS and CISA KEV enrichment client.

GUARDRAILS:
- Network calls allowed ONLY to api.first.org and www.cisa.gov.
- Strict timeouts on all calls (default 3.0s).
- Fails soft: never raises unhandled exceptions or interrupts the scan.
- Works offline from cache.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

import httpx

from osprey.intel.cache import IntelCache

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EpssKevClient:
    """Enriches vulnerabilities with CISA KEV and FIRST EPSS scores."""

    def __init__(self, cache: Optional[IntelCache] = None, timeout: float = 3.0, offline: bool = False):
        self.cache = cache or IntelCache(offline=offline)
        self.timeout = timeout
        self.offline = offline
        self.kev_catalog_available = False

    def get_cisa_kev_catalog(self) -> Set[str]:
        """Fetch the set of CVE IDs present in the CISA KEV catalog."""
        cached = self.cache.get("kev", "cisa_catalog")
        if cached is not None and isinstance(cached, list):
            self.kev_catalog_available = True
            return set(cached)

        if self.offline:
            return set()

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(CISA_KEV_URL, headers={"User-Agent": "osprey-cli/0.1"})
                if resp.status_code == 200:
                    data = resp.json()
                    cves = [item["cveID"] for item in data.get("vulnerabilities", []) if "cveID" in item]
                    self.cache.set("kev", "cisa_catalog", cves)
                    self.kev_catalog_available = True
                    return set(cves)
        except Exception as e:
            logger.debug("Failed to fetch CISA KEV catalog: %s", e)

        return set()

    def get_epss_scores(self, cve_ids: List[str]) -> Dict[str, float]:
        """Fetch EPSS probabilities for a list of CVE IDs."""
        if not cve_ids:
            return {}

        scores: Dict[str, float] = {}
        to_fetch: List[str] = []

        # 1. Read cached EPSS
        for cve in cve_ids:
            cached = self.cache.get("epss", cve)
            if cached is not None:
                try:
                    scores[cve] = float(cached)
                except (ValueError, TypeError):
                    pass
            else:
                to_fetch.append(cve)

        if not to_fetch or self.offline:
            return scores

        # 2. Fetch in chunks of 30 CVEs
        chunk_size = 30
        for i in range(0, len(to_fetch), chunk_size):
            chunk = to_fetch[i : i + chunk_size]
            cve_param = ",".join(chunk)
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.get(
                        EPSS_API_URL,
                        params={"cve": cve_param},
                        headers={"User-Agent": "osprey-cli/0.1"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        for entry in data.get("data", []):
                            cid = entry.get("cve")
                            val = entry.get("epss")
                            if cid and val is not None:
                                try:
                                    prob = float(val)
                                    scores[cid] = prob
                                    self.cache.set("epss", cid, prob)
                                except (ValueError, TypeError):
                                    pass
            except Exception as e:
                logger.debug("Failed to query EPSS for chunk: %s", e)

        return scores
