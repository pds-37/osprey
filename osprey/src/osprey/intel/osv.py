"""Google OSV.dev batch vulnerability client.

GUARDRAILS:
- Network calls allowed ONLY to api.osv.dev.
- Strict timeout on every call (default 5.0s).
- Fails soft and works offline from cache.
- Batches queries via /v1/querybatch and enriches details via /v1/vulns.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from osprey.intel.cache import IntelCache
from osprey.models import Component

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "crates.io": "crates.io",
    "debian": "Debian",
    "alpine": "Alpine",
    "maven": "Maven",
}


class OsvClient:
    """Client for querying OSV.dev /v1/querybatch with caching and retries."""

    def __init__(self, cache: Optional[IntelCache] = None, timeout: float = 5.0, offline: bool = False):
        self.cache = cache or IntelCache(offline=offline)
        self.timeout = timeout
        self.offline = offline
        self.coverage_by_component: Dict[str, str] = {}
        self._last_batch_success = False
        self._last_queryable_keys: set[str] = set()

    def query_components(self, components: List[Component]) -> Dict[str, List[Dict[str, Any]]]:
        """Query vulnerabilities for a list of components.

        Returns a dictionary mapping Component.key -> list of raw OSV advisory dicts.
        """
        results: Dict[str, List[Dict[str, Any]]] = {}
        self.coverage_by_component = {}
        to_fetch: List[Component] = []

        # 1. Check local cache first
        for comp in components:
            cache_key = comp.key
            cached = self.cache.get("osv", cache_key)
            if cached is not None:
                values = cached if isinstance(cached, list) else []
                results[cache_key] = values
                coverage = self.cache.get("osv_coverage", cache_key)
                if isinstance(coverage, dict) and coverage.get("status") == "COMPLETE":
                    observed_at = coverage.get("observed_at")
                    try:
                        observed = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
                        current = datetime.now(timezone.utc)
                        age = current - observed.astimezone(timezone.utc)
                        self.coverage_by_component[cache_key] = (
                            "COMPLETE" if observed.tzinfo is not None
                            and timedelta(0) <= age <= timedelta(hours=24)
                            else "STALE"
                        )
                    except (TypeError, ValueError, OverflowError):
                        self.coverage_by_component[cache_key] = "UNAVAILABLE"
                elif values:
                    self.coverage_by_component[cache_key] = "ADVISORIES_PRESENT_COVERAGE_UNKNOWN"
                else:
                    # Older empty cache entries do not distinguish a successful
                    # empty result from a failed request; they cannot prove absence.
                    self.coverage_by_component[cache_key] = "UNAVAILABLE"
            else:
                to_fetch.append(comp)

        if not to_fetch or self.offline:
            # If offline or all components cached, return immediately
            for comp in to_fetch:
                results[comp.key] = []
                self.coverage_by_component[comp.key] = "UNAVAILABLE"
            return results

        # 2. Batch queries into chunks of 100
        chunk_size = 100
        for i in range(0, len(to_fetch), chunk_size):
            chunk = to_fetch[i : i + chunk_size]
            self._last_batch_success = False
            batch_results = self._fetch_batch(chunk)
            for comp_key, vulns in batch_results.items():
                # Enrich each vulnerability stub with full advisory details
                enriched_vulns = [self._enrich_vuln(v) for v in vulns]
                results[comp_key] = enriched_vulns
                if self._last_batch_success and comp_key in self._last_queryable_keys:
                    self.cache.set("osv", comp_key, enriched_vulns)
                    self.cache.set("osv_coverage", comp_key, {
                        "status": "COMPLETE",
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                    })
                    self.coverage_by_component[comp_key] = "COMPLETE"
                else:
                    self.coverage_by_component[comp_key] = "UNAVAILABLE"

        return results

    def _enrich_vuln(self, stub: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch full vulnerability advisory if stub only contains ID and modified."""
        vuln_id = stub.get("id")
        if not vuln_id:
            return stub

        # If already enriched (e.g. from tests/mocks with 'affected' or 'summary')
        if "affected" in stub or "summary" in stub:
            return stub

        # Check cache
        cached = self.cache.get("vuln_detail", vuln_id)
        if cached is not None and isinstance(cached, dict):
            return cached

        if self.offline:
            return stub

        # Query api.osv.dev/v1/vulns/<id>
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(
                    f"{OSV_VULN_URL}/{vuln_id}",
                    headers={"User-Agent": "osprey-cli/0.1"},
                )
                if resp.status_code == 200:
                    detail = resp.json()
                    self.cache.set("vuln_detail", vuln_id, detail)
                    return detail
        except Exception as e:
            logger.debug("Failed to enrich vuln %s: %s", vuln_id, e)

        return stub

    def _fetch_batch(self, chunk: List[Component]) -> Dict[str, List[Dict[str, Any]]]:
        """Send a single batch request to OSV.dev with retries and timeout."""
        self._last_batch_success = False
        self._last_queryable_keys = set()
        batch_map: Dict[str, List[Dict[str, Any]]] = {c.key: [] for c in chunk}

        # Filter only components with recognized ecosystems
        queryable: List[Tuple[Component, Dict[str, Any]]] = []
        for comp in chunk:
            osv_eco = ECOSYSTEM_MAP.get(comp.ecosystem.lower())
            if not osv_eco or not comp.name or not comp.version:
                continue
            queryable.append(
                (
                    comp,
                    {
                        "package": {
                            "name": comp.name,
                            "ecosystem": osv_eco,
                        },
                        "version": comp.version,
                    },
                )
            )

        if not queryable:
            return batch_map
        self._last_queryable_keys = {comp.key for comp, _ in queryable}

        payload = {"queries": [q[1] for q in queryable]}

        # Try up to 2 attempts with short backoff
        for attempt in range(2):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(
                        OSV_BATCH_URL,
                        json=payload,
                        headers={"User-Agent": "osprey-cli/0.1"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        resp_results = data.get("results", [])
                        if not isinstance(resp_results, list) or len(resp_results) != len(queryable):
                            return batch_map
                        for idx, item in enumerate(resp_results):
                            if idx < len(queryable):
                                comp = queryable[idx][0]
                                value = item.get("vulns", []) if isinstance(item, dict) else None
                                if not isinstance(value, list):
                                    return batch_map
                                batch_map[comp.key] = value
                        self._last_batch_success = True
                        return batch_map
            except Exception as e:
                logger.debug("OSV batch request failed (attempt %d): %s", attempt + 1, e)
                if attempt == 0:
                    time.sleep(0.5)

        return batch_map
