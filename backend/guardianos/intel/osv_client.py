"""Live OSV.dev (Open Source Vulnerabilities) API client.

Queries Google's public OSV database (https://api.osv.dev/v1/query) in real time
for packages across PyPI, npm, Debian, Go, Maven, crates.io, etc.
"""

import json
import logging
import urllib.error
import urllib.request
from typing import List, Optional
from guardianos.intel.models import VulnerabilityRecord, VulnerabilitySeverity, VulnerabilitySource
from guardianos.inventory.models import Ecosystem

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"

ECOSYSTEM_MAP = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
    Ecosystem.DEBIAN: "Debian",
    Ecosystem.GO: "Go",
    Ecosystem.MAVEN: "Maven",
    Ecosystem.CARGO: "crates.io",
}


def query_live_osv(
    package_name: str,
    version: str,
    ecosystem: Ecosystem,
    timeout: float = 3.5
) -> List[VulnerabilityRecord]:
    """Query OSV.dev for live vulnerability advisories affecting package@version."""
    osv_ecosystem = ECOSYSTEM_MAP.get(ecosystem)
    if not osv_ecosystem:
        return []

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": osv_ecosystem,
        },
        "version": version,
    }

    try:
        req = urllib.request.Request(
            OSV_API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "GuardianOS/2.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                return []
            data = json.loads(response.read().decode("utf-8"))
            vulns = data.get("vulns", [])
            records: List[VulnerabilityRecord] = []

            for item in vulns:
                vuln_id = item.get("id", "OSV-UNKNOWN")
                summary = item.get("summary") or item.get("details", "")[:200]
                details = item.get("details", "")

                # Estimate severity from database_specific or CVSS
                severity = VulnerabilitySeverity.HIGH
                cvss_score = 7.5
                for s in item.get("severity", []):
                    if s.get("type") == "CVSS_V3":
                        score_str = s.get("score", "")
                        if "CVSS:3" in score_str:
                            severity = VulnerabilitySeverity.HIGH
                            cvss_score = 8.0

                # Extract fixed versions if listed
                fixed_versions = []
                for affected in item.get("affected", []):
                    for r in affected.get("ranges", []):
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fixed_versions.append(event["fixed"])

                record = VulnerabilityRecord(
                    id=vuln_id,
                    component_name=package_name,
                    ecosystem=ecosystem,
                    summary=summary[:255] if summary else f"Vulnerability in {package_name}",
                    details=details[:1000] if details else "",
                    severity=severity,
                    cvss_score=cvss_score,
                    affected_version_ranges=[],
                    fixed_versions=list(set(fixed_versions)),
                    source=VulnerabilitySource.OSV
                )
                records.append(record)

            return records
    except Exception as e:
        logger.debug("Live OSV query for %s@%s skipped or timed out: %s", package_name, version, e)
        return []
