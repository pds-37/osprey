"""Live OSV.dev (Open Source Vulnerabilities) API client.

Queries Google's public OSV database (https://api.osv.dev/v1/query) in real time
for packages across PyPI, npm, Debian, Go, Maven, crates.io, etc.
"""

import json
import logging
import urllib.error
import urllib.request
from dataclasses import asdict
from datetime import datetime
from typing import List, Optional
from guardianos.intel.models import VulnerabilityRecord, VulnerabilitySeverity, VulnerabilitySource
from guardianos.inventory.models import Ecosystem
from osprey.core.symbols import extract_osv_affected_records, extract_osv_vulnerable_symbols
from osprey.core.evidence import canonical_json, content_digest
from osprey.risk import parse_advisory_severity

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


def _parse_timestamp(value: object) -> datetime | None:
    """Parse a source-supplied timestamp; missing or malformed values stay unavailable."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed


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
                raw_summary = item.get("summary")
                raw_details = item.get("details")
                summary = raw_summary if isinstance(raw_summary, str) else ""
                details = raw_details if isinstance(raw_details, str) else ""
                if not summary:
                    summary = details[:200]

                severity_label, cvss_score = parse_advisory_severity(item)
                severity = VulnerabilitySeverity(severity_label)

                # Extract fixed versions if listed
                fixed_versions = []
                affected_ranges = []
                affected_versions = []
                introduced_versions = []
                scoped_affected = [
                    record for _index, record in extract_osv_affected_records(
                        item,
                        package=package_name,
                        ecosystem=ecosystem.value,
                    )
                ]
                symbol_mappings = extract_osv_vulnerable_symbols(
                    item,
                    package=package_name,
                    ecosystem=ecosystem.value,
                    vulnerability_id=vuln_id,
                )
                vulnerable_symbols = [mapping.symbol for mapping in symbol_mappings]
                for affected in scoped_affected:
                    for exact_version in affected.get("versions", []):
                        exact_version = str(exact_version).strip()
                        if exact_version and exact_version not in affected_versions:
                            affected_versions.append(exact_version)
                    for r in affected.get("ranges", []):
                        if isinstance(r, dict):
                            affected_ranges.append(r)
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fixed_versions.append(event["fixed"])
                            if "introduced" in event:
                                introduced_versions.append(event["introduced"])

                record = VulnerabilityRecord(
                    id=vuln_id,
                    component_name=package_name,
                    ecosystem=ecosystem,
                    summary=summary[:255],
                    details=details[:1000] if details else "",
                    severity=severity,
                    cvss_score=cvss_score,
                    affected_version_ranges=[],
                    affected_ranges=affected_ranges,
                    affected_versions=list(dict.fromkeys(affected_versions)),
                    introduced_versions=list(dict.fromkeys(introduced_versions)),
                    vulnerable_symbols=list(dict.fromkeys(vulnerable_symbols)),
                    vulnerable_symbol_mappings=[asdict(mapping) for mapping in symbol_mappings],
                    query_matched_version=version,
                    fixed_versions=list(dict.fromkeys(fixed_versions)),
                    published_at=_parse_timestamp(item.get("published")),
                    modified_at=_parse_timestamp(item.get("modified")),
                    source_content_hash=content_digest(canonical_json(item)),
                    source=VulnerabilitySource.OSV,
                )
                records.append(record)

            return records
    except Exception as e:
        logger.debug("Live OSV query for %s@%s skipped or timed out: %s", package_name, version, e)
        return []
