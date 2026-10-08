"""Fix availability and minimal safe version pinning engine.

FIX STATUS (v0.1 honest scope):
- Stage 1 only: 'upstream fix released' derived from OSV 'fixed' events vs installed version.
- Output stages 2-5 (distro, base image, your lockfile, production) as 'not tracked yet (roadmap)'.
- Always outputs the minimal safe version to pin (e.g. '>= 4.17.21').

Assumptions and Limitations:
- Fix recommendations reflect upstream patch declarations.
- Does not test compatibility or semantic breaking changes of the upgrade.
"""

from __future__ import annotations

from functools import cmp_to_key
from typing import Any, Dict, List

from osprey.core.versioning import compare_versions
from osprey.models import FixStatus


def _ecosystem_key(value: str) -> str:
    normalized = value.strip().lower()
    if normalized.startswith("debian") or normalized in {"deb", "dpkg"}:
        return "debian"
    if normalized in {"python", "pypi"}:
        return "pypi"
    if normalized in {"node", "npm"}:
        return "npm"
    if normalized in {"golang", "go"}:
        return "go"
    if normalized in {"crates.io", "cargo"}:
        return "cargo"
    return normalized


def extract_fixed_versions(vuln_data: Dict[str, Any], ecosystem: str | None = None) -> List[str]:
    """Extract all fixed version declarations from an OSV advisory entry."""
    fixed: List[str] = []
    affected = vuln_data.get("affected", [])
    if isinstance(affected, list):
        for item in affected:
            if not isinstance(item, dict):
                continue
            package = item.get("package", {})
            advisory_ecosystem = package.get("ecosystem") if isinstance(package, dict) else None
            if ecosystem and advisory_ecosystem and _ecosystem_key(str(advisory_ecosystem)) != _ecosystem_key(ecosystem):
                continue
            for r in item.get("ranges", []):
                if not isinstance(r, dict):
                    continue
                for ev in r.get("events", []):
                    if isinstance(ev, dict) and "fixed" in ev:
                        f_ver = str(ev["fixed"]).strip()
                        if f_ver and f_ver not in fixed:
                            fixed.append(f_ver)

    # Some advisories also provide database_specific fixed list
    db_spec = vuln_data.get("database_specific", {})
    if isinstance(db_spec, dict):
        extra = db_spec.get("fixed_versions", [])
        if isinstance(extra, list):
            for f_ver in extra:
                if str(f_ver) not in fixed:
                    fixed.append(str(f_ver))

    return fixed


def determine_fix_status(installed_version: str, raw_vuln: Dict[str, Any], ecosystem: str | None = None) -> FixStatus:
    """Analyze fixed versions from an advisory and determine the minimal safe version."""
    fixed_versions = extract_fixed_versions(raw_vuln, ecosystem)

    if not fixed_versions:
        return FixStatus(
            status="no fix available",
            fixed_version=None,
            minimal_safe_version="no fix available",
            stages={
                "stage_1_upstream": "no upstream fix released yet",
                "stage_2_distro": "not tracked yet (roadmap)",
                "stage_3_base_image": "not tracked yet (roadmap)",
                "stage_4_lockfile": "not tracked yet (roadmap)",
                "stage_5_production": "not tracked yet (roadmap)",
            },
        )

    comparable = [
        version for version in fixed_versions
        if compare_versions(installed_version, version, ecosystem) is not None
    ]
    if not comparable:
        return FixStatus(
            status="fix boundary observed; version ordering unknown",
            fixed_version=None,
            minimal_safe_version=None,
            stages={
                "stage_1_upstream": "fixed boundary observed, but ecosystem-specific version ordering is unavailable",
                "stage_2_distro": "not tracked yet (roadmap)",
                "stage_3_base_image": "not tracked yet (roadmap)",
                "stage_4_lockfile": "not tracked yet (roadmap)",
                "stage_5_production": "not tracked yet (roadmap)",
            },
        )

    newer = [version for version in comparable if compare_versions(installed_version, version, ecosystem) < 0]
    if not newer:
        return FixStatus(
            status="current version is at or above known fixed boundaries",
            fixed_version=None,
            minimal_safe_version=None,
            stages={
                "stage_1_upstream": "advisory fixed boundaries are not newer than the observed version",
                "stage_2_distro": "not tracked yet (roadmap)",
                "stage_3_base_image": "not tracked yet (roadmap)",
                "stage_4_lockfile": "not tracked yet (roadmap)",
                "stage_5_production": "not tracked yet (roadmap)",
            },
        )

    newer.sort(key=cmp_to_key(lambda left, right: compare_versions(left, right, ecosystem) or 0))
    chosen_fixed = newer[0]

    minimal_safe = f">= {chosen_fixed}"
    return FixStatus(
        status="upstream fix released",
        fixed_version=chosen_fixed,
        minimal_safe_version=minimal_safe,
        stages={
            "stage_1_upstream": f"upstream fix released ({minimal_safe})",
            "stage_2_distro": "not tracked yet (roadmap)",
            "stage_3_base_image": "not tracked yet (roadmap)",
            "stage_4_lockfile": "not tracked yet (roadmap)",
            "stage_5_production": "not tracked yet (roadmap)",
        },
    )
