"""SARIF 2.1.0 exporter for GitHub Code Scanning integration.

Assumptions and Limitations:
- Generates valid SARIF 2.1.0 JSON format.
- Maps ACT NOW to 'error', PLAN/UNKNOWN to 'warning', and MONITOR/IGNORE to 'note'.
- Uses relative file paths to point to originating manifest files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from osprey.models import Finding


def generate_sarif(findings: List[Finding], root_path: Path) -> Dict[str, Any]:
    """Generate SARIF 2.1.0 document from Osprey findings."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    level_map = {
        "ACT NOW": "error",
        "PLAN": "warning",
        "MONITOR": "note",
        "IGNORE": "none",
        "UNKNOWN": "warning",
    }

    for f in findings:
        rule_id = f.vulnerability_id
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f"DependencyVulnerability_{rule_id.replace('-', '_')}",
                "shortDescription": {
                    "text": f"{f.component.name}@{f.component.version}: {rule_id}"
                },
                "fullDescription": {
                    "text": f.summary or f.details or f"Vulnerability {rule_id} affecting {f.component.name}"
                },
                "help": {
                    "text": (
                        f"Vulnerability: {rule_id}\n"
                        f"Component: {f.component.name}@{f.component.version}\n"
                        f"Risk Tier: {f.risk_tier}\n"
                        f"Package Status: {f.package_status.value}\n"
                        f"Function Reachability: {f.reachability.status.value}\n"
                        f"Exposure: {f.exposure.to_display()}\n"
                        f"Recommended Fix: {f.fix_status.minimal_safe_version}\n"
                        f"Rule Fired: {f.firing_rule}"
                    )
                },
                "properties": {
                    "cvss": f.cvss_score,
                    "risk_tier": f.risk_tier,
                    "risk_level": f.risk_level,
                    "risk_score": f.risk_score,
                    "exposure": f.exposure.level,
                    "package_status": f.package_status.value,
                    "reachability_status": f.reachability.status.value,
                    "evidence_ids": f.evidence_ids,
                },
            }

        # Determine file uri
        src = f.component.source_file
        rel_uri = "package.json"
        if src:
            try:
                p = Path(src)
                if p.is_relative_to(root_path):
                    rel_uri = str(p.relative_to(root_path)).replace("\\", "/")
                else:
                    rel_uri = p.name
            except Exception:
                rel_uri = Path(src).name

        sarif_level = level_map.get(f.risk_tier, "warning")
        results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {
                "text": (
                    f"[{f.risk_tier}] {f.component.name}@{f.component.version} affected by {rule_id}. "
                    f"Exposure: {f.exposure.to_display()}. Recommended Fix: {f.fix_status.minimal_safe_version}."
                    f" Function reachability: {f.reachability.status.value}."
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": rel_uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1,
                        },
                    }
                }
            ],
            "properties": {
                "firing_rule": f.firing_rule,
                "epss": f.epss_score,
                "cisa_kev": f.in_cisa_kev,
                "cisa_kev_available": f.kev_available,
                "risk_score": f.risk_score,
                "risk_level": f.risk_level,
                "risk_limitations": f.risk_limitations,
                "package_status": f.package_status.value,
                "reachability_status": f.reachability.status.value,
                "evidence_ids": f.evidence_ids,
            },
        })

    sarif_doc: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Osprey",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/pds-37/osprey",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif_doc


def export_sarif_json(findings: List[Finding], root_path: Path, indent: int = 2) -> str:
    """Serialize SARIF report to JSON string."""
    doc = generate_sarif(findings, root_path)
    return json.dumps(doc, indent=indent)
