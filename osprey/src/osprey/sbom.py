"""CycloneDX 1.5 JSON Software Bill of Materials (SBOM) generator.

Assumptions and Limitations:
- Implements CycloneDX 1.5 JSON schema format.
- Canonical Package URLs (purl) uniquely identify all software components.
- Dev dependencies are accurately attributed with scope='excluded'.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from osprey.models import Component, Finding


def generate_cyclonedx_sbom(
    app_name: str,
    components: List[Component],
    findings: Optional[List[Finding]] = None,
) -> Dict[str, Any]:
    """Generate a CycloneDX 1.5 compliant SBOM document."""
    app_purl = f"pkg:generic/{app_name}@0.1.0"
    bom_serial = f"urn:uuid:{uuid.uuid4()}"

    cdx_components: List[Dict[str, Any]] = []
    dep_refs: List[str] = []

    for comp in components:
        cdx_components.append({
            "type": "library" if comp.ecosystem != "Docker" else "container",
            "name": comp.name,
            "version": comp.version,
            "purl": comp.purl,
            "scope": "excluded" if comp.is_dev else "required",
            "properties": [
                {"name": "ecosystem", "value": comp.ecosystem},
                {"name": "source_file", "value": comp.source_file},
            ],
        })
        dep_refs.append(comp.purl)

    bom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": {
            "tools": [
                {
                    "vendor": "Osprey Contributors",
                    "name": "Osprey",
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "application",
                "name": app_name,
                "version": "0.1.0",
                "purl": app_purl,
            },
        },
        "components": cdx_components,
        "dependencies": [
            {
                "ref": app_purl,
                "dependsOn": dep_refs,
            }
        ],
    }

    if findings:
        vuln_list: List[Dict[str, Any]] = []
        for f in findings:
            vuln_entry: Dict[str, Any] = {
                "id": f.vulnerability_id,
                "source": {"name": "OSV"},
                "ratings": [
                    {
                        "severity": f.severity.lower(),
                        "score": f.cvss_score,
                        "method": "CVSSv3",
                    }
                ],
                "affects": [{"ref": f.component.purl}],
                "description": f.summary or f.details[:200],
                "properties": [
                    {"name": "osprey:risk_tier", "value": f.risk_tier},
                    {"name": "osprey:exposure", "value": f.exposure.level},
                    {"name": "osprey:fix_minimal", "value": f.fix_status.minimal_safe_version or ""},
                ],
            }
            vuln_list.append(vuln_entry)
        bom["vulnerabilities"] = vuln_list

    return bom


def export_cyclonedx_json(
    app_name: str,
    components: List[Component],
    findings: Optional[List[Finding]] = None,
    indent: int = 2,
) -> str:
    """Generate and serialize CycloneDX 1.5 JSON to a formatted string."""
    bom = generate_cyclonedx_sbom(app_name, components, findings)
    return json.dumps(bom, indent=indent)
