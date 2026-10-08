"""Unit tests for SARIF 2.1.0 and CycloneDX 1.5 SBOM generators."""

import json
from pathlib import Path

from osprey.fixes import FixStatus
from osprey.models import Component, ExposureInfo, Finding
from osprey.sarif import export_sarif_json, generate_sarif
from osprey.sbom import export_cyclonedx_json, generate_cyclonedx_sbom


def _create_sample_findings(root_path: Path):
    comp_prod = Component(
        name="express",
        version="4.17.1",
        ecosystem="npm",
        purl="pkg:npm/express@4.17.1",
        is_dev=False,
        source_file=str(root_path / "package.json"),
    )
    comp_dev = Component(
        name="mocha",
        version="8.0.0",
        ecosystem="npm",
        purl="pkg:npm/mocha@8.0.0",
        is_dev=True,
        source_file=str(root_path / "package.json"),
    )

    f_act_now = Finding(
        id="GHSA-xxxx-critical",
        vulnerability_id="GHSA-xxxx-critical",
        component=comp_prod,
        exposure=ExposureInfo(level="public", confidence="inferred", evidence="Dockerfile: EXPOSE 8080"),
        fix_status=FixStatus(status="upstream fix released", minimal_safe_version=">= 4.17.2"),
        risk_tier="ACT NOW",
        firing_rule="Rule 1: public exposure AND Critical CVSS score (9.8 >= 9.0) -> ACT NOW",
        cvss_score=9.8,
        severity="CRITICAL",
        summary="Remote code execution in express",
    )

    f_plan = Finding(
        id="GHSA-yyyy-high",
        vulnerability_id="GHSA-yyyy-high",
        component=comp_prod,
        exposure=ExposureInfo(level="unknown", confidence="unknown", evidence="no indicators"),
        fix_status=FixStatus(status="upstream fix released", minimal_safe_version=">= 4.18.0"),
        risk_tier="PLAN",
        firing_rule="Rule 2: unknown exposure AND High CVSS score (7.5 >= 7.0) -> PLAN",
        cvss_score=7.5,
        severity="HIGH",
        summary="Denial of service in express",
    )

    f_monitor = Finding(
        id="GHSA-zzzz-medium",
        vulnerability_id="GHSA-zzzz-medium",
        component=comp_prod,
        exposure=ExposureInfo(level="internal", confidence="inferred", evidence="internal service"),
        fix_status=FixStatus(status="no fix available", minimal_safe_version=None),
        risk_tier="MONITOR",
        firing_rule="Rule 3: internal service without external ingress -> MONITOR",
        cvss_score=5.5,
        severity="MEDIUM",
        summary="Timing attack in express",
    )

    f_ignore = Finding(
        id="GHSA-dev-ignore",
        vulnerability_id="GHSA-dev-ignore",
        component=comp_dev,
        exposure=ExposureInfo(level="dev-only", confidence="inferred", evidence="package.json devDependencies"),
        fix_status=FixStatus(status="upstream fix released", minimal_safe_version=">= 9.0.0"),
        risk_tier="IGNORE",
        firing_rule="Rule 4: dev-only dependency isolated from production runtime -> IGNORE",
        cvss_score=9.0,
        severity="CRITICAL",
        summary="Prototype pollution in mocha",
    )

    return [comp_prod, comp_dev], [f_act_now, f_plan, f_monitor, f_ignore]


def test_sarif_structure_and_levels(tmp_path: Path):
    comps, findings = _create_sample_findings(tmp_path)
    sarif = generate_sarif(findings, tmp_path)

    # 1. Root structure
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Osprey"
    assert driver["version"] == "0.1.0"
    assert len(driver["rules"]) == 4

    results = sarif["runs"][0]["results"]
    assert len(results) == 4

    # 2. Risk tier to SARIF level mapping
    level_by_id = {r["ruleId"]: r["level"] for r in results}
    assert level_by_id["GHSA-xxxx-critical"] == "error"    # ACT NOW -> error
    assert level_by_id["GHSA-yyyy-high"] == "warning"      # PLAN -> warning
    assert level_by_id["GHSA-zzzz-medium"] == "note"       # MONITOR -> note
    assert level_by_id["GHSA-dev-ignore"] == "none"        # IGNORE -> none

    # 3. Serialization
    sarif_str = export_sarif_json(findings, tmp_path)
    parsed = json.loads(sarif_str)
    assert parsed["version"] == "2.1.0"


def test_cyclonedx_sbom_fields_and_purls(tmp_path: Path):
    comps, findings = _create_sample_findings(tmp_path)
    bom = generate_cyclonedx_sbom("my-test-app", comps, findings)

    # 1. Spec compliance
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["component"]["name"] == "my-test-app"
    assert bom["metadata"]["component"]["purl"] == "pkg:generic/my-test-app@0.1.0"

    # 2. Component purls and scopes
    cdx_comps = bom["components"]
    assert len(cdx_comps) == 2

    prod_cdx = next(c for c in cdx_comps if c["name"] == "express")
    dev_cdx = next(c for c in cdx_comps if c["name"] == "mocha")

    assert prod_cdx["purl"] == "pkg:npm/express@4.17.1"
    assert prod_cdx["scope"] == "required"

    assert dev_cdx["purl"] == "pkg:npm/mocha@8.0.0"
    assert dev_cdx["scope"] == "excluded"  # dev dependency

    # 3. Vulnerability attachments
    assert "vulnerabilities" in bom
    vulns = bom["vulnerabilities"]
    assert len(vulns) == 4
    crit_vuln = next(v for v in vulns if v["id"] == "GHSA-xxxx-critical")
    assert crit_vuln["ratings"][0]["score"] == 9.8
    assert crit_vuln["affects"][0]["ref"] == "pkg:npm/express@4.17.1"

    # 4. JSON Serialization
    bom_str = export_cyclonedx_json("my-test-app", comps, findings)
    parsed = json.loads(bom_str)
    assert parsed["specVersion"] == "1.5"
