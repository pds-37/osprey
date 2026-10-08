"""API tests for the local scanner adapter and filesystem boundary."""

import json

from fastapi.testclient import TestClient

from guardianos.api.app import app
from guardianos.core.config import settings
from guardianos.intel.feed_data import vuln_registry
from guardianos.intel.models import VulnerabilityRecord, VulnerabilitySeverity, VulnerabilitySource
from guardianos.inventory.models import DependencyState
from guardianos.inventory.models import Ecosystem


client = TestClient(app)


def test_local_scan_uses_shared_manifest_and_lockfile_observations(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "tiny-app", "dependencies": {"lodash": "^4.17.20"}}),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "tiny-app", "lockfileVersion": 3, "packages": {
            "": {"name": "tiny-app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
        }}),
        encoding="utf-8",
    )

    response = client.post("/api/v1/sboms/scan-local-manifests", json={"path": ".", "clear_existing": True})
    assert response.status_code == 201, response.text
    components = [item for item in response.json()["components"] if item["name"] == "lodash"]
    assert len(components) == 2
    by_state = {item["state"]: item for item in components}
    assert by_state[DependencyState.DECLARED.value]["version"] == "4.17.20"
    assert by_state[DependencyState.LOCKED.value]["version"] == "4.17.21"
    assert by_state[DependencyState.LOCKED.value]["locked_version"] == "4.17.21"
    assert by_state[DependencyState.LOCKED.value]["installed_version"] is None
    assert by_state[DependencyState.DECLARED.value]["location"] == "package.json"
    assert by_state[DependencyState.LOCKED.value]["location"] == "package-lock.json"
    assert all(item["evidence_ids"] for item in components)
    assert response.json()["summary"]["inventory_engine"] == "shared Osprey scanner"


def test_local_scan_rejects_paths_outside_configured_root(tmp_path, monkeypatch):
    workspace = tmp_path / "allowed"
    workspace.mkdir()
    outside = tmp_path / "private"
    outside.mkdir()
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(workspace))

    response = client.post(
        "/api/v1/sboms/scan-local-manifests",
        json={"path": str(outside), "clear_existing": True},
    )
    assert response.status_code == 403
    assert "outside the configured scan root" in response.json()["detail"]


def test_local_scan_integrates_reachability_into_findings_and_risk(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(tmp_path))
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "reachable-app", "dependencies": {"vulnerable-codec": "1.0.0"}}),
        encoding="utf-8",
    )
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "upload.ts").write_text(
        'import * as codec from "vulnerable-codec";\n'
        'function decodeUpload(body: Uint8Array) { return codec.decode(body); }\n'
        'function handler(req: Request) { return decodeUpload(req.body); }\n'
        'router.post("/upload", handler);\n',
        encoding="utf-8",
    )
    vuln_registry.register_advisory(VulnerabilityRecord(
        id="GHSA-local-scan-reachability",
        summary="Test advisory with an explicit vulnerable symbol",
        ecosystem=Ecosystem.NPM,
        component_name="vulnerable-codec",
        affected_versions=["1.0.0"],
        vulnerable_symbols=["decode"],
        severity=VulnerabilitySeverity.HIGH,
        source=VulnerabilitySource.DEMO_FIXTURE,
    ))

    response = client.post(
        "/api/v1/sboms/scan-local-manifests",
        json={"path": ".", "clear_existing": True},
    )

    assert response.status_code == 201, response.text
    summary = response.json()["summary"]
    assert summary["findings_analyzed"] == 1
    assert summary["reachability"] == {"REACHABLE": 1, "NOT_REACHABLE": 0, "UNKNOWN": 0}

    findings_response = client.get("/api/v1/vulnerabilities")
    assert findings_response.status_code == 200
    finding = next(
        item for item in findings_response.json()
        if item["vulnerability_id"] == "GHSA-local-scan-reachability"
    )
    assert finding["reachability_status"] == "REACHABLE"
    assert finding["reachability_confidence"] > 0
    assert finding["reachability_path"][-1] == "vulnerable-codec.decode"
    assert finding["reachability_path_edges"]
    assert finding["reachability_path_edges"][-1]["relation"] == "vulnerable_symbol_call"
    assert finding["provenance_ids"]["version"] in finding["evidence_ids"]
    assert finding["provenance_ids"]["vulnerability_advisory"] in finding["evidence_ids"]
    assert finding["analysis_provenance_id"] == finding["provenance_ids"]["analysis_run"]
    assert finding["reachability_explanation"]
    assert finding["reachability_limitations"]
    assert finding["evidence_ids"]
    assert finding["runtime_state"]["DECLARED"] == "OBSERVED"
    assert finding["runtime_state"]["INSTALLED"] == "UNKNOWN"
    assert finding["runtime_state"]["LOADED"] == "UNKNOWN"
    assert finding["runtime_state"]["EXERCISED"] == "UNKNOWN"
    assert any("No current LOADED observation" in item for item in finding["runtime_limitations"])

    version_evidence = client.get(f"/api/v1/evidence/{finding['provenance_ids']['version']}")
    assert version_evidence.status_code == 200
    assert version_evidence.json()["type"] == "VERSION"
    assert version_evidence.json()["metadata"]["observed_version"] == "1.0.0"
    assert version_evidence.json()["metadata"]["status"] == "AFFECTED"
    advisory_evidence = client.get(
        f"/api/v1/evidence/{finding['provenance_ids']['vulnerability_advisory']}"
    )
    assert advisory_evidence.status_code == 200
    assert advisory_evidence.json()["metadata"]["advisory_source"] == "DEMO_FIXTURE"
    assert advisory_evidence.json()["metadata"]["severity_evidence"] == "HIGH"
    assert advisory_evidence.json()["metadata"]["cvss_score"] is None

    reachability_evidence = client.get(
        f"/api/v1/evidence/{finding['provenance_ids']['reachability']}"
    )
    assert reachability_evidence.status_code == 200
    assert reachability_evidence.json()["type"] == "REACHABILITY"
    assert reachability_evidence.json()["integrity_status"] == "VERIFIED"
    assert reachability_evidence.json()["metadata"]["observed"]["status"] == "REACHABLE"
    assert reachability_evidence.json()["metadata"]["observed"]["path_edges"]

    risk_response = client.get("/api/v1/risks")
    assert risk_response.status_code == 200
    risk = next(item for item in risk_response.json() if item["finding_id"] == finding["id"])
    assert risk["risk_inputs"]["cvss_score"] is None
    assert risk["risk_inputs"]["epss_score"] is None
    assert risk["risk_inputs"]["kev_listed"] is None
    assert risk["risk_inputs"]["reachability_status"] == "REACHABLE"
    assert risk["provenance_ids"]["risk"] in risk["evidence_ids"]
    assert risk["provenance_ids"]["risk"] in finding["evidence_ids"]
    risk_evidence = client.get(f"/api/v1/evidence/{risk['provenance_ids']['risk']}")
    assert risk_evidence.status_code == 200
    assert risk_evidence.json()["metadata"]["observed"]["inputs"]["cvss_score"] is None
    assert risk_evidence.json()["metadata"]["observed"]["assessment"]["decision"] == risk["decision"]
    reachability_factor = next(
        item for item in risk["factors"] if item["name"] == "Vulnerable Function Reachability"
    )
    assert reachability_factor["score"] == round(finding["reachability_confidence"] * 100.0, 1)
    assert any("REACHABLE" in reason for reason in risk["reasons"])
