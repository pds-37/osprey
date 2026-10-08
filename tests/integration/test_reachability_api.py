"""API-level regression tests for evidence-backed static reachability."""

from fastapi.testclient import TestClient

from guardianos.api.app import app
from guardianos.intel.models import (
    VulnerabilityFinding,
    VulnerabilityRecord,
    VulnerabilitySeverity,
)
from guardianos.intel.service import intel_service
from guardianos.inventory.models import Ecosystem


client = TestClient(app)


def _finding(symbols: list[str]) -> VulnerabilityFinding:
    advisory = VulnerabilityRecord(
        id="GHSA-test-reachability",
        summary="Test advisory with an explicit symbol mapping",
        ecosystem=Ecosystem.NPM,
        component_name="vulnerable-codec",
        vulnerable_symbols=symbols,
        severity=VulnerabilitySeverity.HIGH,
    )
    finding = VulnerabilityFinding(
        id=f"finding-{symbols[0] if symbols else 'unknown'}",
        vulnerability_id=advisory.id,
        component_purl="pkg:npm/vulnerable-codec@1.0.0",
        component_name="vulnerable-codec",
        installed_version="1.0.0",
        severity=VulnerabilitySeverity.HIGH,
        vulnerability=advisory,
    )
    intel_service.save_finding(finding)
    return finding


def test_reachable_vulnerable_symbol_returns_path_and_evidence():
    finding = _finding(["decode"])
    response = client.post("/api/v1/analysis/reachability", json={
        "finding_id": finding.id,
        "source_files": {
            "src/upload.ts": '''
import * as codec from "vulnerable-codec";
function parseUpload(body: Uint8Array) { return codec.decode(body); }
async function handler(req: Request) { return parseUpload(req.body); }
router.post("/upload", handler);
''',
        },
    })

    assert response.status_code == 200
    result = response.json()
    assert result["reachability"]["status"] == "REACHABLE"
    assert result["reachability"]["path"][-1] == "vulnerable-codec.decode"
    assert result["reachability"]["evidence_ids"]
    assert result["reachability"]["explanation"]
    assert result["reachability"]["limitations"]
    assert result["dependency_usages"]
    assert result["exposures"][0]["route"] == "/upload"

    stored = client.get(f"/api/v1/vulnerabilities/findings/{finding.id}").json()
    assert stored["reachability_status"] == "REACHABLE"
    assert stored["reachability_confidence"] > 0
    assert stored["reachability_path"][-1] == "vulnerable-codec.decode"
    assert stored["reachability_limitations"]


def test_reachability_api_uses_the_shared_interfile_graph():
    finding = _finding(["decode"])
    response = client.post("/api/v1/analysis/reachability", json={
        "finding_id": finding.id,
        "source_files": {
            "src/routes.ts": '''
import { uploadHandler } from "./handlers/upload";
router.post("/upload", uploadHandler);
''',
            "src/handlers/upload.ts": '''
import { decode } from "vulnerable-codec";
export function uploadHandler(req: Request) { return decode(req.body); }
''',
        },
    })

    assert response.status_code == 200
    reachability = response.json()["reachability"]
    assert reachability["status"] == "REACHABLE"
    assert any("src/handlers/upload.ts:" in step for step in reachability["path"])
    assert reachability["evidence_ids"]


def test_import_without_advisory_mapped_symbol_is_not_reachable():
    finding = _finding(["decode"])
    response = client.post("/api/v1/analysis/reachability", json={
        "finding_id": finding.id,
        "source_files": {
            "src/upload.ts": '''
import * as codec from "vulnerable-codec";
function handler(req: Request) { return codec.debounce(req.body); }
router.post("/upload", handler);
''',
        },
    })

    assert response.status_code == 200
    assert response.json()["reachability"]["status"] == "NOT_REACHABLE"


def test_advisory_without_symbol_mapping_stays_unknown():
    finding = _finding([])
    response = client.post("/api/v1/analysis/reachability", json={
        "finding_id": finding.id,
        "source_files": {"src/upload.py": "def handler():\n    return 'ok'\n"},
    })

    assert response.status_code == 200
    assert response.json()["reachability"]["status"] == "UNKNOWN"
