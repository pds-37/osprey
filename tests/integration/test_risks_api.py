"""Integration tests for Contextual Risk API."""

import json
from fastapi.testclient import TestClient
from guardianos.api.app import app
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service
from guardianos.risk.service import risk_service

client = TestClient(app)


def test_risks_api_flow(sample_spdx_json):
    inventory_service.clear()
    intel_service.clear()
    risk_service.clear()

    # Ingest SBOM
    client.post("/api/v1/sboms/upload", json={
        "content": json.loads(sample_spdx_json),
        "application": "image-service",
        "environment": "production",
        "state": "RUNNING"
    })

    # Trigger scan
    client.post("/api/v1/vulnerabilities/scan")

    # Evaluate risks
    resp = client.post("/api/v1/risks/evaluate")
    assert resp.status_code == 200
    risks = resp.json()
    assert len(risks) >= 1

    libheif_risk = next((r for r in risks if r["component_name"] == "libheif"), None)
    assert libheif_risk is not None
    assert libheif_risk["risk_level"] == "CRITICAL"
    assert len(libheif_risk["reasons"]) >= 3

    # Summary
    sum_resp = client.get("/api/v1/risks/summary")
    assert sum_resp.status_code == 200
    summary = sum_resp.json()
    assert summary["critical_count"] >= 1
    assert summary["total_findings"] >= 1
