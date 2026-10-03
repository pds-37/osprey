"""Integration tests for Patch Propagation API."""

import json
from fastapi.testclient import TestClient
from guardianos.api.app import app
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service
from guardianos.propagation.service import propagation_service

client = TestClient(app)


def test_patch_propagation_api_flow(sample_spdx_json):
    inventory_service.clear()
    intel_service.clear()
    propagation_service.clear()

    # Ingest SPDX with libheif
    client.post("/api/v1/sboms/upload", json={
        "content": json.loads(sample_spdx_json),
        "application": "media-processor",
        "environment": "production",
        "state": "RUNNING"
    })

    # Trigger vulnerability scan
    client.post("/api/v1/vulnerabilities/scan")

    # Evaluate patch propagation
    resp = client.post("/api/v1/patches/evaluate")
    assert resp.status_code == 200
    records = resp.json()
    assert len(records) >= 1

    libheif_rec = next((r for r in records if r["component_name"] == "libheif"), None)
    assert libheif_rec is not None
    assert libheif_rec["is_production_exposed"] is True
    assert "The upstream fix exists" in libheif_rec["summary_explanation"]
