"""Integration tests for Attack Path API."""

import json
from fastapi.testclient import TestClient
from guardianos.api.app import app
from guardianos.attackpath.service import attack_path_service
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service

client = TestClient(app)


def test_attack_path_api_flow(sample_spdx_json):
    inventory_service.clear()
    intel_service.clear()
    attack_path_service.clear()

    # 1. Ingest vulnerable component
    client.post("/api/v1/sboms/upload", json={
        "content": json.loads(sample_spdx_json),
        "application": "image-service",
        "environment": "production",
        "state": "RUNNING"
    })

    # 2. Trigger scan
    client.post("/api/v1/vulnerabilities/scan")

    # 3. Recalculate attack paths
    resp = client.post("/api/v1/attack-paths/recalculate")
    assert resp.status_code == 200
    paths = resp.json()
    assert len(paths) >= 1

    libheif_path = next((p for p in paths if "libheif" in p["name"]), None)
    assert libheif_path is not None
    assert libheif_path["target_resource"] == "s3://customer-media-production"
    assert libheif_path["status"] == "OPEN"

    # 4. Get detail
    detail_resp = client.get(f"/api/v1/attack-paths/{libheif_path['id']}")
    assert detail_resp.status_code == 200
    assert len(detail_resp.json()["step_edges"]) == 6
