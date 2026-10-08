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
        "state": "UNKNOWN"
    })

    # 2. Trigger scan
    client.post("/api/v1/vulnerabilities/scan")

    # 3. Recalculate attack paths
    resp = client.post("/api/v1/attack-paths/recalculate")
    assert resp.status_code == 200
    paths = resp.json()
    # An SBOM alone provides no route, function, or cloud evidence. The API
    # must not invent a path from the package to a cloud resource.
    assert paths == []
