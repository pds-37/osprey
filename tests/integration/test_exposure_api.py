"""Integration tests for Exposure Analyzer API."""

import json
from fastapi.testclient import TestClient
from guardianos.api.app import app
from guardianos.inventory.service import inventory_service

client = TestClient(app)


def test_exposure_api_flow(sample_spdx_json):
    inventory_service.clear()

    # Ingest component
    client.post("/api/v1/sboms/upload", json={
        "content": json.loads(sample_spdx_json),
        "application": "image-service",
        "environment": "production",
        "state": "RUNNING"
    })

    # Query endpoints
    eps_resp = client.get("/api/v1/exposure/endpoints")
    assert eps_resp.status_code == 200
    eps = eps_resp.json()
    assert len(eps) >= 1

    # Query exposure profile for libheif
    prof_resp = client.get("/api/v1/exposure/libheif")
    assert prof_resp.status_code == 200
    prof = prof_resp.json()
    assert prof["component_name"] == "libheif"
    assert prof["network_exposure"] == "INTERNET_FACING"
    assert prof["auth_requirement"] == "NONE"
    assert len(prof["reasons"]) >= 2
