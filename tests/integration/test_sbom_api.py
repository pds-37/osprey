"""Integration tests for GuardianOS FastAPI endpoints."""

import json
from fastapi.testclient import TestClient
from guardianos.api.app import app

client = TestClient(app)


def test_health_endpoints():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

    ready_resp = client.get("/ready")
    assert ready_resp.status_code == 200
    assert ready_resp.json()["status"] == "ready"


def test_sbom_upload_and_query_flow(sample_cyclonedx_json):
    # 1. Upload CycloneDX JSON
    payload = {
        "content": json.loads(sample_cyclonedx_json),
        "application": "payment-gateway",
        "environment": "production",
        "state": "UNKNOWN"
    }
    upload_resp = client.post("/api/v1/sboms/upload", json=payload)
    assert upload_resp.status_code == 201
    data = upload_resp.json()
    assert data["application"] == "payment-gateway"
    assert data["components_count"] == 4
    assert data["relationships_count"] == 3
    assert all(component["state"] != "RUNNING" for component in data["components"])

    # 2. List SBOMs
    list_resp = client.get("/api/v1/sboms")
    assert list_resp.status_code == 200
    sboms = list_resp.json()
    assert len(sboms) >= 1

    # 3. List components
    comp_resp = client.get("/api/v1/components?application=payment-gateway")
    assert comp_resp.status_code == 200
    comps = comp_resp.json()
    assert len(comps) == 4

    # 4. Query single component detail
    target_purl = "pkg:pypi/fastapi@0.110.0"
    detail_resp = client.get(f"/api/v1/components/detail?purl={target_purl}")
    assert detail_resp.status_code == 200
    comp_detail = detail_resp.json()
    assert comp_detail["name"] == "fastapi"
    assert comp_detail["ecosystem"] == "pypi"

    # 5. Component lineage
    lineage_resp = client.get(f"/api/v1/components/lineage?purl={target_purl}")
    assert lineage_resp.status_code == 200
    lineage = lineage_resp.json()
    assert lineage["found"] is True

    # 6. Graph data query
    graph_resp = client.get("/api/v1/graph/data")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert len(graph_data["nodes"]) >= 4
    assert len(graph_data["edges"]) >= 3

    # 7. Audit log verification
    audit_resp = client.get("/api/v1/audit/events")
    assert audit_resp.status_code == 200
    events = audit_resp.json()
    assert any(e["action"] == "SBOM_INGESTED" for e in events)


def test_clear_inventory_endpoint():
    clear_resp = client.post("/api/v1/sboms/clear")
    assert clear_resp.status_code == 200
    assert clear_resp.json()["status"] == "cleared"

    # Confirm components, sboms, and graph are empty
    assert client.get("/api/v1/components").json() == []
    assert client.get("/api/v1/sboms").json() == []
    graph = client.get("/api/v1/graph/data").json()
    assert len(graph["nodes"]) == 0
    assert len(graph["edges"]) == 0
