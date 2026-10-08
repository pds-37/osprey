"""Integration tests for the deterministic evidence summary API."""

import json
from fastapi.testclient import TestClient
from guardianos.api.app import app
from guardianos.inventory.service import inventory_service

client = TestClient(app)


def test_ai_analyze_api(sample_spdx_json):
    inventory_service.clear()

    # Ingest component
    client.post("/api/v1/sboms/upload", json={
        "content": json.loads(sample_spdx_json),
        "application": "media-processor",
        "environment": "production"
    })

    # Trigger scan
    client.post("/api/v1/vulnerabilities/scan")

    # Post query
    resp = client.post("/api/v1/ai/analyze", json={
        "component_name": "libheif",
        "question": "Why is libheif dangerous in our production cluster?"
    })
    assert resp.status_code == 200
    report = resp.json()
    assert report["target_component"] == "libheif"
    assert report["exposure_verdict"].startswith("UNKNOWN")
    assert report["attack_path_summary"].startswith("NOT OBSERVED")
    assert report["analysis_mode"] == "DETERMINISTIC_EVIDENCE_SUMMARY"
    assert len(report["evidence_citations"]) >= 2
    assert report["evidence_ids"]
    assert all(evidence_id in " ".join(report["evidence_citations"]) for evidence_id in report["evidence_ids"])

    # Explain endpoint
    explain_resp = client.get("/api/v1/ai/explain/libheif")
    assert explain_resp.status_code == 200
    assert "upgrade" in explain_resp.json()["remediation_recommendation"].lower()
