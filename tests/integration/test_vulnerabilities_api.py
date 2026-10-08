"""Integration tests for Vulnerability Intelligence APIs."""

import json
from fastapi.testclient import TestClient
from guardianos.api.app import app
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service

client = TestClient(app)


def test_vulnerability_scan_api(sample_spdx_json):
    inventory_service.clear()
    intel_service.clear()

    # 1. Ingest SPDX containing libheif 1.19.7 and ImageMagick
    upload_payload = {
        "content": json.loads(sample_spdx_json),
        "application": "image-processing-service",
        "environment": "production",
        "state": "UNKNOWN"
    }
    client.post("/api/v1/sboms/upload", json=upload_payload)

    # 2. Trigger vulnerability scan
    scan_resp = client.post("/api/v1/vulnerabilities/scan")
    assert scan_resp.status_code == 200
    findings = scan_resp.json()
    assert len(findings) >= 1

    # Verify libheif finding
    libheif_find = next((f for f in findings if f["component_name"] == "libheif"), None)
    assert libheif_find is not None
    assert libheif_find["vulnerability_id"] == "CVE-2023-44398"
    assert libheif_find["severity"] == "CRITICAL"
    assert libheif_find["fixed_version"] == "1.19.8"

    # 3. Query list endpoint
    list_resp = client.get("/api/v1/vulnerabilities?severity=CRITICAL")
    assert list_resp.status_code == 200
    crit_findings = list_resp.json()
    assert any(f["vulnerability_id"] == "CVE-2023-44398" for f in crit_findings)

    # 4. Query advisories endpoint
    adv_resp = client.get("/api/v1/vulnerabilities/advisories/CVE-2023-44398")
    assert adv_resp.status_code == 200
    adv = adv_resp.json()
    assert adv["id"] == "CVE-2023-44398"
    assert adv["component_name"] == "libheif"
