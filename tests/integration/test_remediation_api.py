"""Integration tests for Remediation & Verification API."""

import json
from fastapi.testclient import TestClient
from guardianos.api.app import app
from guardianos.attackpath.service import attack_path_service
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service
from guardianos.remediation.service import remediation_service

client = TestClient(app)


def test_remediation_api_approval_and_verification_flow(sample_spdx_json):
    inventory_service.clear()
    intel_service.clear()
    attack_path_service.clear()
    remediation_service.clear()

    # 1. Ingest vulnerable component
    client.post("/api/v1/sboms/upload", json={
        "content": json.loads(sample_spdx_json),
        "application": "image-service",
        "environment": "production",
        "state": "RUNNING"
    })

    # 2. Trigger vulnerability scan
    client.post("/api/v1/vulnerabilities/scan")

    # 3. Recalculate attack paths
    path_resp = client.post("/api/v1/attack-paths/recalculate")
    assert path_resp.status_code == 200
    assert len(path_resp.json()) >= 1

    # 4. Generate remediation tasks
    gen_resp = client.post("/api/v1/remediation/generate")
    assert gen_resp.status_code == 200
    tasks = gen_resp.json()
    assert len(tasks) >= 1
    task = tasks[0]
    assert task["status"] == "PENDING_APPROVAL"
    assert "Dockerfile" in task["pull_request"]["target_file"]

    # 5. Human approval gate
    appr_resp = client.post(f"/api/v1/remediation/tasks/{task['id']}/approve", json={"actor": "priyanshu@secops"})
    assert appr_resp.status_code == 200
    assert appr_resp.json()["status"] == "APPROVED"
    assert appr_resp.json()["approval_actor"] == "priyanshu@secops"

    # 6. Post-deployment verification rescan
    ver_resp = client.post(f"/api/v1/remediation/tasks/{task['id']}/verify")
    assert ver_resp.status_code == 200
    ver_task = ver_resp.json()
    assert ver_task["status"] == "VERIFIED_CLOSED"
    assert ver_task["verification_evidence"]["attack_path_status"] == "CLOSED"
    assert ver_task["verification_evidence"]["message"] == "Remediation verified. Attack path CLOSED."
