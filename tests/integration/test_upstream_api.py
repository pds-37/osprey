"""Integration tests for Upstream Changes API endpoints."""

from fastapi.testclient import TestClient
from guardianos.api.app import app

client = TestClient(app)


def test_list_upstream_changes_seeded():
    resp = client.get("/api/v1/upstream-changes")
    assert resp.status_code == 200
    commits = resp.json()
    assert len(commits) >= 1
    libheif_c = next((c for c in commits if c["component_name"] == "libheif"), None)
    assert libheif_c is not None
    assert libheif_c["classification"] == "SUSPECTED_SECURITY_CHANGE"
    assert "integer conversion" in libheif_c["detected_signals"]


def test_analyze_commit_api():
    payload = {
        "repository": "OpenSSL/openssl",
        "commit_sha": "a1b2c3d4e5f67890",
        "component_name": "openssl",
        "author": "Security Team",
        "message": "Fix buffer overflow and memory allocation in handshake parser",
        "diff_summary": "int check_bounds(size_t len) { if (len > MAX) return -1; }"
    }
    resp = client.post("/api/v1/upstream-changes/analyze", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["classification"] == "SUSPECTED_SECURITY_CHANGE"
    assert data["confidence"] >= 0.70
    assert "buffer overflow" in data["detected_signals"]
