import json

from fastapi.testclient import TestClient

from guardianos.api.app import app, create_app
from guardianos.core.config import settings
from guardianos.core.security import get_current_user, get_password_hash
from guardianos.remediation.models import PullRequestProposal, RemediationActionType, RemediationStatus, RemediationTask
from guardianos.remediation.service import _remediation_tasks_db

client = TestClient(app)


def _configure_users(monkeypatch):
    monkeypatch.setattr(settings, "SECRET_KEY", "test-key-that-is-at-least-32-bytes-long")
    monkeypatch.setattr(settings, "ENVIRONMENT", "test")
    monkeypatch.setattr(settings, "AUTH_USERS_JSON", json.dumps({
        "viewer": {"password_hash": get_password_hash("viewer-pass", rounds=100_000), "role": "viewer"},
        "engineer": {"password_hash": get_password_hash("engineer-pass", rounds=100_000), "role": "security_engineer"},
        "admin": {"password_hash": get_password_hash("admin-pass", rounds=100_000), "role": "admin"},
    }))


def _token(username: str, password: str) -> str:
    response = client.post("/api/v1/auth/token", data={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def test_unauthenticated_mutation_returns_401(monkeypatch):
    _configure_users(monkeypatch)
    app.dependency_overrides.pop(get_current_user, None)
    response = client.post("/api/v1/sboms/clear")
    assert response.status_code == 401
    read_response = client.get("/api/v1/components")
    assert read_response.status_code == 401


def test_request_body_limit_enforced_before_authentication(monkeypatch):
    monkeypatch.setattr(settings, "MAX_REQUEST_BODY_BYTES", 1024)
    limited_client = TestClient(create_app())
    response = limited_client.post("/api/v1/sboms/upload", content=b"x" * 1025)
    assert response.status_code == 413


def test_production_app_requires_strong_configured_signing_key(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SECRET_KEY", None)
    try:
        create_app()
    except RuntimeError as error:
        assert "SECRET_KEY must be configured" in str(error)
    else:
        raise AssertionError("production app creation must reject a missing signing secret")


def test_viewer_cannot_mutate_but_security_engineer_can(monkeypatch):
    _configure_users(monkeypatch)
    app.dependency_overrides.pop(get_current_user, None)

    viewer_token = _token("viewer", "viewer-pass")
    engineer_token = _token("engineer", "engineer-pass")
    denied = client.post("/api/v1/sboms/clear", headers={"Authorization": f"Bearer {viewer_token}"})
    assert denied.status_code == 403
    engineer_clear_denied = client.post("/api/v1/sboms/clear", headers={"Authorization": f"Bearer {engineer_token}"})
    assert engineer_clear_denied.status_code == 403
    viewer_read = client.get("/api/v1/components", headers={"Authorization": f"Bearer {viewer_token}"})
    assert viewer_read.status_code == 200

    allowed = client.post(
        "/api/v1/sboms/upload",
        headers={"Authorization": f"Bearer {engineer_token}"},
        json={"content": {"bomFormat": "CycloneDX", "specVersion": "1.4", "version": 1, "components": []}},
    )
    assert allowed.status_code == 201

    denied_approval = client.post(
        "/api/v1/remediation/tasks/test-task/approve",
        headers={"Authorization": f"Bearer {engineer_token}"},
    )
    assert denied_approval.status_code == 403


def test_admin_approval_is_attributed_to_authenticated_user(monkeypatch):
    _configure_users(monkeypatch)
    app.dependency_overrides.pop(get_current_user, None)
    admin_token = _token("admin", "admin-pass")
    clear_response = client.post("/api/v1/sboms/clear", headers={"Authorization": f"Bearer {admin_token}"})
    assert clear_response.status_code == 200
    _remediation_tasks_db.clear()
    task = RemediationTask(
        id="test-task",
        vulnerability_id="GHSA-test-test-test",
        component_name="example",
        current_version="1.0.0",
        target_version="1.0.1",
        action_type=RemediationActionType.UPGRADE_PACKAGE,
        status=RemediationStatus.PENDING_APPROVAL,
        pull_request=PullRequestProposal(title="Upgrade example", body="Proposal", branch_name=None, target_file=None, diff_content=None),
    )
    _remediation_tasks_db[task.id] = task
    _remediation_tasks_db[task.id] = task
    response = client.post(
        "/api/v1/remediation/tasks/test-task/approve",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert response.json()["approval_actor"] == "admin"
    _remediation_tasks_db.clear()
