"""Regression tests for server-side organization and evidence ownership checks."""

import json

from fastapi.testclient import TestClient

from guardianos.api.app import app
from guardianos.core.config import settings
from guardianos.core.security import CurrentUser, UserRole, get_current_user
from guardianos.intel.models import VulnerabilityFinding
from guardianos.intel.service import _findings_db, intel_service
from guardianos.inventory.models import Component, Ecosystem
from guardianos.inventory.service import _components_db, inventory_service
from guardianos.storage.evidence import evidence_store
from guardianos.storage.sqlite import state_store
from osprey.core.models import EvidenceType


client = TestClient(app)


def _configure_two_organizations(monkeypatch):
    placeholder = "pbkdf2_sha256$100000$c2FsdA$ZGlnZXN0"
    monkeypatch.setattr(settings, "AUTH_USERS_JSON", json.dumps({
        "alice": {"password_hash": placeholder, "role": "viewer", "org_id": "org-a"},
        "bob": {"password_hash": placeholder, "role": "viewer", "org_id": "org-b"},
    }))
    previous = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        username="alice", role=UserRole.VIEWER, org_id="org-a"
    )
    return previous


def _restore_user(previous):
    if previous is None:
        app.dependency_overrides.pop(get_current_user, None)
    else:
        app.dependency_overrides[get_current_user] = previous


def test_finding_and_evidence_id_substitution_is_denied(monkeypatch):
    previous = _configure_two_organizations(monkeypatch)
    evidence_a = evidence_store.add(
        evidence_type=EvidenceType.USER_INPUT,
        source="security isolation fixture",
        location="org-a",
        content="evidence-a",
        metadata={"organization_id": "org-a"},
    )
    evidence_b = evidence_store.add(
        evidence_type=EvidenceType.USER_INPUT,
        source="security isolation fixture",
        location="org-b",
        content="evidence-b",
        metadata={"organization_id": "org-b"},
    )
    findings = []
    for suffix, org, record in (("a", "org-a", evidence_a), ("b", "org-b", evidence_b)):
        finding = VulnerabilityFinding(
            id=f"sec-org-finding-{suffix}",
            vulnerability_id="CVE-2099-9001",
            component_purl=f"pkg:npm/org-fixture-{suffix}@1.0.0",
            component_name=f"org-fixture-{suffix}",
            observed_version="1.0.0",
            evidence_ids=[record.id],
            organization_id=org,
        )
        intel_service.save_finding(finding)
        findings.append(finding)
    try:
        assert client.get("/api/v1/vulnerabilities/findings/sec-org-finding-a").status_code == 200
        assert client.get("/api/v1/vulnerabilities/findings/sec-org-finding-b").status_code == 404
        assert client.get(f"/api/v1/evidence/{evidence_a.id}").status_code == 200
        assert client.get(f"/api/v1/evidence/{evidence_b.id}").status_code == 404
    finally:
        _restore_user(previous)
        for finding in findings:
            _findings_db.pop(finding.id, None)
            state_store.delete("findings", finding.id)
        # Keep evidence in the store because IDs are content-addressed and it may
        # already be referenced by a prior persisted finding.


def test_remediation_finding_evidence_is_owner_org_scoped(monkeypatch):
    previous = _configure_two_organizations(monkeypatch)
    record = evidence_store.add(
        evidence_type=EvidenceType.USER_INPUT,
        source="security isolation fixture",
        location="remediation-finding-evidence",
        content="finding evidence",
        metadata={"organization_id": "org-a"},
    )
    workflow_id = "rp-" + "a" * 24
    state_store.put("remediation_workflows", workflow_id, {
        "proposal_id": workflow_id,
        "owner": "alice",
        "org_id": "org-a",
        "finding_evidence_ids": [record.id],
        "evidence_ids": [],
    })
    try:
        assert client.get(f"/api/v1/evidence/{record.id}").status_code == 200
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(
            username="bob", role=UserRole.VIEWER, org_id="org-b"
        )
        assert client.get(f"/api/v1/evidence/{record.id}").status_code == 404
    finally:
        state_store.delete("remediation_workflows", workflow_id)
        _restore_user(previous)


def test_inventory_reads_are_organization_scoped(monkeypatch):
    previous = _configure_two_organizations(monkeypatch)
    components = []
    for suffix, org in (("a", "org-a"), ("b", "org-b")):
        component = Component(
            id=f"pkg:npm/org-fixture-{suffix}@1.0.0",
            name=f"org-fixture-{suffix}",
            version="1.0.0",
            ecosystem=Ecosystem.NPM,
            purl=f"pkg:npm/org-fixture-{suffix}@1.0.0",
            organization_id=org,
        )
        inventory_service.save_component(component)
        components.append(component)
    try:
        listed = client.get("/api/v1/components?limit=1000")
        assert listed.status_code == 200
        visible = {item["organization_id"] for item in listed.json()}
        assert visible == {"org-a"}
        assert client.get("/api/v1/components/detail", params={"purl": components[0].purl}).status_code == 200
        assert client.get("/api/v1/components/detail", params={"purl": components[1].purl}).status_code == 404
    finally:
        _restore_user(previous)
        for component in components:
            _components_db.pop(component.observation_id, None)
            state_store.delete("components", component.observation_id)


def test_global_legacy_api_fails_closed_when_multiple_organizations_are_configured(monkeypatch):
    previous = _configure_two_organizations(monkeypatch)
    try:
        for path in ("/api/v1/graph/data", "/api/v1/risks", "/api/v1/audit/events"):
            response = client.get(path)
            assert response.status_code == 409
            assert response.json()["detail"] == "ENDPOINT_UNAVAILABLE_IN_MULTI_ORGANIZATION_MODE"
        response = client.post("/api/v1/sboms/clear")
        assert response.status_code == 403  # viewer role rejected before the handler
    finally:
        _restore_user(previous)


def test_local_workspace_scan_and_remediation_fail_closed_for_multiple_organizations(monkeypatch):
    previous = _configure_two_organizations(monkeypatch)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        username="alice", role=UserRole.SECURITY_ENGINEER, org_id="org-a"
    )
    try:
        scan = client.post("/api/v1/sboms/scan-local-manifests", json={
            "path": "org-b/private-workspace",
            "clear_existing": False,
        })
        assert scan.status_code == 409
        assert scan.json()["detail"] == "WORKSPACE_SCAN_REQUIRES_SINGLE_ORGANIZATION_MODE"

        proposal = client.post("/api/v1/remediation/proposals", json={
            "finding_id": "finding-from-another-workspace",
            "workspace": "org-b/private-workspace",
        })
        assert proposal.status_code == 409
        assert proposal.json()["detail"] == "WORKSPACE_ACCESS_REQUIRES_SINGLE_ORGANIZATION_MODE"
    finally:
        _restore_user(previous)
