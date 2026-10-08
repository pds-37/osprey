"""API and end-to-end remediation tests use isolated temporary npm projects only."""

import hashlib
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import datetime, timezone
from threading import Barrier, Lock

import pytest
from fastapi.testclient import TestClient

from guardianos.api.app import app
from guardianos.core.config import settings
from guardianos.core.security import CurrentUser, UserRole, get_current_user
from guardianos.remediation.workflow import RemediationWorkflow, WorkflowError
from guardianos.storage.evidence import evidence_store
from osprey.intel.cache import IntelCache
from osprey.models import Component
from osprey.remediation import create_proposal
from osprey.scanner import scan_workspace


client = TestClient(app)
ADVISORY = {
    "id": "GHSA-phase7-fixture",
    "summary": "Fixture advisory; no exploit behavior is exercised.",
    "affected": [{
        "package": {"ecosystem": "npm", "name": "demo"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}],
    }],
    "database_specific": {"severity": "HIGH"},
}


def _fixture(root: Path, cache_dir: Path):
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({
        "name": "fixture-app", "dependencies": {"demo": "^1.1.0"},
    }), encoding="utf-8")
    (root / "package-lock.json").write_text(json.dumps({
        "name": "fixture-app", "lockfileVersion": 3,
        "packages": {
            "": {"name": "fixture-app", "dependencies": {"demo": "^1.1.0"}},
            "node_modules/demo": {"version": "1.1.0", "resolved": "https://fixture.invalid/demo-1.1.0.tgz", "integrity": "sha512-old"},
            "node_modules/parent/node_modules/demo": {"version": "1.2.0", "resolved": "https://fixture.invalid/demo-1.2.0.tgz", "integrity": "sha512-fixed"},
        },
    }), encoding="utf-8")
    cache = IntelCache(cache_dir=cache_dir, offline=True)
    for version, advisories in (("1.1.0", [ADVISORY]), ("1.2.0", [])):
        component = Component(name="demo", version=version, ecosystem="npm", purl=f"pkg:npm/demo@{version}")
        cache.set("osv", component.key, advisories)
        cache.set("osv_coverage", component.key, {
            "status": "COMPLETE", "observed_at": datetime.now(timezone.utc).isoformat(),
        })
    return [(root / "package.json").read_bytes(), (root / "package-lock.json").read_bytes()]


def _file_hashes(root: Path):
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob("*") if path.is_file()}


def test_api_end_to_end_proposal_approval_apply_rescan_evidence(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    cache = tmp_path / "osprey-cache"
    original = _fixture(root, cache)
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("OSPREY_CACHE_DIR", str(cache))
    baseline = scan_workspace(root, offline=True)
    finding = next(item for item in baseline.findings
                   if item.vulnerability_id == ADVISORY["id"]
                   and item.component.source_file.endswith("package.json"))
    assert finding is not None
    cli_proposal = create_proposal(root, finding)
    before_hashes = _file_hashes(root)

    create = client.post("/api/v1/remediation/proposals", json={
        "finding_id": finding.id, "workspace": ".",
    })
    assert create.status_code == 201, create.text
    state = create.json()
    proposal = state["proposal"]
    assert state["proposal_id"] == cli_proposal.proposal_id
    assert proposal["status"] == "PROPOSED"
    assert proposal["target_version"] == "1.2.0"
    assert _file_hashes(root) == before_hashes

    retrieved = client.get(f"/api/v1/remediation/proposals/{state['proposal_id']}")
    assert retrieved.status_code == 200
    assert retrieved.json()["proposal_id"] == state["proposal_id"]
    assert state["evidence_ids"]
    assert state["finding_evidence_ids"]
    for evidence_id in state["finding_evidence_ids"]:
        assert client.get(f"/api/v1/evidence/{evidence_id}").status_code == 200
    for evidence_id in state["evidence_ids"]:
        evidence = client.get(f"/api/v1/evidence/{evidence_id}")
        assert evidence.status_code == 200
        assert evidence.json()["integrity_status"] == "VERIFIED"
        assert evidence.json()["content"] == ""

    approved = client.post(f"/api/v1/remediation/proposals/{state['proposal_id']}/approve")
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"
    applied = client.post(f"/api/v1/remediation/proposals/{state['proposal_id']}/apply",
                          json={"workspace": "."})
    assert applied.status_code == 200, applied.text
    completed = applied.json()
    assert completed["application"]["status"] == "APPLIED"
    assert completed["verification_state"] == "VERIFIED"
    assert completed["verification"]["post_scan_completed"] is True
    assert completed["verification"]["observed_locked_versions"] == ["1.2.0"]
    assert completed["verification"]["risk_after"]["decision"] == "UNKNOWN"
    assert completed["verification"]["risk_delta"] is None
    assert completed["evidence_ids"]
    persisted_events = [evidence_store.get(item) for item in completed["evidence_ids"]]
    assert all(record is not None for record in persisted_events)
    observations = [record.metadata["observed"] for record in persisted_events]
    assert all(item["proposal_id"] == state["proposal_id"] for item in observations)
    assert all(item["finding_id"] == finding.id for item in observations)
    assert all(item["dependency_identity"]["package"] == "demo" for item in observations)
    assert all(item["before_state"]["version"] == "1.1.0" for item in observations)
    assert all(item["proposed_state"]["version"] == "1.2.0" for item in observations)
    assert all(set(item["file_hashes"]["before"]) == {"package.json", "package-lock.json"}
               for item in observations)
    applied_event = next(item for item in observations if item["after_state"]["state"] == "APPLIED")
    verified_event = next(item for item in observations if item["after_state"]["state"] == "VERIFIED")
    assert applied_event["after_state"]["version"] == "1.2.0"
    assert set(applied_event["file_hashes"]["after"]) == {"package.json", "package-lock.json"}
    assert verified_event["after_state"]["locked_versions"] == ["1.2.0"]
    status_response = client.get(f"/api/v1/remediation/proposals/{state['proposal_id']}/status")
    verify_response = client.get(f"/api/v1/remediation/proposals/{state['proposal_id']}/verification")
    assert status_response.json()["status"] == "VERIFIED"
    assert verify_response.json()["state"] == "VERIFIED"

    manifest = json.loads((root / "package.json").read_text())
    lock = json.loads((root / "package-lock.json").read_text())
    assert manifest["dependencies"]["demo"] == "^1.2.0"
    assert lock["packages"]["node_modules/demo"]["version"] == "1.2.0"
    changed = {name for name, digest in _file_hashes(root).items() if before_hashes.get(name) != digest}
    assert changed == {"package.json", "package-lock.json"}
    assert len(original) == 2

    replay = client.post(f"/api/v1/remediation/proposals/{state['proposal_id']}/apply",
                         json={"workspace": "."})
    assert replay.status_code == 409


def test_api_apply_without_approval_and_stale_proposal_do_not_modify_files(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    cache = tmp_path / "osprey-cache"
    _fixture(root, cache)
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("OSPREY_CACHE_DIR", str(cache))
    finding = next(item for item in scan_workspace(root, offline=True).findings
                   if item.vulnerability_id == ADVISORY["id"]
                   and item.component.source_file.endswith("package.json"))
    response = client.post("/api/v1/remediation/proposals", json={"finding_id": finding.id})
    proposal_id = response.json()["proposal_id"]
    original_hashes = _file_hashes(root)
    no_approval = client.post(f"/api/v1/remediation/proposals/{proposal_id}/apply", json={})
    assert no_approval.status_code == 409
    assert _file_hashes(root) == original_hashes

    assert client.post(f"/api/v1/remediation/proposals/{proposal_id}/approve").status_code == 200
    manifest_path = root / "package.json"
    manifest_path.write_text('{"name":"fixture-app","dependencies":{"demo":"^1.1.1"}}', encoding="utf-8")
    changed_hashes = _file_hashes(root)
    stale = client.post(f"/api/v1/remediation/proposals/{proposal_id}/apply", json={})
    assert stale.status_code == 409
    assert stale.json()["detail"] == "STALE_PROPOSAL"
    assert _file_hashes(root) == changed_hashes


def test_api_proposal_access_is_owner_scoped_and_requires_auth(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    cache = tmp_path / "osprey-cache"
    _fixture(root, cache)
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("OSPREY_CACHE_DIR", str(cache))
    finding = next(item for item in scan_workspace(root, offline=True).findings
                   if item.vulnerability_id == ADVISORY["id"]
                   and item.component.source_file.endswith("package.json"))
    state = client.post("/api/v1/remediation/proposals", json={"finding_id": finding.id}).json()
    proposal_id = state["proposal_id"]
    admin_override = app.dependency_overrides[get_current_user]
    try:
        app.dependency_overrides.pop(get_current_user, None)
        assert client.get(f"/api/v1/remediation/proposals/{proposal_id}").status_code == 401
        app.dependency_overrides[get_current_user] = lambda: CurrentUser(
            username="different-user", role=UserRole.VIEWER, org_id="default-org")
        assert client.get(f"/api/v1/remediation/proposals/{proposal_id}").status_code == 404
        assert client.get("/api/v1/remediation/proposals/rp-../../etc").status_code == 404
    finally:
        app.dependency_overrides[get_current_user] = admin_override


def test_api_apply_failure_persists_verified_rollback_evidence(tmp_path, monkeypatch):
    from guardianos.remediation import workflow as workflow_module
    from osprey.remediation import RemediationApplyError

    root = tmp_path / "workspace"
    cache = tmp_path / "osprey-cache"
    _fixture(root, cache)
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("OSPREY_CACHE_DIR", str(cache))
    finding = next(item for item in scan_workspace(root, offline=True).findings
                   if item.vulnerability_id == ADVISORY["id"]
                   and item.component.source_file.endswith("package.json"))
    created = client.post("/api/v1/remediation/proposals", json={"finding_id": finding.id})
    proposal_id = created.json()["proposal_id"]
    assert client.post(f"/api/v1/remediation/proposals/{proposal_id}/approve").status_code == 200
    before = _file_hashes(root)

    def fail_apply(*args, **kwargs):
        raise RemediationApplyError("fixture apply failure; rollback verified",
                                    rollback_verified=True, files_attempted=())

    monkeypatch.setattr(workflow_module, "apply_npm_proposal", fail_apply)
    response = client.post(f"/api/v1/remediation/proposals/{proposal_id}/apply", json={})
    assert response.status_code == 500
    state = client.get(f"/api/v1/remediation/proposals/{proposal_id}").json()
    assert state["status"] == "FAILED"
    rollback_ids = [item for item in state["evidence_ids"]
                    if evidence_store.get(item).type.value == "REMEDIATION_ROLLBACK"]
    assert rollback_ids
    rollback_record = client.get(f"/api/v1/evidence/{rollback_ids[0]}").json()
    assert rollback_record["metadata"]["observed"]["rollback_verified"] is True
    assert _file_hashes(root) == before


def test_api_rejects_wrong_workspace_and_malicious_paths(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    cache = tmp_path / "osprey-cache"
    _fixture(root, cache)
    (root / "other").mkdir()
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(root))
    monkeypatch.setenv("OSPREY_CACHE_DIR", str(cache))
    finding = next(item for item in scan_workspace(root, offline=True).findings
                   if item.vulnerability_id == ADVISORY["id"]
                   and item.component.source_file.endswith("package.json"))
    created = client.post("/api/v1/remediation/proposals", json={"finding_id": finding.id})
    proposal_id = created.json()["proposal_id"]
    assert client.post(f"/api/v1/remediation/proposals/{proposal_id}/approve").status_code == 200
    snapshot = _file_hashes(root)
    wrong_workspace = client.post(f"/api/v1/remediation/proposals/{proposal_id}/apply",
                                  json={"workspace": "other"})
    assert wrong_workspace.status_code == 403
    assert _file_hashes(root) == snapshot
    for candidate in ("../outside", str(tmp_path), "C:\\private", "\\\\server\\share"):
        result = client.post("/api/v1/remediation/proposals", json={
            "finding_id": finding.id, "workspace": candidate,
        })
        assert result.status_code in (403, 422)
    assert client.get("/api/v1/remediation/proposals/rp-../../etc").status_code == 404


def test_workspace_resolver_blocks_symlink_escapes(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(root))
    escape = root / "nested" / "escape"
    escape.parent.mkdir()
    try:
        os.symlink(outside, escape, target_is_directory=True)
    except (OSError, NotImplementedError):
        # Windows directory junctions provide the same path-resolution escape
        # condition without requiring the symlink privilege.
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(escape), str(outside)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("neither directory symlinks nor junctions are available")
    with pytest.raises(WorkflowError) as error:
        RemediationWorkflow().resolve_workspace("nested/escape")
    assert error.value.status_code == 403
    if escape.exists():
        os.rmdir(escape)


def test_workspace_resolver_rejects_nested_symlink_resolved_outside_root(tmp_path, monkeypatch):
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside" / "nested" / "project"
    outside.mkdir(parents=True)
    nested = root / "nested"
    nested.mkdir()
    fake_link_target = nested / "link" / "project"
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(root))
    real_resolve = Path.resolve

    def resolve_nested(path, *args, **kwargs):
        if path == fake_link_target:
            return outside
        return real_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve_nested)
    with pytest.raises(WorkflowError) as error:
        RemediationWorkflow().resolve_workspace("nested/link/project")
    assert error.value.code == "WORKSPACE_OUTSIDE_ALLOWED_ROOT"


def test_concurrent_apply_claims_proposal_once(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    cache = tmp_path / "osprey-cache"
    _fixture(root, cache)
    monkeypatch.setattr(settings, "WORKSPACE_ROOT", str(root))
    monkeypatch.setattr(settings, "AUTH_USERS_JSON", json.dumps({
        "admin": {"password_hash": "pbkdf2_sha256$100000$c2FsdA$ZGlnZXN0",
                  "role": "admin", "org_id": "default-org"},
    }))
    monkeypatch.setenv("OSPREY_CACHE_DIR", str(cache))
    user = CurrentUser(username="admin", role=UserRole.ADMIN, org_id="default-org")
    workflow = RemediationWorkflow()
    finding = next(item for item in scan_workspace(root, offline=True).findings
                   if item.vulnerability_id == ADVISORY["id"]
                   and item.component.source_file.endswith("package.json"))
    state = workflow.create(finding.id, ".", user=user)
    workflow.approve(state["proposal_id"], user=user)

    real_scan = workflow._scan
    scan_barrier = Barrier(2)
    scan_lock = Lock()
    preapply_scans = 0

    def synchronized_scan(scan_root):
        nonlocal preapply_scans
        result = real_scan(scan_root)
        with scan_lock:
            preapply_scans += 1
            wait_for_peer = preapply_scans <= 2
        if wait_for_peer:
            scan_barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(workflow, "_scan", synchronized_scan)

    def apply_once():
        try:
            workflow.apply(state["proposal_id"], ".", user=user)
            return "APPLIED"
        except WorkflowError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: apply_once(), range(2)))

    assert outcomes.count("APPLIED") == 1
    assert outcomes.count("DUPLICATE_OR_REPLAYED_APPLY") == 1
