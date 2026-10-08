import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from osprey.models import Component, ExposureInfo, Finding, FixStatus
from osprey.core.models import ReachabilityResult, ReachabilityStatus, VersionMatchStatus
from osprey.remediation import (
    RemediationApplyError,
    apply_npm_proposal,
    create_proposal,
    verify_post_scan,
)
from osprey.cli import app


def _finding(root):
    manifest = root / "package.json"
    return Finding(
        id="finding-1", vulnerability_id="GHSA-test", component=Component(
            name="demo", version="1.1.0", ecosystem="npm", purl="pkg:npm/demo@1.1.0",
            source_file=str(manifest),
        ), exposure=ExposureInfo("unknown", "unknown", "unknown"),
        fix_status=FixStatus(fixed_version="1.2.0"), risk_tier="PLAN", firing_rule="PLAN",
        raw_vuln={"affected": [{"package": {"name": "demo", "ecosystem": "npm"},
                                "ranges": [{"type": "SEMVER", "events": [
                                    {"introduced": "0"}, {"fixed": "1.2.0"}]}]}]},
        package_status=VersionMatchStatus.AFFECTED,
        reachability=ReachabilityResult(ReachabilityStatus.UNKNOWN, 0.0),
        risk_score=43.0, risk_level="MEDIUM",
    )


def _workspace(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"demo": "^1.1.0"}}))
    # Target is present as a nested install; root direct dependency is still 1.1.0.
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"demo": "^1.1.0"}},
            "node_modules/demo": {"version": "1.1.0"},
            "node_modules/other/node_modules/demo": {"version": "1.2.0"},
        },
    }))
    return tmp_path


def test_proposal_is_deterministic_read_only_and_uses_advisory_fixed_range(tmp_path):
    root = _workspace(tmp_path)
    original = [(root / name).read_bytes() for name in ("package.json", "package-lock.json")]
    first = create_proposal(root, _finding(root))
    second = create_proposal(root, _finding(root))
    assert first.proposal_id == second.proposal_id
    assert first.target_version == "1.2.0"
    assert first.status == "PROPOSED"
    assert [(root / name).read_bytes() for name in ("package.json", "package-lock.json")] == original


def test_duplicate_json_keys_fail_closed(tmp_path):
    root = _workspace(tmp_path)
    (root / "package.json").write_text(
        '{"dependencies":{"demo":"^1.1.0"},"dependencies":{"demo":"^1.1.0"}}',
        encoding="utf-8",
    )
    proposal = create_proposal(root, _finding(root))
    assert proposal.status == "UNSUPPORTED"
    assert proposal.target_version is None


def test_apply_requires_approval_and_rejects_stale_inputs(tmp_path):
    root = _workspace(tmp_path)
    proposal = create_proposal(root, _finding(root))
    with pytest.raises(PermissionError):
        apply_npm_proposal(root, proposal, approved=False, finding=_finding(root))
    (root / "package.json").write_text('{"dependencies":{"demo":"^1.1.1"}}')
    with pytest.raises(RuntimeError, match="STALE_PROPOSAL"):
        apply_npm_proposal(root, proposal, approved=True, finding=_finding(root))


def test_tampered_proposal_and_lockfile_staleness_are_rejected(tmp_path):
    root = _workspace(tmp_path)
    finding = _finding(root)
    proposal = create_proposal(root, finding)
    with pytest.raises(RuntimeError, match="STALE_PROPOSAL"):
        apply_npm_proposal(root, replace(proposal, target_version="9.9.9"),
                            approved=True, finding=finding)
    lockfile = root / "package-lock.json"
    lockfile.write_text('{"lockfileVersion":3,"packages":{}}')
    modified_by_user = lockfile.read_bytes()
    with pytest.raises(RuntimeError, match="STALE_PROPOSAL"):
        apply_npm_proposal(root, proposal, approved=True, finding=finding)
    assert lockfile.read_bytes() == modified_by_user


def test_apply_updates_only_approved_dependency_json_values(tmp_path):
    root = _workspace(tmp_path)
    proposal = create_proposal(root, _finding(root))
    result = apply_npm_proposal(root, proposal, approved=True, finding=_finding(root))
    manifest = json.loads((root / "package.json").read_text())
    lock = json.loads((root / "package-lock.json").read_text())
    assert result["status"] == "APPLIED"
    assert manifest["dependencies"]["demo"] == "^1.2.0"
    assert manifest["dependencies"].get("other") is None
    assert lock["packages"][""]["dependencies"]["demo"] == "^1.2.0"


def test_unsupported_package_manager_fails_closed(tmp_path):
    finding = _finding(tmp_path)
    finding.component.ecosystem = "pypi"
    assert create_proposal(tmp_path, finding).status == "UNSUPPORTED"


@pytest.mark.parametrize("bad_path", [
    "../outside/package.json",
    "C:\\outside\\package.json",
    "\\\\server\\share\\package.json",
])
def test_proposal_path_manipulation_is_rejected_without_writes(tmp_path, bad_path):
    root = _workspace(tmp_path)
    finding = _finding(root)
    proposal = create_proposal(root, finding)
    original = [(root / "package.json").read_bytes(), (root / "package-lock.json").read_bytes()]
    with pytest.raises(RuntimeError, match="STALE_PROPOSAL"):
        apply_npm_proposal(root, replace(proposal, manifest_path=bad_path),
                           approved=True, finding=finding)
    assert [(root / "package.json").read_bytes(), (root / "package-lock.json").read_bytes()] == original


def test_partial_apply_rolls_back_and_verifies_original_hashes(tmp_path, monkeypatch):
    root = _workspace(tmp_path)
    finding = _finding(root)
    proposal = create_proposal(root, finding)
    paths = [root / "package.json", root / "package-lock.json"]
    original = [path.read_bytes() for path in paths]
    real_replace = __import__("os").replace
    calls = 0

    def fail_second_replace(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("fixture failure")
        return real_replace(source, destination)

    monkeypatch.setattr("os.replace", fail_second_replace)
    with pytest.raises(RemediationApplyError) as error:
        apply_npm_proposal(root, proposal, approved=True, finding=finding)
    assert error.value.rollback_verified is True
    assert [path.read_bytes() for path in paths] == original


def test_rollback_failure_is_reported_without_claiming_recovery(tmp_path, monkeypatch):
    root = _workspace(tmp_path)
    finding = _finding(root)
    proposal = create_proposal(root, finding)
    manifest = root / "package.json"
    original = manifest.read_bytes()
    real_replace = __import__("os").replace
    calls = 0

    def fail_second_replace(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("fixture failure")
        return real_replace(source, destination)

    real_write_bytes = type(manifest).write_bytes

    def fail_manifest_rollback(path, data):
        if path == manifest and data == original:
            raise OSError("rollback fixture failure")
        return real_write_bytes(path, data)

    monkeypatch.setattr("os.replace", fail_second_replace)
    monkeypatch.setattr(type(manifest), "write_bytes", fail_manifest_rollback)
    with pytest.raises(RemediationApplyError) as error:
        apply_npm_proposal(root, proposal, approved=True, finding=finding)
    assert error.value.rollback_verified is False


def test_post_scan_verification_distinguishes_unknown_failed_and_verified(tmp_path):
    root = _workspace(tmp_path)
    finding = _finding(root)
    proposal = create_proposal(root, finding)
    locked = Component(name="demo", version="1.2.0", ecosystem="npm",
                       purl="pkg:npm/demo@1.2.0", source_file="package-lock.json")
    scan = SimpleNamespace(components=[locked], findings=[], advisory_coverage={}, source_analysis=None)
    unknown = verify_post_scan(proposal, scan)
    assert unknown["state"] == "UNKNOWN"
    assert "advisory coverage was insufficient" in unknown["reason"]
    scan.advisory_coverage = {locked.observation_id: "COMPLETE"}
    verified = verify_post_scan(proposal, scan)
    assert verified["state"] == "VERIFIED"
    scan.findings = [finding]
    failed = verify_post_scan(proposal, scan)
    assert failed["state"] == "FAILED"


def test_cli_proposal_and_apply_use_shared_engine_and_rescan(tmp_path, monkeypatch):
    root = _workspace(tmp_path)
    finding = _finding(root)
    proposal = create_proposal(root, finding)
    before = SimpleNamespace(findings=[finding], components=[finding.component],
                             source_analysis=SimpleNamespace(files_scanned=[]), advisory_coverage={})
    locked = Component(name="demo", version="1.2.0", ecosystem="npm",
                       purl="pkg:npm/demo@1.2.0", source_file=str(root / "package-lock.json"))
    after = SimpleNamespace(findings=[], components=[locked], source_analysis=SimpleNamespace(files_scanned=[]),
                            advisory_coverage={locked.observation_id: "COMPLETE"})
    scans = iter((before, before, after))
    monkeypatch.setattr("osprey.cli.scan_workspace", lambda *args, **kwargs: next(scans))
    runner = CliRunner()
    proposal_result = runner.invoke(app, ["remediate", finding.id, "--path", str(root)])
    assert proposal_result.exit_code == 0, proposal_result.output
    proposal_json = json.loads(proposal_result.output)
    assert proposal_json[0]["proposal_id"] == proposal.proposal_id
    manifest_before = (root / "package.json").read_bytes()
    applied = runner.invoke(app, ["remediate", finding.id, "--path", str(root),
                                  "--apply", proposal.proposal_id, "--approve"])
    assert applied.exit_code == 0, applied.output
    result = json.loads(applied.output)
    assert result["status"] == "APPLIED"
    assert result["verification"] == "VERIFIED"
    assert result["verification_result"]["risk_after"]["decision"] == "UNKNOWN"
    assert (root / "package.json").read_bytes() != manifest_before
