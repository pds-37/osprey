"""Unit tests for finding explanation engine and CLI exit codes."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from rich.console import Console
from typer.testing import CliRunner

from osprey.cli import app
from osprey.explain import explain_finding
from osprey.fixes import FixStatus
from osprey.models import Component, ExposureInfo, Finding
from osprey.core.evidence import EvidenceStore
from osprey.core.models import EvidenceType
from osprey.core.evidence import EvidenceStore
from osprey.core.models import EvidenceType

runner = CliRunner()


def _build_test_finding(source_file: str):
    comp = Component(
        name="libheif",
        version="1.17.0",
        ecosystem="Debian",
        purl="pkg:deb/debian/libheif@1.17.0",
        is_dev=False,
        source_file=source_file,
    )
    return Finding(
        id="GHSA-w77h-v8r5-8vch",
        vulnerability_id="GHSA-w77h-v8r5-8vch",
        component=comp,
        exposure=ExposureInfo(level="public", confidence="inferred", evidence="Dockerfile: EXPOSE 8080"),
        fix_status=FixStatus(status="upstream fix released", minimal_safe_version=">= 1.19.8"),
        risk_tier="ACT NOW",
        firing_rule="Rule 1: public exposure AND Critical CVSS score (9.8 >= 9.0) -> ACT NOW",
        cvss_score=9.8,
        severity="CRITICAL",
        summary="Heap overflow vulnerability in libheif",
        aliases=["CVE-2023-49463"],
    )


def test_explain_evidence_chain_contains_rule_and_source():
    source_manifest = "services/image-parser/Dockerfile"
    finding = _build_test_finding(source_manifest)

    # Capture rich console output using recorded console
    rec_console = Console(record=True)
    found = explain_finding("GHSA-w77h-v8r5-8vch", [finding], out_console=rec_console)
    assert found is True

    rendered = rec_console.export_text()
    # 1. Contains exact firing rule
    assert "Rule 1: public exposure AND Critical CVSS score" in rendered
    # 2. Contains source file
    assert source_manifest in rendered
    # 3. Contains minimal safe version
    assert ">= 1.19.8" in rendered


def test_explain_not_found():
    rec_console = Console(record=True)
    found = explain_finding("NON-EXISTENT-ID", [], out_console=rec_console)
    assert found is False
    rendered = rec_console.export_text()
    assert "not found" in rendered.lower()


def test_cli_version_exit_code_0():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "Osprey v0.1.0" in result.stdout

    res_short = runner.invoke(app, ["-v"])
    assert res_short.exit_code == 0
    assert "Osprey v0.1.0" in res_short.stdout


def test_cli_scan_invalid_path_exit_code_2():
    result = runner.invoke(app, ["scan", "invalid_nonexistent_directory_xyz"])
    assert result.exit_code == 2
    assert "Scan error" in result.stderr
    # Must NOT show Python stack trace
    assert "Traceback (most recent call last)" not in result.stderr


def test_cli_explain_unknown_finding_exit_code_1(tmp_path: Path):
    result = runner.invoke(app, ["explain", "GHSA-fake-id", "--path", str(tmp_path)])
    assert result.exit_code == 1


def test_cli_explain_question_is_read_only_and_cites_verified_evidence(tmp_path: Path):
    finding = _build_test_finding("src/parser.py")
    store = EvidenceStore()
    version = store.add(
        evidence_type=EvidenceType.VERSION,
        source="Osprey version matcher",
        location="GHSA-w77h-v8r5-8vch",
        content='{"status":"AFFECTED"}',
        metadata={
            "status": "AFFECTED",
            "advisory_id": finding.vulnerability_id,
            "package": finding.component.name,
            "observed_version": finding.component.version,
        },
    )
    risk = store.add(
        evidence_type=EvidenceType.RISK,
        source="Osprey shared deterministic risk engine",
        location=f"finding:{finding.id}",
        content='{"decision":"ACT NOW"}',
        metadata={"finding_id": finding.id, "observed": {"assessment": {"decision": "ACT NOW"}}},
    )
    finding.evidence_ids = [version.id, risk.id]
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("unchanged", encoding="utf-8")
    before = sentinel.read_bytes()
    scan_result = MagicMock()
    scan_result.findings = [finding]
    scan_result.evidence = [version, risk]

    with patch("osprey.cli.scan_workspace", return_value=scan_result):
        response = runner.invoke(app, ["explain", finding.id, "--path", str(tmp_path), "--question", "Why is it risky?"])

    assert response.exit_code == 0
    assert "EVIDENCE_ONLY_READ_ONLY" in response.stdout
    assert "ACT NOW" in response.stdout
    assert version.id in response.stdout
    assert risk.id in response.stdout
    assert sentinel.read_bytes() == before


def test_cli_explain_question_preserves_unknown_when_evidence_missing(tmp_path: Path):
    finding = _build_test_finding("src/parser.py")
    finding.evidence_ids = []
    scan_result = MagicMock()
    scan_result.findings = [finding]
    scan_result.evidence = []
    with patch("osprey.cli.scan_workspace", return_value=scan_result):
        response = runner.invoke(app, ["explain", finding.id, "--path", str(tmp_path), "--question", "Why is it risky?"])
    assert response.exit_code == 0
    assert "Risk result is UNKNOWN" in response.stdout
    assert "Runtime state is UNKNOWN" in response.stdout


def test_cli_fail_on_policy_exit_codes(tmp_path: Path):
    # Setup dummy clean repo
    pj = tmp_path / "package.json"
    pj.write_text('{"dependencies": {}}')

    # 1. Clean repo should exit 0 even with --fail-on act-now
    res_clean = runner.invoke(app, ["scan", str(tmp_path), "--offline", "--fail-on", "act-now"])
    assert res_clean.exit_code == 0

    # 2. Mock a scan that returns an ACT NOW finding
    mock_scan_res = MagicMock()
    mock_scan_res.root_path = tmp_path
    mock_scan_res.app_name = "test"
    mock_scan_res.components = []
    mock_scan_res.manifests = []
    finding_act_now = _build_test_finding(str(pj))
    mock_scan_res.findings = [finding_act_now]

    with patch("osprey.cli.scan_workspace", return_value=mock_scan_res):
        # With --fail-on act-now, should exit 1
        res_fail_act_now = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "act-now"])
        assert res_fail_act_now.exit_code == 1

        # With --fail-on plan, should also exit 1 (act-now >= plan)
        res_fail_plan = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "plan"])
        assert res_fail_plan.exit_code == 1

        # Without --fail-on, should exit 0
        res_no_fail = runner.invoke(app, ["scan", str(tmp_path)])
        assert res_no_fail.exit_code == 0
