"""Adversarial scanner tests for link traversal and bounded manifest parsing."""

import pytest
import subprocess

from osprey.parsers.docker import DockerParser
from osprey.parsers.npm import NpmParser
from osprey.scanner import scan_workspace


def test_workspace_scan_does_not_follow_manifest_symlinks(tmp_path):
    root = tmp_path / "workspace"
    outside = tmp_path / "outside-package.json"
    root.mkdir()
    outside.write_text('{"dependencies":{"private-outside-package":"9.9.9"}}', encoding="utf-8")
    try:
        (root / "package.json").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("file symlinks are unavailable on this host")

    result = scan_workspace(root, offline=True)

    assert all(component.name != "private-outside-package" for component in result.components)
    assert any("reparse-point" in item for item in result.source_analysis.errors)


def test_workspace_scan_does_not_descend_into_directory_junctions(tmp_path):
    root = tmp_path / "workspace"
    outside = tmp_path / "outside-directory"
    root.mkdir()
    outside.mkdir()
    (outside / "package.json").write_text(
        '{"dependencies":{"private-junction-package":"9.9.9"}}', encoding="utf-8"
    )
    junction = root / "linked"
    try:
        junction.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        result = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("neither directory symlinks nor junctions are available")

    result = scan_workspace(root, offline=True)

    assert all(component.name != "private-junction-package" for component in result.components)
    assert any("reparse-point" in item for item in result.source_analysis.errors)


def test_compose_manifest_cannot_read_dockerfile_outside_workspace(tmp_path):
    root = tmp_path / "workspace"
    outside = tmp_path / "private-context"
    root.mkdir()
    outside.mkdir()
    (root / "compose.yaml").write_text(
        "services:\n  app:\n    build: ../private-context\n", encoding="utf-8"
    )
    (outside / "Dockerfile").write_text("FROM private/base-image:9.9.9\n", encoding="utf-8")

    services = DockerParser().parse_services(root / "compose.yaml", workspace_root=root)

    assert services
    assert services[0].dockerfile_path is None
    assert services[0].build_context is None
    assert services[0].components == []


def test_npm_parser_refuses_oversized_manifest(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_bytes(b"{" + b" " * 20_000_000 + b"}")

    assert NpmParser().parse(manifest) == []


def test_workspace_scan_reports_oversized_manifest_as_limitation(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "package.json").write_bytes(b"{" + b" " * 20_000_000 + b"}")

    result = scan_workspace(root, offline=True)

    assert not result.components
    assert any("20 MB parser safety limit" in item for item in result.source_analysis.errors)


@pytest.mark.parametrize("contents", [
    '{"dependencies":{"axios":',
    '[]',
    '{"dependencies":[]}',
])
def test_malformed_npm_manifest_is_reported_as_a_limitation(tmp_path, contents):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "package.json").write_text(contents, encoding="utf-8")

    result = scan_workspace(root, offline=True)

    assert not result.components
    assert not result.findings
    assert any("package.json: npm manifest" in item for item in result.source_analysis.errors)


@pytest.mark.parametrize(("filename", "contents", "marker"), [
    ("pyproject.toml", "[project\ndependencies = ['requests']", "pyproject.toml could not be parsed"),
    ("compose.yaml", "services: [broken", "Compose manifest could not be parsed"),
])
def test_malformed_python_and_compose_manifests_are_reported(tmp_path, filename, contents, marker):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / filename).write_text(contents, encoding="utf-8")

    result = scan_workspace(root, offline=True)

    assert any(marker in item for item in result.source_analysis.errors)
