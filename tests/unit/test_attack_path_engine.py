"""Unit tests for Attack Path Engine graph traversal."""

from guardianos.attackpath.engine import construct_attack_paths
from guardianos.attackpath.models import AttackPathStatus, NodeRole
from guardianos.intel.models import VulnerabilityFinding, VulnerabilitySeverity
from guardianos.intel.service import intel_service
from guardianos.inventory.models import Component, DependencyState, Ecosystem
from guardianos.inventory.service import inventory_service


def test_construct_attack_path_full_flow():
    inventory_service.clear()
    intel_service.clear()

    comp = Component(
        id="pkg:deb/debian/libheif@1.19.7",
        name="libheif",
        ecosystem=Ecosystem.DEBIAN,
        version="1.19.7",
        purl="pkg:deb/debian/libheif@1.19.7",
        state=DependencyState.RUNNING,
        application="image-service",
        environment="production"
    )
    inventory_service.ingest_sbom(
        raw_content='{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "libheif", "version": "1.19.7", "purl": "pkg:deb/debian/libheif@1.19.7"}]}',
        application="image-service"
    )

    # Trigger vulnerability match
    intel_service.scan_all_components()

    # Normal analysis must not infer public ingress or cloud assets from package state.
    paths = construct_attack_paths()
    assert paths == []

    # Synthetic paths are available only in the explicit fixture mode.
    paths = construct_attack_paths(include_demo_fixtures=True)
    assert len(paths) >= 1
    p = paths[0]
    assert p.fixture is True
    assert p.status == AttackPathStatus.OPEN
    assert p.entry_point == "Internet (POST /upload)"
    assert p.target_resource == "s3://customer-media-production"
    assert len(p.nodes) == 7

    # Verify node sequence roles
    assert p.nodes[0].role == NodeRole.ENTRY_POINT
    assert p.nodes[1].role == NodeRole.ROUTE
    assert p.nodes[2].role == NodeRole.SERVICE
    assert p.nodes[3].role == NodeRole.VULNERABLE_COMPONENT
    assert p.nodes[4].role == NodeRole.EXECUTION_PRIMITIVE
    assert p.nodes[5].role == NodeRole.PRIVILEGE_TRANSITION
    assert p.nodes[6].role == NodeRole.HIGH_VALUE_TARGET
