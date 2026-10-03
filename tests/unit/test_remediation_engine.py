"""Unit tests for Remediation Engine, PR generation, and Verification closure."""

from guardianos.attackpath.models import AttackPathStatus
from guardianos.attackpath.service import attack_path_service
from guardianos.intel.models import VulnerabilityFinding, VulnerabilitySeverity
from guardianos.intel.service import intel_service
from guardianos.inventory.models import DependencyState
from guardianos.inventory.service import inventory_service
from guardianos.remediation.generator import generate_remediation_task
from guardianos.remediation.models import RemediationStatus
from guardianos.remediation.service import remediation_service
from guardianos.remediation.verifier import verify_remediation_closure


def test_remediation_lifecycle_and_verification():
    inventory_service.clear()
    intel_service.clear()
    attack_path_service.clear()
    remediation_service.clear()

    # 1. Setup vulnerable component
    inventory_service.ingest_sbom(
        raw_content='{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "libheif", "version": "1.19.7", "purl": "pkg:deb/debian/libheif@1.19.7"}]}',
        application="image-service",
        default_state=DependencyState.RUNNING
    )
    comp = inventory_service.get_component("pkg:deb/debian/libheif@1.19.7")
    assert comp is not None

    intel_service.scan_all_components()

    paths = attack_path_service.recalculate_paths()
    assert len(paths) >= 1
    path = paths[0]
    assert path.status == AttackPathStatus.OPEN

    finding = intel_service.list_findings()[0]

    # 2. Generate remediation task & PR
    task = generate_remediation_task(finding, comp, path)
    assert task.status == RemediationStatus.PENDING_APPROVAL
    assert task.component_name == "libheif"
    assert task.target_version == "1.19.8"
    assert "Dockerfile" in task.pull_request.target_file
    assert "+    libheif=1.19.8" in task.pull_request.diff_content

    # 3. Simulate human approval
    task.status = RemediationStatus.APPROVED
    task.approval_actor = "lead-security-architect"

    # 4. Trigger verification closure
    evidence = verify_remediation_closure(task)

    assert task.status == RemediationStatus.VERIFIED_CLOSED
    assert evidence["attack_path_status"] == "CLOSED"
    assert evidence["vulnerability_status"] == "RESOLVED"
    assert evidence["message"] == "Remediation verified. Attack path CLOSED."
    
    # Query path from service
    updated_path = attack_path_service.get_path(path.id)
    assert updated_path is not None
    assert updated_path.status == AttackPathStatus.CLOSED
