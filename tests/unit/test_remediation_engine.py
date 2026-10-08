"""Unit tests for Remediation Engine, PR generation, and Verification closure."""

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
        default_state=DependencyState.UNKNOWN
    )
    comp = inventory_service.get_component("pkg:deb/debian/libheif@1.19.7")
    assert comp is not None

    intel_service.scan_all_components()

    paths = attack_path_service.recalculate_paths()
    assert paths == []
    path = None

    finding = intel_service.list_findings()[0]

    # 2. Generate remediation task & PR
    task = generate_remediation_task(finding, comp, path)
    assert task.status == RemediationStatus.PENDING_APPROVAL
    assert task.component_name == "libheif"
    assert task.target_version == "1.19.8"
    assert task.pull_request.target_file is None
    assert task.pull_request.diff_content is None
    assert "did not edit a repository" in task.pull_request.body

    # 3. Simulate human approval
    task.status = RemediationStatus.APPROVED
    task.approval_actor = "lead-security-architect"

    # 4. Trigger verification closure
    evidence = verify_remediation_closure(task)

    assert task.status == RemediationStatus.UNVERIFIED
    assert evidence["attack_path_status"] == "NOT_OBSERVED"
    assert evidence["vulnerability_status"] == "UNKNOWN"
    assert "Upload a fresh SBOM" in evidence["message"]
    assert inventory_service.get_component("pkg:deb/debian/libheif@1.19.7") is not None


def test_fixed_version_in_inventory_does_not_claim_deployment_verified():
    inventory_service.clear()
    intel_service.clear()
    remediation_service.clear()

    inventory_service.ingest_sbom(
        raw_content='{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"name":"libheif","version":"1.19.7","purl":"pkg:deb/debian/libheif@1.19.7"}]}',
        application="image-service",
    )
    intel_service.scan_all_components()
    finding = intel_service.list_findings()[0]
    vulnerable = inventory_service.get_component(finding.component_purl)
    task = generate_remediation_task(finding, vulnerable)

    inventory_service.ingest_sbom(
        raw_content='{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"name":"libheif","version":"1.19.8","purl":"pkg:deb/debian/libheif@1.19.8"}]}',
        application="image-service",
        default_state=DependencyState.INSTALLED,
    )
    evidence = verify_remediation_closure(task)

    assert task.status == RemediationStatus.UNVERIFIED
    assert evidence["remediation_status"] == "RESOLVED_FOR_OBSERVED_COMPONENT"
    assert evidence["verification_scope"] == "inventory observation only"
    assert evidence["attack_path_status"] == "NOT_OBSERVED"
