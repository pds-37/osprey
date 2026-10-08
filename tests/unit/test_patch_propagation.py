"""Unit tests for Patch Propagation Tracker."""

from guardianos.intel.models import VulnerabilityFinding, VulnerabilitySeverity
from guardianos.inventory.models import Component, DependencyState, Ecosystem
from guardianos.propagation.models import PropagationStage, StageStatus
from guardianos.propagation.tracker import evaluate_patch_propagation


def test_evaluate_patch_propagation_libheif():
    comp = Component(
        id="pkg:deb/debian/libheif@1.19.7",
        name="libheif",
        ecosystem=Ecosystem.DEBIAN,
        version="1.19.7",
        purl="pkg:deb/debian/libheif@1.19.7",
        state=DependencyState.RUNNING,
        application="media-upload-service",
        environment="production"
    )

    finding = VulnerabilityFinding(
        id="find-libheif-cve",
        vulnerability_id="CVE-2023-44398",
        component_purl=comp.purl,
        component_name=comp.name,
        installed_version="1.19.7",
        fixed_version="1.19.8",
        severity=VulnerabilitySeverity.CRITICAL,
        is_fix_available=True,
        application="media-upload-service"
    )

    record = evaluate_patch_propagation(finding, comp)

    assert record.component_name == "libheif"
    assert record.is_production_exposed is None
    assert record.bottleneck_stage is None
    assert record.stages[PropagationStage.UPSTREAM_FIX].status == StageStatus.UNKNOWN
    assert record.stages[PropagationStage.SECURITY_ADVISORY].status == StageStatus.COMPLETED
    assert record.stages[PropagationStage.DISTRIBUTION_PACKAGE].status == StageStatus.UNKNOWN
    assert record.stages[PropagationStage.BASE_IMAGE_REBUILD].status == StageStatus.UNKNOWN
    assert "status is unknown" in record.summary_explanation
