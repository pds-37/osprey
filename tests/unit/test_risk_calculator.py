"""Unit tests for Contextual Risk calculation engine."""

from guardianos.attackpath.engine import construct_attack_paths
from guardianos.exposure.service import exposure_service
from guardianos.intel.models import VulnerabilityFinding, VulnerabilityRecord, VulnerabilitySeverity, VulnerabilitySource
from guardianos.intel.service import intel_service
from guardianos.inventory.models import DependencyState
from guardianos.inventory.service import inventory_service
from guardianos.risk.calculator import calculate_contextual_risk
from guardianos.risk.models import RiskLevel


def test_contextual_risk_libheif_critical():
    inventory_service.clear()
    intel_service.clear()

    # Ingest component into inventory
    inventory_service.ingest_sbom(
        raw_content='{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "libheif", "version": "1.19.7", "purl": "pkg:deb/debian/libheif@1.19.7"}]}',
        application="image-service",
        default_state=DependencyState.RUNNING
    )
    comp = inventory_service.get_component("pkg:deb/debian/libheif@1.19.7")
    assert comp is not None

    adv = VulnerabilityRecord(
        id="CVE-2023-44398",
        summary="Heap overflow in libheif",
        details="Heap buffer overflow RCE",
        ecosystem=comp.ecosystem,
        component_name=comp.name,
        affected_version_ranges=["< 1.19.8"],
        fixed_versions=["1.19.8"],
        severity=VulnerabilitySeverity.CRITICAL,
        cvss_score=9.8,
        source=VulnerabilitySource.DEBIAN
    )

    finding = VulnerabilityFinding(
        id="find-libheif-test",
        vulnerability_id="CVE-2023-44398",
        component_purl=comp.purl,
        component_name=comp.name,
        installed_version="1.19.7",
        fixed_version="1.19.8",
        severity=VulnerabilitySeverity.CRITICAL,
        is_fix_available=True,
        application="image-service",
        environment="production",
        vulnerability=adv
    )

    exposure = exposure_service.get_component_exposure("libheif")
    assert exposure is not None

    paths = construct_attack_paths()
    path = paths[0] if paths else None

    risk = calculate_contextual_risk(
        finding=finding,
        component=comp,
        exposure=exposure,
        attack_path=path
    )

    assert risk.risk_level == RiskLevel.CRITICAL
    assert risk.composite_score >= 80.0
    assert any("Remote exploitation possible" in r for r in risk.reasons)
    assert any("Internet-facing endpoint" in r for r in risk.reasons)
    assert any("Vulnerable parser" in r for r in risk.reasons)
    assert len(risk.evidence) >= 2
    assert "Potential remote takeover" in risk.potential_impact
