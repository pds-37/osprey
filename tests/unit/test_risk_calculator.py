"""Unit tests for Contextual Risk calculation engine."""

from guardianos.attackpath.engine import construct_attack_paths
from osprey.core.models import EvidenceType
from guardianos.exposure.models import (
    AuthRequirement,
    DataProcessingType,
    EndpointProfile,
    ExposureRating,
    NetworkExposure,
)
from guardianos.exposure.service import exposure_service
from guardianos.intel.models import VulnerabilityFinding, VulnerabilityRecord, VulnerabilitySeverity, VulnerabilitySource
from guardianos.intel.service import intel_service
from guardianos.inventory.models import DependencyState
from guardianos.inventory.service import inventory_service
from guardianos.risk.calculator import calculate_contextual_risk
from guardianos.risk.models import RiskLevel
from guardianos.storage.evidence import evidence_store
from osprey.risk import RiskEvidence, calculate_risk


def test_contextual_risk_libheif_critical():
    inventory_service.clear()
    intel_service.clear()

    # Ingest component into inventory
    inventory_service.ingest_sbom(
        raw_content='{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [{"name": "libheif", "version": "1.19.7", "purl": "pkg:deb/debian/libheif@1.19.7"}]}',
        application="image-service",
        default_state=DependencyState.UNKNOWN
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
        package_status="AFFECTED",
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

    assert exposure.network_exposure == NetworkExposure.UNKNOWN
    assert exposure.exposure_rating == ExposureRating.UNKNOWN
    assert risk.risk_level == RiskLevel.UNKNOWN
    assert risk.composite_score is None
    assert risk.evidence_coverage == 0.25
    assert any("severity warrants review" in r for r in risk.reasons)
    assert any("UNKNOWN" in r for r in risk.reasons)
    assert any("No evidence-backed application reachability" in r for r in risk.reasons)
    assert risk.evidence == ["Advisory CVE-2023-44398 reports CVSS 9.8."]
    assert len(risk.evidence_ids) == 1
    risk_evidence = evidence_store.get(risk.evidence_ids[0])
    assert risk_evidence is not None
    assert risk_evidence.type == EvidenceType.RISK
    assert evidence_store.integrity_status(risk_evidence) == "VERIFIED"
    assert "not established" in risk.potential_impact
    shared = calculate_risk(RiskEvidence(
        severity="CRITICAL",
        cvss_score=9.8,
        version_status="AFFECTED",
        dependency_present=True,
        exposure="UNKNOWN",
        reachability_status="UNKNOWN",
        reachability_confidence=0.0,
        source_analysis_complete=True,
    ))
    assert risk.composite_score == shared.score
    assert risk.risk_level.value == shared.risk_level
    assert risk.decision == shared.decision
    assert [(f.name, f.weight, f.score) for f in risk.factors] == [
        (f.name, f.weight, f.score) for f in shared.factors
    ]


def test_contextual_risk_uses_linked_user_endpoint_evidence():
    inventory_service.clear()
    intel_service.clear()
    exposure_service.clear()
    inventory_service.ingest_sbom(
        raw_content='{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"name":"libheif","version":"1.19.7","purl":"pkg:deb/debian/libheif@1.19.7"}]}',
        application="image-service",
        default_state=DependencyState.INSTALLED,
    )
    component = inventory_service.get_component("pkg:deb/debian/libheif@1.19.7")
    assert component is not None
    finding = VulnerabilityFinding(
        id="finding-context-test",
        vulnerability_id="CVE-2023-44398",
        component_purl=component.purl,
        component_name=component.name,
        installed_version=component.version,
        fixed_version="1.19.8",
        severity=VulnerabilitySeverity.CRITICAL,
        package_status="AFFECTED",
        vulnerability=VulnerabilityRecord(
            id="CVE-2023-44398",
            summary="Test advisory",
            ecosystem=component.ecosystem,
            component_name=component.name,
            severity=VulnerabilitySeverity.CRITICAL,
            cvss_score=9.8,
            source=VulnerabilitySource.DEBIAN,
        ),
    )
    endpoint = exposure_service.register_endpoint(EndpointProfile(
        id="test:upload",
        path="POST /upload",
        service="image-service",
        network_exposure=NetworkExposure.INTERNET_FACING,
        auth_requirement=AuthRequirement.NONE,
        processing_type=DataProcessingType.PARSER_UNTRUSTED_INPUT,
        connected_components=["libheif"],
    ))
    profile = exposure_service.get_component_exposure(component.purl)
    assert profile is not None

    risk = calculate_contextual_risk(finding, component, profile, None)

    assert risk.risk_level == RiskLevel.CRITICAL
    assert risk.decision == "PLAN"
    assert risk.composite_score is not None
    assert risk.evidence_coverage == 0.6
    assert endpoint.evidence_ids
    assert set(endpoint.evidence_ids).issubset(risk.evidence_ids)


def test_backend_shared_engine_parity_for_reachability_states():
    inventory_service.clear()
    intel_service.clear()
    exposure_service.clear()
    evidence_store.clear()
    inventory_service.ingest_sbom(
        raw_content='{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"name":"libheif","version":"1.19.7","purl":"pkg:deb/debian/libheif@1.19.7"}]}',
        application="image-service",
        default_state=DependencyState.INSTALLED,
    )
    component = inventory_service.get_component("pkg:deb/debian/libheif@1.19.7")
    assert component is not None

    cases = [
        ("UNKNOWN", 0.0, ()),
        ("NOT_REACHABLE", 0.95, ()),
    ]
    route_record = evidence_store.add(
        evidence_type=EvidenceType.ROUTE,
        source="test source analyzer",
        location="routes/upload.py:12",
        content="POST /upload",
    )
    function_record = evidence_store.add(
        evidence_type=EvidenceType.FUNCTION,
        source="test source analyzer",
        location="services/parser.py:24",
        content="parse_document",
    )
    cases.append(("REACHABLE", 0.9, (route_record.id, function_record.id)))

    for status, confidence, evidence_ids in cases:
        finding = VulnerabilityFinding(
            id=f"finding-{status.lower()}",
            vulnerability_id="CVE-2023-44398",
            component_purl=component.purl,
            component_name=component.name,
            installed_version=component.version,
            fixed_version="1.19.8",
            severity=VulnerabilitySeverity.CRITICAL,
            package_status="AFFECTED",
            reachability_status=status,
            reachability_confidence=confidence,
            evidence_ids=list(evidence_ids),
            vulnerability=VulnerabilityRecord(
                id="CVE-2023-44398",
                summary="Test advisory",
                ecosystem=component.ecosystem,
                component_name=component.name,
                severity=VulnerabilitySeverity.CRITICAL,
                cvss_score=9.8,
                source=VulnerabilitySource.DEBIAN,
            ),
        )
        backend_result = calculate_contextual_risk(finding, component, None, None)
        shared_result = calculate_risk(RiskEvidence(
            severity="CRITICAL",
            cvss_score=9.8,
            version_status="AFFECTED",
            dependency_present=True,
            exposure="UNKNOWN",
            reachability_status=status,
            reachability_confidence=confidence,
            source_analysis_complete=True,
            evidence_ids=evidence_ids,
        ))
        assert backend_result.composite_score == shared_result.score
        assert backend_result.risk_level.value == shared_result.risk_level
        assert backend_result.decision == shared_result.decision
        assert [(factor.name, factor.weight, factor.score) for factor in backend_result.factors] == [
            (factor.name, factor.weight, factor.score) for factor in shared_result.factors
        ]
