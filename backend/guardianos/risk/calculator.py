"""Backend adapter to Osprey's authoritative shared risk calculation."""

from typing import List, Optional

from dataclasses import asdict
from osprey.core.provenance import record_risk_assessment
from osprey.core.models import EvidenceType
from osprey.runtime import summarize_runtime_state
from osprey.risk import RiskEvidence, calculate_risk
from guardianos.attackpath.models import AttackPath, AttackPathStatus
from guardianos.exposure.models import AuthRequirement, ExposureProfile, NetworkExposure
from guardianos.intel.models import VulnerabilityFinding
from guardianos.inventory.models import Component
from guardianos.risk.models import ContextualRiskScore, RiskFactor, RiskLevel
from guardianos.storage.evidence import evidence_store


def _has_evidence(evidence_ids: list[str], evidence_type: EvidenceType) -> bool:
    return any(
        (record := evidence_store.get(evidence_id)) is not None and record.type == evidence_type
        for evidence_id in evidence_ids
    )


def calculate_contextual_risk(
    finding: VulnerabilityFinding,
    component: Component,
    exposure: Optional[ExposureProfile],
    attack_path: Optional[AttackPath],
) -> ContextualRiskScore:
    """Normalize backend evidence, call the shared engine, and map its result to the API model."""
    fixture = bool(attack_path and attack_path.fixture)
    evidence_ids = list(finding.evidence_ids)
    asserted_endpoints = [
        endpoint for endpoint in (exposure.endpoints if exposure else [])
        if endpoint.evidence_source == "USER_INPUT"
        and _has_evidence(endpoint.evidence_ids, EvidenceType.USER_INPUT)
    ]
    network_values = {endpoint.network_exposure for endpoint in asserted_endpoints} - {NetworkExposure.UNKNOWN}
    auth_values = {endpoint.auth_requirement for endpoint in asserted_endpoints}
    network_limitations: list[str] = []
    if len(network_values) > 1:
        network = "UNKNOWN"
        network_limitations.append("Conflicting user-provided network exposure assertions were observed.")
    elif NetworkExposure.INTERNET_FACING in network_values:
        network = "PUBLIC"
    elif NetworkExposure.INTERNAL_NETWORK in network_values:
        network = "INTERNAL"
    elif network_values & {NetworkExposure.LOCALHOST_ONLY, NetworkExposure.ISOLATED}:
        network = "LOCAL"
    else:
        network = "UNKNOWN"
    processing_values = {endpoint.processing_type.value for endpoint in asserted_endpoints}
    processing = (
        "PARSER_UNTRUSTED_INPUT" if any("PARSER" in value for value in processing_values)
        else next((value for value in sorted(processing_values) if value != "UNKNOWN"), "UNKNOWN")
    )
    if AuthRequirement.NONE in auth_values:
        auth_requirement = "NONE"
    elif auth_values & {AuthRequirement.OPTIONAL, AuthRequirement.REQUIRED, AuthRequirement.MFA_REQUIRED}:
        auth_requirement = next(value.value for value in sorted(auth_values, key=lambda item: item.value) if value != AuthRequirement.UNKNOWN)
    else:
        auth_requirement = "UNKNOWN"
    evidence_ids.extend(eid for endpoint in asserted_endpoints for eid in endpoint.evidence_ids)

    source_reachability = finding.reachability_status
    path_confidence = finding.reachability_confidence
    has_static_path_evidence = any(
        _has_evidence(finding.evidence_ids, evidence_type)
        for evidence_type in (EvidenceType.ROUTE, EvidenceType.FUNCTION, EvidenceType.IMPORT)
    )
    if source_reachability == "REACHABLE" and not has_static_path_evidence:
        source_reachability = "UNKNOWN"
    if source_reachability == "REACHABLE":
        evidence_ids.extend(
            evidence_id for evidence_id in finding.evidence_ids
            if (record := evidence_store.get(evidence_id)) is not None
            and record.type in {EvidenceType.ROUTE, EvidenceType.FUNCTION, EvidenceType.IMPORT}
        )
    elif source_reachability == "NOT_REACHABLE":
        # A bounded negative result is scored only when the source analysis has no recorded limits.
        pass

    if (
        source_reachability != "REACHABLE"
        and attack_path
        and attack_path.status == AttackPathStatus.OPEN
        and not attack_path.fixture
        and attack_path.evidence
        and any(item.startswith("ev-") and evidence_store.get(item) for item in attack_path.evidence)
    ):
        source_reachability = "REACHABLE"
        path_confidence = attack_path.confidence
        has_static_path_evidence = True
        evidence_ids.extend(item for item in attack_path.evidence if item.startswith("ev-"))

    runtime_snapshot = summarize_runtime_state(
        evidence_store,
        package_name=finding.component_name,
        ecosystem=(finding.vulnerability.ecosystem.value if finding.vulnerability else component.ecosystem.value).lower(),
        version=finding.observed_version or finding.installed_version or component.version,
        declared_observed=finding.declared_version is not None,
        locked_observed=finding.locked_version is not None,
        installed_observed=finding.installed_version is not None,
        finding_id=finding.id,
    )
    runtime_observed = runtime_snapshot.loaded_current
    evidence_ids.extend(runtime_snapshot.evidence_ids)

    version_status = str(finding.package_status or "UNKNOWN").upper()
    cvss = finding.vulnerability.cvss_score if finding.vulnerability else None
    risk_inputs = RiskEvidence(
        severity=finding.severity.value,
        cvss_score=cvss,
        epss_score=finding.epss_score,
        kev_listed=(
            True if finding.kev_listed is True else
            False if finding.kev_available and finding.kev_listed is False else None
        ),
        version_status=version_status,
        dependency_present=True,
        exposure=network,
        exposure_confidence="USER_ASSERTED" if network != "UNKNOWN" else "UNKNOWN",
        auth_requirement=auth_requirement,
        processing_type=processing,
        reachability_status=source_reachability,
        reachability_confidence=path_confidence,
        source_analysis_complete=not bool(finding.reachability_limitations),
        runtime_observed=True if runtime_observed else None,
        evidence_ids=tuple(dict.fromkeys(evidence_ids)),
        limitations=tuple([
            *finding.reachability_limitations,
            *finding.runtime_limitations,
            *runtime_snapshot.limitations,
            *network_limitations,
        ]),
    )
    assessment = calculate_risk(risk_inputs)
    risk_record = record_risk_assessment(
        evidence_store,
        risk_inputs,
        assessment,
        finding_id=finding.id,
    )

    reasons: List[str] = [assessment.explanation]
    if cvss is None and finding.severity.value != "UNKNOWN":
        reasons.append("No CVSS score was observed; the advisory severity is used as a coarse package-level signal.")
    if finding.severity.value in {"HIGH", "CRITICAL"}:
        reasons.append("High or critical advisory severity warrants review; severity alone does not establish exploitability.")
    if source_reachability == "UNKNOWN":
        reasons.append("No evidence-backed application reachability result is available.")
    elif source_reachability == "REACHABLE":
        reasons.append(
            f"Supported source-level reachability is REACHABLE at confidence {path_confidence:.2f}; this does not establish deployment or Internet exposure."
        )
    elif source_reachability == "NOT_REACHABLE":
        reasons.append("The submitted source bundle did not establish a path; this bounded negative result does not prove universal unreachability.")
    if network == "UNKNOWN":
        reasons.append("Network exposure is UNKNOWN; source routes do not establish external ingress.")
    if fixture:
        reasons.append("Synthetic demo endpoint/path data was excluded from risk scoring.")
    reasons.extend(assessment.limitations)

    evidence: List[str] = []
    if cvss is not None:
        evidence.append(f"Advisory {finding.vulnerability_id} reports CVSS {cvss}.")
    elif finding.severity.value != "UNKNOWN":
        evidence.append(f"Advisory {finding.vulnerability_id} reports severity {finding.severity.value}.")
    if asserted_endpoints:
        evidence.append("Network and processing context comes from linked user-provided endpoint assertions; it is not independently verified.")

    return ContextualRiskScore(
        id=f"risk-{finding.id}",
        finding_id=finding.id,
        component_purl=component.purl,
        component_name=component.name,
        vulnerability_id=finding.vulnerability_id,
        risk_level=RiskLevel(assessment.risk_level),
        composite_score=assessment.score,
        evidence_coverage=assessment.evidence_coverage,
        fixture=fixture,
        cvss_score=cvss,
        risk_inputs=asdict(risk_inputs),
        decision=assessment.decision,
        reasons=list(dict.fromkeys(reasons)),
        factors=[RiskFactor(
            name=factor.name,
            weight=factor.weight,
            score=factor.score,
            description=factor.description,
        ) for factor in assessment.factors],
        attack_path_id=attack_path.id if attack_path else None,
        potential_impact=(
            f"{assessment.explanation} Application-context evidence is not established for all analysis dimensions."
            if assessment.score is None else assessment.explanation
        ),
        evidence=evidence,
        evidence_ids=list(dict.fromkeys([*assessment.evidence_ids, risk_record.id])),
        provenance_ids={"risk": risk_record.id},
        limitations=list(assessment.limitations),
    )
