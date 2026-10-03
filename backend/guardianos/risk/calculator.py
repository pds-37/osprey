"""Contextual Risk calculation engine evaluating multi-dimensional threats."""

from typing import List, Optional
from guardianos.attackpath.models import AttackPath, AttackPathStatus
from guardianos.exposure.models import AuthRequirement, ExposureProfile, NetworkExposure
from guardianos.intel.models import VulnerabilityFinding
from guardianos.inventory.models import Component, DependencyState
from guardianos.risk.models import ContextualRiskScore, RiskFactor, RiskLevel


def calculate_contextual_risk(
    finding: VulnerabilityFinding,
    component: Component,
    exposure: Optional[ExposureProfile],
    attack_path: Optional[AttackPath]
) -> ContextualRiskScore:
    """
    Calculate explainable contextual risk combining vulnerability metrics,
    ingress exposure, attack paths, and data sensitivity.
    """
    factors: List[RiskFactor] = []
    reasons: List[str] = []
    evidence: List[str] = []

    # 1. Vulnerability Factor (25%)
    cvss = finding.vulnerability.cvss_score if finding.vulnerability else 7.5
    vuln_score = (cvss / 10.0) * 100.0 if cvss else 75.0
    factors.append(RiskFactor(
        name="Vulnerability Severity",
        weight=0.25,
        score=round(vuln_score, 1),
        description=f"Base CVSS score of {cvss} ({finding.severity.value})"
    ))
    if vuln_score >= 80:
        reasons.append("Remote exploitation possible via high/critical severity advisory.")
    evidence.append(f"Advisory {finding.vulnerability_id} has CVSS {cvss}.")

    # 2. Exposure & Authentication Factor (30%)
    has_internet = (exposure and exposure.network_exposure == NetworkExposure.INTERNET_FACING)
    unauth = (exposure and exposure.auth_requirement == AuthRequirement.NONE)
    if has_internet and unauth:
        exp_score = 100.0
        reasons.append("Internet-facing endpoint reachable without authentication.")
        evidence.append("Connected endpoint is public and unauthenticated.")
    elif has_internet:
        exp_score = 70.0
        reasons.append("Internet-facing endpoint with authentication required.")
    elif exposure and exposure.network_exposure == NetworkExposure.INTERNAL_NETWORK:
        exp_score = 40.0
        reasons.append("Reachable only from internal network.")
    else:
        exp_score = 15.0
        reasons.append("Local or isolated service boundary.")

    factors.append(RiskFactor(
        name="Network Exposure & Ingress",
        weight=0.30,
        score=exp_score,
        description="Public Internet accessibility and authentication posture"
    ))

    # 3. Parser & Untrusted Input (15%)
    if exposure and "parser" in exposure.processing_type.value.lower():
        proc_score = 100.0
        reasons.append("Vulnerable parser actively processes attacker-controlled data.")
        evidence.append("Component acts as primary file/image decoder for upload route.")
    else:
        proc_score = 30.0

    factors.append(RiskFactor(
        name="Untrusted Input Processing",
        weight=0.15,
        score=proc_score,
        description="Whether component processes untrusted external binary payloads"
    ))

    # 4. Attack Path & Asset Reachability (20%)
    if attack_path and attack_path.status == AttackPathStatus.OPEN:
        path_score = 100.0
        reasons.append(f"Compromised service has verified path to cloud storage ({attack_path.target_resource}).")
        evidence.append(f"End-to-end graph traversal confirms open attack path: {attack_path.name}.")
    else:
        path_score = 10.0

    factors.append(RiskFactor(
        name="Attack Path Reachability",
        weight=0.20,
        score=path_score,
        description="Discovered attack paths reaching cloud resources or sensitive stores"
    ))

    # 5. Production Environment State (10%)
    is_prod = (component.environment.lower() == "production")
    is_running = (component.state == DependencyState.RUNNING)
    if is_prod and is_running:
        runtime_score = 100.0
        reasons.append("Active production environment running in live workloads.")
    elif is_prod:
        runtime_score = 70.0
        reasons.append("Production image ready for deployment.")
    else:
        runtime_score = 20.0
        reasons.append("Non-production / development environment.")

    factors.append(RiskFactor(
        name="Production Runtime State",
        weight=0.10,
        score=runtime_score,
        description="Production deployment and live memory execution state"
    ))

    # Composite weighted score
    composite = sum(f.weight * f.score for f in factors)
    composite = round(min(100.0, max(0.0, composite)), 1)

    if composite >= 80.0:
        level = RiskLevel.CRITICAL
        impact = "Potential remote takeover of production container and unauthorized exfiltration of customer cloud assets."
    elif composite >= 60.0:
        level = RiskLevel.HIGH
        impact = "Component compromise could enable lateral movement or service degradation."
    elif composite >= 40.0:
        level = RiskLevel.MEDIUM
        impact = "Exploitation requires non-trivial local access or authenticated privileges."
    else:
        level = RiskLevel.LOW
        impact = "Minimal real-world exposure; component is shielded by internal security controls."

    return ContextualRiskScore(
        id=f"risk-{finding.id}",
        finding_id=finding.id,
        component_purl=component.purl,
        component_name=component.name,
        vulnerability_id=finding.vulnerability_id,
        risk_level=level,
        composite_score=composite,
        cvss_score=cvss,
        reasons=reasons,
        factors=factors,
        attack_path_id=attack_path.id if attack_path else None,
        potential_impact=impact,
        evidence=evidence
    )
