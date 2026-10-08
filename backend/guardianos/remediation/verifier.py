"""Remediation Verification Engine confirming attack path closure."""

from datetime import datetime, timezone
from typing import Any, Dict
from guardianos.attackpath.service import attack_path_service
from guardianos.core.audit import record_audit_event
from guardianos.intel.service import intel_service
from guardianos.inventory.models import Component, DependencyState, Ecosystem
from guardianos.inventory.normalizer import build_canonical_purl
from guardianos.inventory.service import inventory_service, _components_db
from guardianos.remediation.models import RemediationStatus, RemediationTask


def verify_remediation_closure(task: RemediationTask, *, include_demo_fixtures: bool = False) -> Dict[str, Any]:
    """
    Compare the proposal with current inventory evidence. This does not deploy a
    change or prove runtime/production closure. Only the explicit demo fixture
    branch below simulates a deployment lifecycle.
    """
    if not include_demo_fixtures:
        observed = [
            component for component in inventory_service.list_components(search=task.component_name, limit=1000)
            if component.name.lower() == task.component_name.lower()
            and component.version == task.target_version
        ]
        if not observed:
            task.status = RemediationStatus.UNVERIFIED
            evidence = {
                "remediation_status": "NOT_OBSERVED",
                "attack_path_status": "NOT_OBSERVED",
                "vulnerability_status": "UNKNOWN",
                "message": "No inventory observation contains the proposed target version. Upload a fresh SBOM before verification.",
            }
        else:
            target_purls = {component.purl for component in observed}
            current_findings = intel_service.scan_all_components()
            still_affected = any(
                finding.vulnerability_id == task.vulnerability_id and finding.component_purl in target_purls
                for finding in current_findings
            )
            # A matching inventory record does not prove that the application was
            # rebuilt or deployed. Keep the workflow unverified and report the
            # narrower observed-component result in evidence.
            task.status = RemediationStatus.UNVERIFIED
            evidence = {
                "remediation_status": "STILL_AFFECTED" if still_affected else "RESOLVED_FOR_OBSERVED_COMPONENT",
                "verification_scope": "inventory observation only",
                "attack_path_status": "NOT_OBSERVED",
                "vulnerability_status": "AFFECTED" if still_affected else "NOT_REPORTED_FOR_OBSERVED_VERSION",
                "observed_component_purls": sorted(target_purls),
                "message": (
                    "The new inventory observation is still reported as affected."
                    if still_affected
                    else "The advisory was not returned for the newly observed component version; rebuild, deployment, and attack-path closure remain unobserved."
                ),
            }
        task.verification_evidence = evidence
        record_audit_event(
            action="REMEDIATION_VERIFICATION_ATTEMPTED",
            target_type="RemediationTask",
            target_id=task.id,
            actor="verification-engine",
            details=evidence,
        )
        return evidence

    # The fixture-only branch below deliberately simulates a deployment lifecycle.
    # It is called only by the explicitly enabled demo scenario.
    # 1. Locate existing component in inventory
    all_comps = inventory_service.list_components(limit=1000)
    old_comp = next((c for c in all_comps if c.name.lower() == task.component_name.lower()), None)

    eco = old_comp.ecosystem if (old_comp and old_comp.ecosystem) else Ecosystem.GENERIC
    app_name = old_comp.application if old_comp else "default-app"

    namespace = None
    if old_comp and "/" in old_comp.purl:
        parts = old_comp.purl.split("/")
        if len(parts) > 2 and not parts[1].startswith("pkg:"):
            namespace = parts[1]

    new_purl = build_canonical_purl(
        ecosystem=eco,
        name=task.component_name,
        version=task.target_version,
        namespace=namespace
    )

    # Remove old version from inventory
    if old_comp and old_comp.purl in _components_db:
        try:
            del _components_db[old_comp.purl]
        except KeyError:
            pass

    remediated_comp = Component(
        id=new_purl,
        name=task.component_name,
        ecosystem=eco,
        version=task.target_version,
        purl=new_purl,
        # A simulated inventory recheck cannot establish installation/runtime state.
        state=DependencyState.UNKNOWN,
        application=app_name,
        environment="production"
    )
    _components_db[new_purl] = remediated_comp

    # 2. Rescan vulnerability state
    new_findings = intel_service.scan_all_components()
    is_still_vulnerable = any(
        f.component_name.lower() == task.component_name.lower() and f.vulnerability_id == task.vulnerability_id
        for f in new_findings
    )

    # 3. Recalculate and close attack path
    if task.associated_attack_path_id:
        attack_path_service.close_path(
            task.associated_attack_path_id,
            reason=f"Remediated via upgrade to {task.target_version}"
        )

    # Also close any open attack path referencing this component
    for p in attack_path_service.list_paths():
        if (task.component_name.lower() in p.name.lower() or
            (old_comp and old_comp.purl in p.vulnerable_component)):
            attack_path_service.close_path(p.id, reason=f"Remediated via upgrade to {task.target_version}")

    task.status = RemediationStatus.VERIFIED_CLOSED
    task.verified_at = datetime.now(timezone.utc)
    
    evidence = {
        "remediation_status": "SIMULATED_FIXTURE_ONLY",
        "attack_path_status": "SIMULATED_CLOSED",
        "vulnerability_status": "SIMULATED_RESOLVED",
        "remediated_component": task.component_name,
        "old_version": task.current_version,
        "new_version": task.target_version,
        "is_still_vulnerable": is_still_vulnerable,
        "message": "SIMULATED FIXTURE ONLY: target version and path closure are seeded; no deployment or runtime state was verified."
    }
    task.verification_evidence = evidence

    record_audit_event(
        action="REMEDIATION_VERIFIED",
        target_type="RemediationTask",
        target_id=task.id,
        actor="verification-engine",
        details=evidence
    )

    return evidence
