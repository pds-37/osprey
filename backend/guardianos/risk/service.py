"""Contextual Risk service managing risk evaluations and dashboard metrics."""

from typing import Dict, List, Optional
from guardianos.attackpath.service import attack_path_service
from guardianos.core.audit import record_audit_event
from guardianos.exposure.service import exposure_service
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service
from guardianos.risk.calculator import calculate_contextual_risk
from guardianos.risk.models import ContextualRiskScore, RiskLevel

_risks_db: Dict[str, ContextualRiskScore] = {}


class RiskService:
    """Service evaluating explainable contextual risk across the entire organization."""

    def evaluate_all(self) -> List[ContextualRiskScore]:
        findings = intel_service.list_findings()
        attack_paths = attack_path_service.list_paths()
        results = []

        for f in findings:
            comp = inventory_service.get_component(f.component_purl)
            if not comp:
                continue

            exposure = exposure_service.get_component_exposure(comp.name)
            # Find matching attack path
            path = next((p for p in attack_paths if f.component_purl == p.vulnerable_component or comp.name in p.name), None)

            risk = calculate_contextual_risk(
                finding=f,
                component=comp,
                exposure=exposure,
                attack_path=path
            )
            _risks_db[risk.id] = risk
            results.append(risk)

        if results:
            record_audit_event(
                action="RISK_EVALUATION_COMPLETED",
                target_type="RiskScore",
                target_id=f"total-{len(results)}",
                actor="risk-engine",
                details={
                    "critical": sum(1 for r in results if r.risk_level == RiskLevel.CRITICAL),
                    "high": sum(1 for r in results if r.risk_level == RiskLevel.HIGH),
                }
            )

        return results

    def list_risks(self, level: Optional[str] = None) -> List[ContextualRiskScore]:
        risks = list(_risks_db.values())
        if not risks:
            risks = self.evaluate_all()
        if level:
            risks = [r for r in risks if r.risk_level.value.lower() == level.lower()]
        return sorted(risks, key=lambda r: r.composite_score, reverse=True)

    def get_summary(self) -> dict:
        risks = self.list_risks()
        return {
            "total_findings": len(risks),
            "critical_count": sum(1 for r in risks if r.risk_level == RiskLevel.CRITICAL),
            "high_count": sum(1 for r in risks if r.risk_level == RiskLevel.HIGH),
            "medium_count": sum(1 for r in risks if r.risk_level == RiskLevel.MEDIUM),
            "low_count": sum(1 for r in risks if r.risk_level == RiskLevel.LOW),
            "internet_exposed_count": sum(1 for r in risks if any("Internet-facing" in r_reason for r_reason in r.reasons)),
            "open_attack_paths_count": len([p for p in attack_path_service.list_paths() if p.status.value == "OPEN"])
        }

    def clear(self) -> None:
        _risks_db.clear()


risk_service = RiskService()
