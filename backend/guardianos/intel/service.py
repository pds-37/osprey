"""Vulnerability Intelligence service coordinating matching and graph correlation."""

import uuid
from typing import Dict, List, Optional
from guardianos.core.audit import record_audit_event
from guardianos.graph.builder import get_graph_store
from guardianos.intel.feed_data import vuln_registry
from guardianos.intel.models import VulnerabilityFinding, VulnerabilityRecord
from guardianos.intel.version_matcher import is_version_affected
from guardianos.inventory.models import Component
from guardianos.inventory.service import inventory_service

_findings_db: Dict[str, VulnerabilityFinding] = {}


class IntelService:
    """Service correlating software inventory against vulnerability intelligence feeds."""

    def __init__(self) -> None:
        self.registry = vuln_registry
        self.graph = get_graph_store()

    def match_component(self, comp: Component) -> List[VulnerabilityFinding]:
        """Check if an individual component is affected by any known vulnerability."""
        advisories = list(self.registry.find_by_component(comp.name, comp.ecosystem))
        
        # If not found in local registry, query Google's live OSV.dev database
        if not advisories:
            try:
                from guardianos.intel.osv_client import query_live_osv
                live_advs = query_live_osv(comp.name, comp.version, comp.ecosystem, timeout=2.5)
                advisories.extend(live_advs)
            except Exception:
                pass

        findings = []

        for adv in advisories:
            if adv.source == "OSV.dev":
                affected = True
            else:
                affected = is_version_affected(
                    installed=comp.version,
                    affected_ranges=adv.affected_version_ranges,
                    fixed_versions=adv.fixed_versions
                )
            if affected:
                fixed_ver = adv.fixed_versions[0] if adv.fixed_versions else None
                finding_id = f"find-{comp.name}-{adv.id}-{uuid.uuid4().hex[:6]}"
                finding = VulnerabilityFinding(
                    id=finding_id,
                    vulnerability_id=adv.id,
                    component_purl=comp.purl,
                    component_name=comp.name,
                    installed_version=comp.version,
                    fixed_version=fixed_ver,
                    severity=adv.severity,
                    is_fix_available=bool(fixed_ver),
                    application=comp.application,
                    environment=comp.environment,
                    vulnerability=adv
                )
                findings.append(finding)
                _findings_db[finding.id] = finding

                # Correlate in Knowledge Graph
                vuln_node_id = f"vuln:{adv.id}"
                self.graph.add_node(
                    node_id=vuln_node_id,
                    label="Vulnerability",
                    properties={
                        "id": adv.id,
                        "name": adv.id,
                        "summary": adv.summary,
                        "severity": adv.severity.value,
                        "cvss_score": adv.cvss_score,
                        "fixed_version": fixed_ver,
                        "component_name": comp.name
                    }
                )
                # Edge: Component AFFECTED_BY Vulnerability
                self.graph.add_edge(
                    source_id=comp.purl,
                    target_id=vuln_node_id,
                    relation="AFFECTED_BY",
                    properties={"severity": adv.severity.value, "installed_version": comp.version}
                )

        return findings

    def scan_all_components(self) -> List[VulnerabilityFinding]:
        """Scan all components currently in the software inventory."""
        components = inventory_service.list_components(limit=1000)
        all_findings: List[VulnerabilityFinding] = []
        
        for comp in components:
            findings = self.match_component(comp)
            all_findings.extend(findings)

        if all_findings:
            record_audit_event(
                action="VULNERABILITY_SCAN_COMPLETED",
                target_type="VulnerabilityFindings",
                target_id=f"findings-count-{len(all_findings)}",
                actor="intel-service",
                details={
                    "total_findings": len(all_findings),
                    "critical_count": sum(1 for f in all_findings if f.severity.value == "CRITICAL"),
                    "high_count": sum(1 for f in all_findings if f.severity.value == "HIGH"),
                }
            )

        return all_findings

    def list_findings(self, application: Optional[str] = None, severity: Optional[str] = None) -> List[VulnerabilityFinding]:
        findings = list(_findings_db.values())
        if application:
            findings = [f for f in findings if f.application.lower() == application.lower()]
        if severity:
            findings = [f for f in findings if f.severity.value.lower() == severity.lower()]
        return findings

    def get_finding(self, finding_id: str) -> Optional[VulnerabilityFinding]:
        return _findings_db.get(finding_id)

    def clear(self) -> None:
        _findings_db.clear()


intel_service = IntelService()
