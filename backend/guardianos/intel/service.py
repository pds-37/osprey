"""Vulnerability Intelligence service coordinating matching and graph correlation."""

import json
import hashlib
from dataclasses import asdict
from typing import Dict, List, Optional
from osprey import __version__
from osprey.core.evidence import canonical_json
from osprey.core.provenance import (
    record_analysis_limitations,
    record_analysis_run,
    record_reachability,
)
from osprey.runtime import summarize_runtime_state
from guardianos.storage.evidence import evidence_store
from osprey.core.models import EvidenceType, ReachabilityResult, VersionMatchStatus
from osprey.core.versioning import evaluate_version
from guardianos.core.audit import record_audit_event
from guardianos.graph.builder import get_graph_store
from guardianos.intel.feed_data import vuln_registry
from guardianos.intel.models import VulnerabilityFinding, VulnerabilityRecord
from guardianos.intel.version_matcher import is_version_affected
from guardianos.inventory.models import Component
from guardianos.inventory.service import inventory_service
from guardianos.storage.sqlite import state_store
from osprey.analyzers.reachability import analyze_reachability
from osprey.analyzers.source import SourceAnalysis

_findings_db: Dict[str, VulnerabilityFinding] = {
    key: VulnerabilityFinding.model_validate(value)
    for key, value in state_store.list("findings").items()
}


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
            if adv.query_matched_version == comp.version:
                match_status = VersionMatchStatus.AFFECTED
            else:
                version_match = evaluate_version(
                    installed=comp.version,
                    ecosystem=comp.ecosystem.value,
                    ranges=adv.affected_ranges,
                    exact_versions=adv.affected_versions,
                    fixed_versions=adv.fixed_versions,
                    introduced_versions=adv.introduced_versions,
                )
                match_status = version_match.status
            if match_status == VersionMatchStatus.AFFECTED:
                fixed_ver = adv.fixed_versions[0] if adv.fixed_versions else None
                stable_key = f"{comp.observation_id}:{adv.id}"
                finding_id = "find-" + hashlib.sha256(stable_key.encode()).hexdigest()[:24]
                component_evidence = list(comp.evidence_ids)
                if not component_evidence:
                    user_record = evidence_store.add(
                        evidence_type=EvidenceType.USER_INPUT,
                        source="component inventory input",
                        location=comp.location or comp.purl,
                        content=f"{comp.purl}@{comp.version}",
                        confidence=0.5,
                        metadata={"component_purl": comp.purl, "observation_id": comp.observation_id},
                    )
                    component_evidence.append(user_record.id)
                advisory_confidence = {
                    "OSV": 0.95,
                    "DEMO_FIXTURE": 0.25,
                    "NVD": 0.9,
                    "GHSA": 0.9,
                    "Debian": 0.9,
                    "Vendor": 0.9,
                    "UNKNOWN": 0.0,
                }.get(adv.source.value, 0.0)
                advisory_payload = adv.model_dump(mode="json")
                advisory_content = canonical_json(advisory_payload)
                advisory_record = evidence_store.add(
                    evidence_type=EvidenceType.VULNERABILITY_ADVISORY,
                    source=adv.source.value,
                    location=adv.id,
                    content=None if adv.source_content_hash else advisory_content,
                    content_hash=adv.source_content_hash,
                    confidence=advisory_confidence,
                    metadata={
                        "advisory_id": adv.id,
                        "advisory_source": adv.source.value,
                        "package": comp.name,
                        "ecosystem": comp.ecosystem.value,
                        "observed_version": comp.version,
                        "query_matched_version": adv.query_matched_version,
                        "affected_ranges": adv.affected_ranges,
                        "affected_versions": adv.affected_versions,
                        "fixed_versions": adv.fixed_versions,
                        "introduced_versions": adv.introduced_versions,
                        "severity_evidence": adv.severity.value if adv.severity.value != "UNKNOWN" else None,
                        "cvss_score": adv.cvss_score,
                        "source_content_hash": adv.source_content_hash,
                    },
                )
                matching_method = (
                    "OSV exact package-version query"
                    if adv.query_matched_version == comp.version
                    else "Osprey ecosystem-aware version-range matcher"
                )
                version_payload = {
                    "package": comp.name,
                    "ecosystem": comp.ecosystem.value,
                    "observed_version": comp.version,
                    "status": match_status.value,
                    "matching_method": matching_method,
                    "affected_ranges": adv.affected_ranges,
                    "affected_versions": adv.affected_versions,
                    "introduced_versions": adv.introduced_versions,
                    "fixed_versions": adv.fixed_versions,
                    "advisory_id": adv.id,
                }
                version_record = evidence_store.add(
                    evidence_type=EvidenceType.VERSION,
                    source="Osprey version matcher",
                    location=adv.id,
                    content=canonical_json(version_payload),
                    confidence=advisory_confidence,
                    metadata={
                        "analyzer": "Osprey",
                        "analyzer_version": __version__,
                        "analysis_type": "affected_version_match",
                        **version_payload,
                    },
                )
                symbol_record = None
                if adv.vulnerable_symbols or adv.vulnerable_symbol_mappings:
                    symbol_payload = {
                        "package": comp.name,
                        "ecosystem": comp.ecosystem.value,
                        "advisory_id": adv.id,
                        "vulnerable_symbols": adv.vulnerable_symbols,
                        "symbol_mappings": adv.vulnerable_symbol_mappings,
                    }
                    symbol_record = evidence_store.add(
                        evidence_type=EvidenceType.VULNERABLE_SYMBOL,
                        source=adv.source.value,
                        location=adv.id,
                        content=canonical_json(symbol_payload),
                        confidence=advisory_confidence,
                        metadata={
                            "analyzer": "Osprey",
                            "analyzer_version": __version__,
                            **symbol_payload,
                        },
                    )
                runtime_snapshot = summarize_runtime_state(
                    evidence_store,
                    package_name=comp.name,
                    ecosystem=comp.ecosystem.value.lower(),
                    version=comp.version,
                    declared_observed=comp.declared_version is not None or comp.state.value == "DECLARED",
                    locked_observed=comp.locked_version is not None or comp.state.value == "LOCKED",
                    installed_observed=comp.installed_version is not None or comp.state.value == "INSTALLED",
                    finding_id=finding_id,
                )
                finding = VulnerabilityFinding(
                    id=finding_id,
                    vulnerability_id=adv.id,
                    component_purl=comp.purl,
                    component_name=comp.name,
                    observed_version=comp.version,
                    installed_version=comp.installed_version,
                    declared_version=comp.declared_version,
                    locked_version=comp.locked_version,
                    fixed_version=fixed_ver,
                    severity=adv.severity,
                    is_fix_available=bool(fixed_ver),
                    package_status=match_status.value,
                    reachability_status="UNKNOWN",
                    runtime_state=runtime_snapshot.states,
                    runtime_evidence_ids=list(runtime_snapshot.evidence_ids),
                    runtime_limitations=list(runtime_snapshot.limitations),
                    evidence_ids=list(dict.fromkeys([
                        *component_evidence,
                        advisory_record.id,
                        version_record.id,
                        *runtime_snapshot.evidence_ids,
                        *([symbol_record.id] if symbol_record else []),
                    ])),
                    provenance_ids={
                        "vulnerability_advisory": advisory_record.id,
                        "version": version_record.id,
                        **({"runtime": runtime_snapshot.evidence_ids[0]} if runtime_snapshot.evidence_ids else {}),
                        **({"vulnerable_symbols": symbol_record.id} if symbol_record else {}),
                    },
                    application=comp.application,
                    environment=comp.environment,
                    organization_id=comp.organization_id,
                    vulnerability=adv
                )
                findings.append(finding)
                _findings_db[finding.id] = finding
                state_store.put("findings", finding.id, finding)

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
                        "observed_version": comp.version,
                        "installed_version": comp.installed_version,
                        "component_name": comp.name
                    }
                )
                # Edge: Component AFFECTED_BY Vulnerability
                self.graph.add_edge(
                    source_id=comp.purl,
                    target_id=vuln_node_id,
                    relation="AFFECTED_BY",
                    properties={
                        "severity": adv.severity.value,
                        "observed_version": comp.version,
                        "installed_version": comp.installed_version,
                    }
                )

        return findings

    def scan_all_components(self) -> List[VulnerabilityFinding]:
        """Scan all components currently in the software inventory."""
        import concurrent.futures
        components = inventory_service.list_components(limit=1000)
        all_findings: List[VulnerabilityFinding] = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            for findings in executor.map(self.match_component, components):
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
        return [self._refresh_runtime_state(finding) for finding in findings]

    def get_finding(self, finding_id: str) -> Optional[VulnerabilityFinding]:
        finding = _findings_db.get(finding_id)
        return self._refresh_runtime_state(finding) if finding is not None else None

    def _refresh_runtime_state(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        snapshot = summarize_runtime_state(
            evidence_store,
            package_name=finding.component_name,
            ecosystem=(finding.vulnerability.ecosystem.value if finding.vulnerability else ""),
            version=finding.observed_version or finding.installed_version or "",
            declared_observed=finding.declared_version is not None,
            locked_observed=finding.locked_version is not None,
            installed_observed=finding.installed_version is not None,
            finding_id=finding.id,
        )
        finding.runtime_state = snapshot.states
        finding.runtime_evidence_ids = list(snapshot.evidence_ids)
        finding.runtime_limitations = list(snapshot.limitations)
        finding.evidence_ids = list(dict.fromkeys([*finding.evidence_ids, *snapshot.evidence_ids]))
        if snapshot.evidence_ids:
            finding.provenance_ids = {
                **finding.provenance_ids,
                "runtime": snapshot.evidence_ids[0],
            }
        self.save_finding(finding)
        return finding

    def analyze_finding_reachability(
        self,
        finding: VulnerabilityFinding,
        source_analysis: SourceAnalysis,
        *,
        analysis_type: str = "workspace_reachability",
    ) -> ReachabilityResult:
        """Attach the shared static reachability result to a persisted finding."""
        vulnerability = finding.vulnerability
        symbol_mappings = vulnerability.vulnerable_symbol_mappings if vulnerability else []
        vulnerable_symbols = (
            symbol_mappings
            or (vulnerability.vulnerable_symbols if vulnerability else [])
        )
        # match_component records the advisory evidence after component evidence;
        # this final ID is the source record for package-scoped OSV mappings.
        symbol_evidence_ids = finding.evidence_ids[-1:] if symbol_mappings else []
        analysis_run = record_analysis_run(
            evidence_store,
            source_analysis,
            analysis_type=analysis_type,
        )
        analysis_limitations = record_analysis_limitations(
            evidence_store,
            source_analysis.errors,
            analysis_run_id=analysis_run.id,
        )
        result = analyze_reachability(
            source_analysis,
            package=finding.component_name,
            vulnerable_symbols=vulnerable_symbols,
            direct_dependency=False,
            ecosystem=vulnerability.ecosystem.value if vulnerability else None,
            symbol_evidence_ids=symbol_evidence_ids,
        )
        reachability_record, limitation_record = record_reachability(
            evidence_store,
            result,
            finding_id=finding.id,
            analysis_run_id=analysis_run.id,
        )
        finding.reachability_status = result.status.value
        finding.reachability_confidence = result.confidence
        finding.reachability_path = list(result.path)
        finding.reachability_path_edges = [asdict(edge) for edge in result.path_edges]
        finding.reachability_explanation = result.explanation
        finding.reachability_limitations = list(result.limitations)
        provenance_ids = {
            **finding.provenance_ids,
            "analysis_run": analysis_run.id,
            "reachability": reachability_record.id,
        }
        if limitation_record:
            provenance_ids["reachability_limitations"] = limitation_record.id
        if analysis_limitations:
            provenance_ids["analysis_limitations"] = analysis_limitations.id
        finding.provenance_ids = provenance_ids
        finding.analysis_provenance_id = analysis_run.id
        finding.evidence_ids = list(dict.fromkeys([
            *finding.evidence_ids,
            *result.evidence,
            analysis_run.id,
            reachability_record.id,
            *([limitation_record.id] if limitation_record else []),
            *([analysis_limitations.id] if analysis_limitations else []),
        ]))
        self.save_finding(finding)
        return result

    def save_finding(self, finding: VulnerabilityFinding) -> None:
        _findings_db[finding.id] = finding
        state_store.put("findings", finding.id, finding)

    def clear(self) -> None:
        _findings_db.clear()
        state_store.clear("findings")


intel_service = IntelService()
