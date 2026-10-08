"""Evidence summary service; generated text cannot create findings or evidence."""

from typing import List

from pydantic import BaseModel, Field

from guardianos.attackpath.service import attack_path_service
from guardianos.exposure.models import AuthRequirement, NetworkExposure
from guardianos.exposure.service import exposure_service
from guardianos.intel.service import intel_service
from guardianos.inventory.service import inventory_service
from guardianos.upstream.service import upstream_service


class AIAnalysisReport(BaseModel):
    query: str
    target_component: str
    executive_summary: str
    lineage_explanation: str
    exposure_verdict: str
    attack_path_summary: str
    upstream_change_summary: str
    remediation_recommendation: str
    evidence_citations: List[str] = Field(default_factory=list)
    evidence_ids: List[str] = Field(default_factory=list)
    analysis_mode: str = "DETERMINISTIC_EVIDENCE_SUMMARY"


class AISecurityAnalyst:
    """Summarize existing deterministic records without inventing evidence."""

    def analyze_component(self, component_name: str, user_question: str = "") -> AIAnalysisReport:
        name = component_name.strip()
        component = next(
            (item for item in inventory_service.list_components(search=name, limit=1000)
             if item.name.lower() == name.lower() or item.purl.lower() == name.lower()),
            None,
        )
        if component is None:
            return AIAnalysisReport(
                query=user_question,
                target_component=name,
                executive_summary="No matching component observation exists in the current inventory.",
                lineage_explanation="NOT OBSERVED: component lineage is unavailable without an inventory observation.",
                exposure_verdict="UNKNOWN: no component or endpoint observation is available.",
                attack_path_summary="NOT OBSERVED: no verified attack path is available.",
                upstream_change_summary="NOT OBSERVED: no upstream change record is available.",
                remediation_recommendation="Upload an inventory artifact and run vulnerability analysis before making a remediation decision.",
            )

        findings = [f for f in intel_service.list_findings() if f.component_purl == component.purl]
        exposure = exposure_service.get_component_exposure(component.purl)
        paths = [
            path for path in attack_path_service.list_paths()
            if path.vulnerable_component == component.purl
        ]
        upstream = upstream_service.list_commits(component=component.name)
        lineage_data = inventory_service.get_component_lineage(component.purl)
        ancestors = lineage_data.get("ancestors", []) if isinstance(lineage_data, dict) else []

        evidence_ids = list(dict.fromkeys(
            component.evidence_ids + [eid for finding in findings for eid in finding.evidence_ids]
        ))
        citations = [f"Evidence ID: {evidence_id}" for evidence_id in evidence_ids]
        if not evidence_ids:
            citations.append("No traceable evidence IDs are attached to this observation.")

        if ancestors:
            ancestor_names = [
                ancestor.get("name", str(ancestor)) if isinstance(ancestor, dict) else str(ancestor)
                for ancestor in ancestors
            ]
            lineage = "Observed dependency lineage: " + " -> ".join([*ancestor_names, component.name]) + "."
        else:
            lineage = "NOT OBSERVED: no parent dependency relationship is recorded for this component."

        if exposure:
            network = exposure.network_exposure.value
            auth = exposure.auth_requirement.value
            if network == NetworkExposure.UNKNOWN.value:
                exposure_text = "UNKNOWN: no endpoint is connected to this component."
            else:
                exposure_text = f"Endpoint metadata reports network exposure {network} and authentication {auth}."
                if any(ep.evidence_source == "DEMO_FIXTURE" for ep in exposure.endpoints):
                    exposure_text = "DEMO FIXTURE ONLY: " + exposure_text
        else:
            exposure_text = "UNKNOWN: no endpoint exposure observation is available."

        if paths:
            fixture_paths = [path for path in paths if getattr(path, "fixture", False)]
            if fixture_paths:
                path_text = "DEMO FIXTURE ONLY: seeded attack-path records are simulated and are not application evidence."
            else:
                path_text = f"{len(paths)} attack-path record(s) are present; review their evidence before treating them as reachable."
        else:
            path_text = "NOT OBSERVED: no verified end-to-end path is available; absence is not proof of isolation."

        if upstream:
            upstream_text = f"{len(upstream)} upstream change record(s) are stored; they are not automatically classified as security fixes."
        else:
            upstream_text = "NOT OBSERVED: no upstream change record is available."

        if findings:
            vuln_ids = list(dict.fromkeys(finding.vulnerability_id for finding in findings))
            fixed = list(dict.fromkeys(f.fixed_version for f in findings if f.fixed_version))
            summary = (
                f"The current scan records {len(findings)} affected finding(s) for {component.name} "
                f"{component.version}: {', '.join(vuln_ids)}. This establishes package-level affected status; "
                "function reachability remains a separate analysis."
            )
            remediation = (
                f"Review an upgrade to {', '.join(fixed)} and submit a fresh inventory observation to verify the result. "
                "No repository file or pull request was generated."
                if fixed else
                "Review the advisory and identify a supported fixed release. No repository file or pull request was generated."
            )
        else:
            summary = (
                f"No vulnerability finding is recorded for {component.name} {component.version} in the current scan state. "
                "This does not establish that the package has no vulnerabilities; scan freshness and source coverage are not inferred."
            )
            remediation = "No package-specific upgrade recommendation is available from the current findings."

        return AIAnalysisReport(
            query=user_question,
            target_component=component.name,
            executive_summary=summary,
            lineage_explanation=lineage,
            exposure_verdict=exposure_text,
            attack_path_summary=path_text,
            upstream_change_summary=upstream_text,
            remediation_recommendation=remediation,
            evidence_citations=citations,
            evidence_ids=evidence_ids,
        )


ai_analyst = AISecurityAnalyst()
