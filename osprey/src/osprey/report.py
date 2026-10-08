"""Terminal and JSON report rendering using Rich.

DEFAULT OUTPUT SPEC:
  Osprey scan: ./my-app
  187 findings -> 3 need action
  ACT NOW (1)
   1. libheif 1.17.0  GHSA-xxxx  unknown (Dockerfile port declared; ingress unobserved)  fix: >= 1.19.8
  PLAN (2) ...
  Run `osprey explain <id>` for the evidence chain. Use --detail for everything.

Assumptions and Limitations:
- Keeps default summary strictly concise (10-15 lines) to eliminate alert fatigue.
- Full details including MONITOR and IGNORE findings are exposed with --detail.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Dict, List

from rich.console import Console

from osprey.scanner import ScanResult
from osprey import __version__
from osprey.core.evidence import verify_record
from osprey.core.models import EvidenceType

console = Console()


def _risk_display(finding) -> str:
    score = "UNKNOWN" if finding.risk_score is None else f"{finding.risk_score:.1f}"
    return f"{finding.risk_level} risk / {score}"


def render_terminal_report(result: ScanResult, detail: bool = False) -> None:
    """Print the formatted Rich terminal summary adhering to Osprey output rules."""
    total_findings = len(result.findings)
    act_now = [f for f in result.findings if f.risk_tier == "ACT NOW"]
    plan = [f for f in result.findings if f.risk_tier == "PLAN"]
    monitor = [f for f in result.findings if f.risk_tier == "MONITOR"]
    ignore = [f for f in result.findings if f.risk_tier == "IGNORE"]
    unknown_risk = [f for f in result.findings if f.risk_tier == "UNKNOWN"]

    action_count = len(act_now) + len(plan)

    # Header line
    console.print(f"[bold white]Osprey scan:[/] [cyan]{result.root_path}[/]")
    console.print(f"[bold]{total_findings} findings[/] -> [bold yellow]{action_count} need action[/]\n")
    reachable_count = sum(1 for f in result.findings if f.reachability.status.value == "REACHABLE")
    not_reachable_count = sum(1 for f in result.findings if f.reachability.status.value == "NOT_REACHABLE")
    unknown_count = sum(1 for f in result.findings if f.reachability.status.value == "UNKNOWN")
    console.print(
        f"Reachability: [green]{reachable_count} reachable[/], "
        f"[yellow]{not_reachable_count} not reachable[/], [dim]{unknown_count} unknown[/]\n"
    )

    # ACT NOW Section
    if act_now:
        console.print(f"[bold red]ACT NOW ({len(act_now)})[/]")
        for idx, f in enumerate(act_now, 1):
            fix_str = f"fix: {f.fix_status.minimal_safe_version}" if f.fix_status.minimal_safe_version else "no fix"
            console.print(
                f" [red]{idx}.[/] [bold white]{f.component.name} {f.component.version}[/]  "
                f"[yellow]{f.vulnerability_id}[/]  "
                f"[white]{_risk_display(f)}[/]  "
                f"[magenta]{f.exposure.to_display()}[/]  "
                f"[cyan]package {f.package_status.value} / function {f.reachability.status.value}[/]  "
                f"[green]{fix_str}[/]"
            )
        console.print()
    else:
        console.print("[dim]ACT NOW (0)[/]\n")

    # PLAN Section
    if plan:
        console.print(f"[bold yellow]PLAN ({len(plan)})[/]")
        # In default mode, show up to 3 to keep summary 10-15 lines
        items_to_show = plan if detail else plan[:3]
        for idx, f in enumerate(items_to_show, 1):
            fix_str = f"fix: {f.fix_status.minimal_safe_version}" if f.fix_status.minimal_safe_version else "no fix"
            console.print(
                f" [yellow]{idx}.[/] [bold white]{f.component.name} {f.component.version}[/]  "
                f"[yellow]{f.vulnerability_id}[/]  "
                f"[white]{_risk_display(f)}[/]  "
                f"[dim]{f.exposure.to_display()}[/]  "
                f"[cyan]package {f.package_status.value} / function {f.reachability.status.value}[/]  "
                f"[green]{fix_str}[/]"
            )
        if not detail and len(plan) > 3:
            console.print(f" [dim]... and {len(plan) - 3} more (use --detail to view all)[/]")
        console.print()
    else:
        console.print("[dim]PLAN (0)[/]\n")

    if unknown_risk:
        console.print(f"[bold magenta]UNKNOWN ({len(unknown_risk)})[/]")
        items_to_show = unknown_risk if detail else unknown_risk[:3]
        for idx, f in enumerate(items_to_show, 1):
            console.print(
                f" [magenta]{idx}.[/] {f.component.name} {f.component.version}  "
                f"{f.vulnerability_id}  decision could not be established safely"
                f" ({_risk_display(f)})"
            )
        if not detail and len(unknown_risk) > 3:
            console.print(f" [dim]... and {len(unknown_risk) - 3} more (use --detail to view all)[/]")
        console.print()

    # Detail mode shows MONITOR and IGNORE
    if detail:
        if monitor:
            console.print(f"[bold blue]MONITOR ({len(monitor)})[/]")
            for idx, f in enumerate(monitor, 1):
                fix_str = f.fix_status.minimal_safe_version or "no fix"
                console.print(
                    f" [blue]{idx}.[/] {f.component.name} {f.component.version}  "
                    f"{f.vulnerability_id}  [dim]{f.exposure.to_display()}[/]  "
                    f"{_risk_display(f)}  "
                    f"package {f.package_status.value} / function {f.reachability.status.value}  fix: {fix_str}"
                )
            console.print()

        if ignore:
            console.print(f"[bold dim]IGNORE ({len(ignore)})[/]")
            for idx, f in enumerate(ignore, 1):
                console.print(
                    f" [dim]{idx}. {f.component.name} {f.component.version}  "
                    f"{f.vulnerability_id}  {f.exposure.to_display()}  "
                    f"{_risk_display(f)}  "
                    f"package {f.package_status.value} / function {f.reachability.status.value}[/]"
                )
            console.print()

    # Footer instructions
    sample_id = (
        act_now[0].vulnerability_id if act_now else
        plan[0].vulnerability_id if plan else
        unknown_risk[0].vulnerability_id if unknown_risk else "finding-id"
    )
    console.print(f"[dim]Run `osprey explain {sample_id}` for the evidence chain. Use --detail for everything.[/]")


def render_json_report(result: ScanResult) -> str:
    """Serialize the scan result to machine-readable JSON."""
    findings_data: List[Dict[str, Any]] = []
    reachable_count = sum(1 for f in result.findings if f.reachability.status.value == "REACHABLE")
    not_reachable_count = sum(1 for f in result.findings if f.reachability.status.value == "NOT_REACHABLE")
    unknown_count = sum(1 for f in result.findings if f.reachability.status.value == "UNKNOWN")
    for f in result.findings:
        findings_data.append({
            "id": f.id,
            "vulnerability_id": f.vulnerability_id,
            "component": {
                "name": f.component.name,
                "version": f.component.version,
                "declared_version": f.component.declared_version,
                "locked_version": f.component.locked_version,
                "installed_version": f.component.installed_version,
                "ecosystem": f.component.ecosystem,
                "purl": f.component.purl,
                "observation_id": f.component.observation_id,
                "evidence_ids": f.component.evidence_ids,
                "is_dev": f.component.is_dev,
                "source_file": f.component.source_file,
            },
            "risk_tier": f.risk_tier,
            "decision": f.risk_tier,
            "risk_score": f.risk_score,
            "risk_level": f.risk_level,
            "risk_factors": f.risk_factors,
            "risk_limitations": f.risk_limitations,
            "firing_rule": f.firing_rule,
            "package_status": f.package_status.value,
            "reachability": {
                "status": f.reachability.status.value,
                "confidence": f.reachability.confidence,
                "path": list(f.reachability.path),
                "reason": f.reachability.reason,
                "explanation": f.reachability.explanation,
                "limitations": list(f.reachability.limitations),
                "path_edges": [asdict(edge) for edge in f.reachability.path_edges],
                "evidence_ids": list(f.reachability.evidence),
            },
            "evidence_ids": f.evidence_ids,
            "provenance_ids": f.provenance_ids,
            "risk_inputs": f.risk_inputs,
            "runtime_state": f.runtime_state,
            "runtime_evidence_ids": f.runtime_evidence_ids,
            "runtime_limitations": f.runtime_limitations,
            "cvss_score": f.cvss_score,
            "severity": f.severity,
            "epss_score": f.epss_score,
            "in_cisa_kev": f.in_cisa_kev,
            "kev_available": f.kev_available,
            "exposure": {
                "level": f.exposure.level,
                "confidence": f.exposure.confidence,
                "evidence": f.exposure.evidence,
            },
            "fix_status": {
                "status": f.fix_status.status,
                "minimal_safe_version": f.fix_status.minimal_safe_version,
                "stages": f.fix_status.stages,
            },
            "summary": f.summary,
            "aliases": f.aliases,
        })

    analysis_record = next(
        (record for record in result.evidence if record.id == result.analysis_provenance_id),
        None,
    )
    data = {
        "osprey_version": __version__,
        "root_path": str(result.root_path),
        "app_name": result.app_name,
        "analysis": {
            "analyzer": "Osprey",
            "analyzer_version": __version__,
            "analysis_type": "workspace_scan",
            "source_file_count": len(result.source_analysis.files_scanned) if result.source_analysis else 0,
            "language_counts": analysis_record.metadata.get("language_counts", {}) if analysis_record else {},
            "max_graph_depth": analysis_record.metadata.get("max_graph_depth") if analysis_record else None,
            "limitation_count": len(result.source_analysis.errors) if result.source_analysis else 0,
            "provenance_evidence_id": result.analysis_provenance_id,
            "limitations_evidence_id": result.analysis_limitations_evidence_id,
        },
        "runtime": {
            "collection": "OPT_IN_INSTRUMENTATION_ONLY",
            "observation_count": sum(1 for record in result.evidence if record.type == EvidenceType.RUNTIME_OBSERVATION),
            "status": (
                "OBSERVED" if any(record.type == EvidenceType.RUNTIME_OBSERVATION for record in result.evidence)
                else "RUNTIME OBSERVATION UNAVAILABLE"
            ),
            "limitations": [
                "Workspace scans do not start or attach to application processes.",
                "LOADED and EXERCISED remain UNKNOWN without explicit in-process instrumentation.",
            ],
        },
        "duration_seconds": round(result.duration_seconds, 3),
        "manifests": result.manifests,
        "counts": {
            "components": len(result.components),
            "total_findings": len(result.findings),
            "act_now": sum(1 for f in result.findings if f.risk_tier == "ACT NOW"),
            "plan": sum(1 for f in result.findings if f.risk_tier == "PLAN"),
            "monitor": sum(1 for f in result.findings if f.risk_tier == "MONITOR"),
            "ignore": sum(1 for f in result.findings if f.risk_tier == "IGNORE"),
            "unknown_risk": sum(1 for f in result.findings if f.risk_tier == "UNKNOWN"),
            "reachable": reachable_count,
            "not_reachable": not_reachable_count,
            "unknown_reachability": unknown_count,
        },
        "findings": findings_data,
        "evidence": [
            {
                "id": evidence.id,
                "type": evidence.type.value,
                "source": evidence.source,
                "location": evidence.location,
                "timestamp": evidence.timestamp,
                "confidence": evidence.confidence,
                "content_hash": evidence.content_hash,
                "record_hash": evidence.record_hash,
                "integrity_status": (
                    "UNVERIFIED_LEGACY" if verify_record(evidence) is None
                    else "VERIFIED" if verify_record(evidence) else "MISMATCH"
                ),
                "metadata": evidence.metadata,
            }
            for evidence in result.evidence
            if (
                any(evidence.id in finding.evidence_ids for finding in result.findings)
                or evidence.type in {EvidenceType.ANALYSIS_RUN, EvidenceType.ANALYSIS_LIMITATION}
            )
        ],
    }
    return json.dumps(data, indent=2)
