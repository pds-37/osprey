"""Evidence chain explanation engine for individual findings.

Assumptions and Limitations:
- Displays full deterministic audit trail explaining why a finding was prioritized into its risk tier.
- Shows structural graph lineage from the root application down to the vulnerable dependency.
"""

from __future__ import annotations

from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from osprey.graph import SupplyChainGraph
from osprey.models import Finding

console = Console()


def explain_finding(
    finding_id: str,
    findings: List[Finding],
    graph: Optional[SupplyChainGraph] = None,
    out_console: Optional[Console] = None,
) -> bool:
    """Print the complete evidence chain and audit trail for a finding ID."""
    c = out_console or console
    target: Optional[Finding] = None
    query = finding_id.strip().lower()

    for f in findings:
        if (
            f.id.lower() == query
            or f.vulnerability_id.lower() == query
            or query in [a.lower() for a in f.aliases]
            or f.component.name.lower() == query
        ):
            target = f
            break

    if not target:
        c.print(f"[bold red]Finding '{finding_id}' not found in scan results.[/]")
        return False

    c.print(Panel(
        f"[bold white]{target.vulnerability_id}[/] in [cyan]{target.component.name}@{target.component.version}[/]",
        title="[bold yellow]Osprey Finding Evidence Chain[/]",
        border_style="cyan",
    ))


    # 1. Vulnerability Metadata Table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Property", style="bold white")
    table.add_column("Value")

    table.add_row("Vulnerability ID:", f"[yellow]{target.vulnerability_id}[/]")
    if target.aliases:
        table.add_row("Aliases:", ", ".join(target.aliases))
    table.add_row("Package (purl):", f"[cyan]{target.component.purl}[/]")
    table.add_row("Package vulnerability:", target.package_status.value)
    table.add_row("Function reachability:", f"{target.reachability.status.value} ({target.reachability.confidence:.0%})")
    table.add_row("Manifest File:", target.component.source_file or "unknown")
    table.add_row("CVSS:", str(target.cvss_score) if target.cvss_score is not None else "Unavailable")
    table.add_row("Advisory severity:", target.severity or "UNKNOWN")
    table.add_row("EPSS:", f"{target.epss_score:.1%}" if target.epss_score is not None else "Unavailable")
    kev_status = (
        "[red]YES (listed)[/]" if target.in_cisa_kev else
        "NO (catalog checked)" if target.kev_available else
        "Unavailable"
    )
    table.add_row("CISA KEV:", kev_status)
    c.print(table)
    c.print()

    # 2. Package-Level Exposure
    c.print("[bold underline]1. Exposure Inference (Package-Level):[/]")
    c.print(f" • [bold]Level:[/] {target.exposure.level}")
    c.print(f" • [bold]Confidence:[/] {target.exposure.confidence}")
    c.print(f" • [bold]Evidence:[/] [dim]{target.exposure.evidence}[/]")
    c.print()

    c.print("[bold underline]2. Vulnerable Function Reachability:[/]")
    c.print(f" • [bold]Status:[/] {target.reachability.status.value}")
    c.print(f" • [bold]Reason:[/] {target.reachability.reason}")
    if target.reachability.path:
        c.print(f" • [bold]Observed path:[/] {' -> '.join(target.reachability.path)}")
    if target.reachability.path_edges:
        c.print(" • [bold]Observed path edges:[/]")
        for edge in target.reachability.path_edges:
            source_location = f"{edge.source_file}:{edge.line}" if edge.line else edge.source_file
            target_location = f"{edge.target_file}:" if edge.target_file else ""
            c.print(
                f"   - {source_location} {edge.source_symbol} -> "
                f"{target_location}{edge.target_symbol} ({edge.relation}; "
                f"{edge.resolution}; confidence {edge.confidence:.0%})"
            )
    if target.reachability.limitations:
        c.print(" • [bold]Limitations:[/]")
        for limitation in target.reachability.limitations:
            c.print(f"   - {limitation}")
    if target.evidence_ids:
        c.print(f" • [bold]Evidence IDs:[/] {', '.join(target.evidence_ids)}")
    if target.provenance_ids:
        c.print(f" • [bold]Evidence roles:[/] {', '.join(f'{kind}={evidence_id}' for kind, evidence_id in sorted(target.provenance_ids.items()))}")
    c.print()

    c.print("[bold underline]Runtime Evidence (separate from static reachability):[/]")
    runtime_summary = "; ".join(
        f"{state.lower()}={status}"
        for state, status in target.runtime_state.items()
    )
    c.print(f" • {runtime_summary}")
    if target.runtime_evidence_ids:
        c.print(f" • [bold]Runtime evidence IDs:[/] {', '.join(target.runtime_evidence_ids)}")
    for limitation in target.runtime_limitations:
        c.print(f" • [dim]{limitation}[/]")
    c.print()

    # 3. Shared deterministic risk assessment
    c.print("[bold underline]3. Shared Risk Assessment:[/] ")
    tier_color = (
        "red" if target.risk_tier == "ACT NOW" else
        "yellow" if target.risk_tier == "PLAN" else
        "magenta" if target.risk_tier == "UNKNOWN" else "blue"
    )
    c.print(f" • [bold]Risk Tier:[/] [{tier_color}]{target.risk_tier}[/]")
    score = "UNKNOWN" if target.risk_score is None else f"{target.risk_score:.1f}/100"
    c.print(f" • [bold]Risk Level / Score:[/] {target.risk_level} / {score}")
    c.print(f" • [bold]Explanation:[/] {target.firing_rule}")
    if target.risk_inputs:
        input_names = (
            "severity", "cvss_score", "epss_score", "kev_listed", "version_status",
            "dependency_present", "exposure", "reachability_status", "reachability_confidence",
        )
        rendered_inputs = []
        for name in input_names:
            if name not in target.risk_inputs:
                continue
            value = target.risk_inputs[name]
            rendered_inputs.append(f"{name}={'UNAVAILABLE' if value is None else value}")
        c.print(f" • [bold]Risk inputs:[/] {'; '.join(rendered_inputs)}")
    for factor in target.risk_factors:
        value = "UNKNOWN" if factor["score"] is None else f"{factor['score']:.1f}"
        c.print(f"   - {factor['name']}: {value} (weight {factor['weight']:.2f})")
    if target.risk_limitations:
        c.print(" • [bold]Risk limitations:[/]")
        for limitation in target.risk_limitations:
            c.print(f"   - {limitation}")
    c.print()

    # 4. Fix Availability and Lifecycle
    c.print("[bold underline]4. Fix Availability & Pinning Recommendation:[/] ")
    c.print(f" • [bold]Minimal Safe Version:[/] [green]{target.fix_status.minimal_safe_version}[/]")
    for stage_key, stage_val in target.fix_status.stages.items():
        st_label = stage_key.replace("_", " ").title()
        c.print(f"   - {st_label}: [dim]{stage_val}[/]")
    c.print()

    # 5. Graph Lineage Path
    if graph:
        path = graph.get_evidence_path(target.id)
        if path:
            c.print("[bold underline]5. Software Lineage Chain:[/] ")
            chain_str = " -> ".join(f"[cyan]{p}[/]" for p in path)
            c.print(f" {chain_str}\n")


    return True
